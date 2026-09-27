"""
Scenario 7 — tool poisoning -> tool-integrity quarantine.

A DIFFERENT layer from Scenarios 1-6: it inspects the tool *metadata* the agent
is offered, not what the agent does. Proves:
  - a poisoned tool description is detected,
  - the poisoned tool is quarantined (withheld) from the tool list,
  - legitimate tools are still offered,
  - a direct call to the quarantined tool is blocked (HTTP 403) and not executed,
  - the event is logged as `tool_poisoning` (distinct from every other layer),
  - Scenarios 1/3/5 mechanisms still work.
"""
import os
import unittest

from starlette.testclient import TestClient

from app.proxy import app
from app import tool_integrity, db


class TestToolIntegrityUnit(unittest.TestCase):
    def test_poisoned_description_detected(self):
        self.assertTrue(tool_integrity.is_poisoned(tool_integrity.POISONED_TOOL))
        self.assertIsNotNone(
            tool_integrity.scan_description(tool_integrity.POISONED_TOOL["description"])
        )

    def test_legit_descriptions_not_flagged(self):
        self.assertFalse(tool_integrity.is_poisoned(
            {"name": "read_file", "description": "Read the contents of a file by path."}))
        # Must NOT false-positive on the legitimate outbound-request tool.
        self.assertFalse(tool_integrity.is_poisoned(
            {"name": "send_http_request",
             "description": "Send an HTTP request to a controlled local/mock demo endpoint."}))


class TestScenario7Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["TRIPWIRE_ENABLE_POISONED_TOOL"] = "1"
        cls.client = TestClient(app)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)
        os.environ.pop("TRIPWIRE_ENABLE_POISONED_TOOL", None)

    def setUp(self):
        self.session_id = self.client.post("/mcp/session").json()["session_id"]

    def _tools(self):
        return self.client.get("/mcp/tools", params={"session_id": self.session_id}).json()["tools"]

    def _call(self, tool, arguments):
        return self.client.post(
            "/mcp/call",
            json={"session_id": self.session_id, "tool": tool, "arguments": arguments},
        )

    def test_poisoned_tool_quarantined_from_list(self):
        names = [t["name"] for t in self._tools()]
        self.assertNotIn("get_diagnostics_bundle", names)   # quarantined / withheld
        self.assertIn("read_file", names)                    # legit tools still offered
        self.assertIn("search_files", names)

        events = self.client.get("/mcp/trail", params={"session_id": self.session_id}).json()["events"]
        types = [e["event_type"] for e in events]
        self.assertIn("tool_poisoning", types)
        poison = [e for e in events if e["event_type"] == "tool_poisoning"][-1]
        self.assertEqual(poison["tool_name"], "get_diagnostics_bundle")
        self.assertEqual(poison["is_canary"], 0)

    def test_direct_call_to_poisoned_tool_blocked(self):
        self._tools()  # trigger quarantine
        resp = self._call("get_diagnostics_bundle", {})
        self.assertEqual(resp.status_code, 403)
        body = resp.json()
        self.assertIn("quarantined", body["error"].lower())
        # Not executed: no telemetry-shaped result comes back.
        self.assertNotIn("result", body)
        self.assertFalse(db.is_frozen(self.session_id))

    def test_distinct_from_other_layers(self):
        self._tools()
        events = self.client.get("/mcp/trail", params={"session_id": self.session_id}).json()["events"]
        types = [e["event_type"] for e in events]
        self.assertIn("tool_poisoning", types)
        for other in ("canary_trigger", "policy_block", "network_block", "behavior_anomaly"):
            self.assertNotIn(other, types)

    # --- Scenarios 1/3/5 remain unchanged ------------------------------------
    def test_scenario1_canary_still_freezes(self):
        resp = self._call("export_crm_contacts", {})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(db.is_frozen(self.session_id))

    def test_scenario3_command_policy_still_blocks(self):
        resp = self._call("run_command", {"command": "cat config/app.env"})
        self.assertEqual(resp.status_code, 403)
        self.assertIn("policy", resp.json()["error"].lower())

    def test_scenario5_network_still_blocks(self):
        resp = self._call("send_http_request", {"url": "http://127.0.0.1:9999/unapproved"})
        self.assertEqual(resp.status_code, 403)
        self.assertIn("network policy", resp.json()["error"].lower())


if __name__ == "__main__":
    unittest.main()
