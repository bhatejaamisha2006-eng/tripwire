"""
Scenario 3 — runtime policy enforcement on run_command arguments.

Proves:
  - an unauthorized command (reading a restricted secrets/config file) is
    BLOCKED by policy with HTTP 403,
  - the command never executes (the fixture's contents are never returned),
  - the block is logged as a `policy_block` event (NOT a canary),
  - an ordinary run_command still works,
  - Scenario 1 (canary detection + freeze) still works unchanged.
"""
import unittest

from starlette.testclient import TestClient

from app.proxy import app
from app import policy, db


class TestPolicyUnit(unittest.TestCase):
    def test_unauthorized_command_blocked(self):
        self.assertEqual(
            policy.check_policy("run_command", {"command": "cat config/app.env"}), "BLOCK"
        )
        self.assertEqual(
            policy.check_policy("run_command", {"command": "cat .env"}), "BLOCK"
        )

    def test_ordinary_command_allowed(self):
        self.assertEqual(policy.check_policy("run_command", {"command": "ls"}), "ALLOW")
        self.assertEqual(policy.check_policy("run_command", {"command": "pwd"}), "ALLOW")

    def test_backwards_compatible_signature(self):
        # Existing one-argument callers must keep working.
        self.assertEqual(policy.check_policy("restart_server"), "BLOCK")
        self.assertEqual(policy.check_policy("get_project_status"), "ALLOW")


class TestScenario3Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)

    def setUp(self):
        self.session_id = self.client.post("/mcp/session").json()["session_id"]

    def test_unauthorized_command_is_blocked_before_execution(self):
        resp = self.client.post(
            "/mcp/call",
            json={
                "session_id": self.session_id,
                "tool": "run_command",
                "arguments": {"command": "cat config/app.env"},
            },
        )
        # Blocked with 403 by policy...
        self.assertEqual(resp.status_code, 403)
        body = resp.json()
        self.assertIn("error", body)
        self.assertIn("policy", body["error"].lower())
        self.assertIn("run_command", body["error"])

        # ...the command did NOT execute: the fixture's contents never appear.
        self.assertNotIn("placeholder_not_real", str(body))
        self.assertNotIn("stdout", body)

        # ...and a policy block does not freeze the session (that's Scenario 1).
        self.assertFalse(db.is_frozen(self.session_id))

    def test_block_is_logged_as_policy_not_canary(self):
        self.client.post(
            "/mcp/call",
            json={
                "session_id": self.session_id,
                "tool": "run_command",
                "arguments": {"command": "cat config/app.env"},
            },
        )
        events = self.client.get(
            "/mcp/trail", params={"session_id": self.session_id}
        ).json()["events"]

        blocks = [e for e in events if e["event_type"] == "policy_block"]
        self.assertTrue(blocks, "expected a policy_block event in the trail")
        block = blocks[-1]
        self.assertEqual(block["tool_name"], "run_command")
        self.assertEqual(block["is_canary"], 0)  # explicitly NOT a canary
        self.assertNotIn(
            "canary_trigger", [e["event_type"] for e in events]
        )

    def test_ordinary_command_still_executes(self):
        resp = self.client.post(
            "/mcp/call",
            json={
                "session_id": self.session_id,
                "tool": "run_command",
                "arguments": {"command": "pwd"},
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("result", resp.json())

    def test_scenario1_canary_still_freezes(self):
        # Scenario 1's mechanism must remain intact: a canary call freezes.
        resp = self.client.post(
            "/mcp/call",
            json={
                "session_id": self.session_id,
                "tool": "export_crm_contacts",
                "arguments": {},
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(db.is_frozen(self.session_id))


if __name__ == "__main__":
    unittest.main()
