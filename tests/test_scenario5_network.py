"""
Scenario 5 — unauthorized network access / SSRF-style abuse -> network policy block.

A DIFFERENT mechanism from Scenarios 3/4 (action policy): here the destination
is inspected, not the action. Proves:
  - an approved destination is ALLOWED,
  - an unauthorized destination is BLOCKED (HTTP 403),
  - the blocked request never reaches the backend/mock endpoint,
  - the block is logged as `network_block` (NOT canary, NOT policy_block),
  - Scenarios 1-4 still work (canaries freeze; command/destructive policy blocks).
"""
import threading
import http.server
import unittest

from starlette.testclient import TestClient

from app.proxy import app
from app import network_policy, db


class _CountingHandler(http.server.BaseHTTPRequestHandler):
    hits = 0

    def do_POST(self):
        _CountingHandler.hits += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST

    def log_message(self, *args):
        pass


class TestNetworkPolicyUnit(unittest.TestCase):
    def test_approved_destination_allowed(self):
        self.assertEqual(
            network_policy.check_network_policy("http://127.0.0.1:9000/mock-telemetry"), "ALLOW"
        )

    def test_unauthorized_destination_blocked(self):
        self.assertEqual(
            network_policy.check_network_policy("http://127.0.0.1:9999/unapproved"), "BLOCK"
        )

    def test_other_hosts_blocked(self):
        self.assertEqual(network_policy.check_network_policy("http://169.254.169.254/latest/meta-data"), "BLOCK")
        self.assertEqual(network_policy.check_network_policy("http://example.com/"), "BLOCK")
        self.assertEqual(network_policy.check_network_policy("not a url"), "BLOCK")


class TestScenario5Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Mock endpoint on the UNAPPROVED port: a blocked request must never hit it.
        cls.server = http.server.HTTPServer(("127.0.0.1", 9999), _CountingHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.client = TestClient(app)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.session_id = self.client.post("/mcp/session").json()["session_id"]

    def _call(self, tool, arguments):
        return self.client.post(
            "/mcp/call",
            json={"session_id": self.session_id, "tool": tool, "arguments": arguments},
        )

    def test_unauthorized_destination_blocked_before_backend(self):
        _CountingHandler.hits = 0
        resp = self._call("send_http_request", {"url": "http://127.0.0.1:9999/unapproved", "data": "x"})
        self.assertEqual(resp.status_code, 403)
        self.assertIn("network policy", resp.json()["error"].lower())
        self.assertIn("127.0.0.1:9999", resp.json()["error"])
        # The request must NEVER have reached the mock endpoint.
        self.assertEqual(_CountingHandler.hits, 0, "blocked request reached the destination")
        self.assertFalse(db.is_frozen(self.session_id))

    def test_approved_destination_allowed(self):
        resp = self._call("send_http_request", {"url": "http://127.0.0.1:9000/mock-telemetry", "data": "x"})
        # Not a network block (may be 200 from backend regardless of listener state).
        self.assertNotEqual(resp.status_code, 403)

    def test_block_logged_as_network_not_canary_or_policy(self):
        self._call("send_http_request", {"url": "http://127.0.0.1:9999/unapproved", "data": "x"})
        events = self.client.get("/mcp/trail", params={"session_id": self.session_id}).json()["events"]
        types = [e["event_type"] for e in events]
        self.assertIn("network_block", types)
        self.assertNotIn("canary_trigger", types)
        self.assertNotIn("policy_block", types)
        net = [e for e in events if e["event_type"] == "network_block"][-1]
        self.assertEqual(net["tool_name"], "send_http_request")
        self.assertEqual(net["is_canary"], 0)

    # --- Scenarios 1-4 remain unchanged -------------------------------------
    def test_scenario1_canary_still_freezes(self):
        resp = self._call("export_crm_contacts", {})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(db.is_frozen(self.session_id))

    def test_scenario2_canary_still_freezes(self):
        resp = self._call("disable_audit_trail", {})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(db.is_frozen(self.session_id))

    def test_scenario3_command_policy_still_blocks(self):
        resp = self._call("run_command", {"command": "cat config/app.env"})
        self.assertEqual(resp.status_code, 403)
        self.assertIn("policy", resp.json()["error"].lower())

    def test_scenario4_destructive_policy_still_blocks(self):
        resp = self._call("delete_file", {"path": "sandbox/obsolete_report_2024.tmp"})
        self.assertEqual(resp.status_code, 403)
        self.assertIn("destructive", resp.json()["error"].lower())


if __name__ == "__main__":
    unittest.main()
