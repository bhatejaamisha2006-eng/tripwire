import unittest
from starlette.testclient import TestClient
from app.proxy import app
from app import policy, db, canary


class TestPolicyStandalone(unittest.TestCase):
    def test_policy_allow_tools(self):
        self.assertEqual(policy.check_policy("get_project_status"), "ALLOW")
        self.assertEqual(policy.check_policy("search_docs"), "ALLOW")
        self.assertEqual(policy.check_policy("list_files"), "ALLOW")

    def test_policy_block_tools(self):
        self.assertEqual(policy.check_policy("restart_server"), "BLOCK")
        self.assertEqual(policy.check_policy("get_admin_credentials"), "BLOCK")


class TestRuntimeSecurityPaths(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)

    def setUp(self):
        session_res = self.client.post("/mcp/session")
        self.assertEqual(session_res.status_code, 200)
        self.session_id = session_res.json()["session_id"]

    def test_flow1_allow_path(self):
        """FLOW 1 — ALLOW: Normal tool -> HTTP 200 -> MCP backend called -> session active."""
        resp = self.client.post(
            "/mcp/call",
            json={"session_id": self.session_id, "tool": "get_project_status", "arguments": {}},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("result", data)
        self.assertIn("Tripwire backend is healthy", str(data["result"]))
        self.assertFalse(db.is_frozen(self.session_id))

    def test_flow2_policy_block_path(self):
        """FLOW 2 — POLICY BLOCK: Protected tool -> HTTP 403 -> backend NOT called -> session NOT frozen."""
        resp = self.client.post(
            "/mcp/call",
            json={"session_id": self.session_id, "tool": "restart_server", "arguments": {}},
        )
        self.assertEqual(resp.status_code, 403)
        data = resp.json()
        self.assertIn("error", data)
        self.assertIn("blocked by policy", data["error"])
        # Session must NOT be frozen by a policy block
        self.assertFalse(db.is_frozen(self.session_id))

    def test_restart_server_allowed_when_policy_permits(self):
        """Verify restart_server is blocked unless the policy explicitly allows it."""
        # 1. Blocked under default policy
        blocked = self.client.post(
            "/mcp/call",
            json={"session_id": self.session_id, "tool": "restart_server", "arguments": {}},
        )
        self.assertEqual(blocked.status_code, 403)

        # 2. When policy allows it, it calls the MCP backend and succeeds
        orig_sensitive = set(policy.SENSITIVE_TOOLS)
        try:
            policy.SENSITIVE_TOOLS.remove("restart_server")
            allowed = self.client.post(
                "/mcp/call",
                json={"session_id": self.session_id, "tool": "restart_server", "arguments": {}},
            )
            self.assertEqual(allowed.status_code, 200)
            self.assertIn("Tripwire backend restarted successfully", str(allowed.json()["result"]))
        finally:
            policy.SENSITIVE_TOOLS = orig_sensitive

    def test_flow3_canary_path(self):
        """FLOW 3 — CANARY: Deception tool -> HTTP 200 fake response -> session FROZEN -> backend NOT called."""
        resp = self.client.post(
            "/mcp/call",
            json={"session_id": self.session_id, "tool": "get_admin_credentials", "arguments": {}},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("result", data)
        self.assertIn("username", data["result"])
        # Session MUST be frozen
        self.assertTrue(db.is_frozen(self.session_id))

    def test_flow4_post_freeze_block(self):
        """FLOW 4 — POST-FREEZE: Any tool after freeze -> HTTP 423 -> rejected."""
        # First trigger canary to freeze session
        canary_resp = self.client.post(
            "/mcp/call",
            json={"session_id": self.session_id, "tool": "get_admin_credentials", "arguments": {}},
        )
        self.assertEqual(canary_resp.status_code, 200)
        self.assertTrue(db.is_frozen(self.session_id))

        # Subsequent call must be locked out with HTTP 423
        blocked_resp = self.client.post(
            "/mcp/call",
            json={"session_id": self.session_id, "tool": "get_project_status", "arguments": {}},
        )
        self.assertEqual(blocked_resp.status_code, 423)
        self.assertIn("session frozen", blocked_resp.json()["error"])

    def test_complete_forensic_trail(self):
        """Verify the full ordered sequence of events in SQLite."""
        # 1. ALLOW call
        self.client.post("/mcp/call", json={"session_id": self.session_id, "tool": "get_project_status", "arguments": {}})
        # 2. POLICY BLOCK call
        self.client.post("/mcp/call", json={"session_id": self.session_id, "tool": "restart_server", "arguments": {}})
        # 3. CANARY call
        self.client.post("/mcp/call", json={"session_id": self.session_id, "tool": "get_admin_credentials", "arguments": {}})
        # 4. POST-FREEZE call
        self.client.post("/mcp/call", json={"session_id": self.session_id, "tool": "get_project_status", "arguments": {}})

        trail_resp = self.client.get("/mcp/trail", params={"session_id": self.session_id})
        self.assertEqual(trail_resp.status_code, 200)
        events = trail_resp.json()["events"]
        event_types = [e["event_type"] for e in events]

        self.assertIn("tool_call", event_types)
        self.assertIn("policy_block", event_types)
        self.assertIn("canary_trigger", event_types)
        self.assertIn("freeze", event_types)
        self.assertIn("frozen_block", event_types)


if __name__ == "__main__":
    unittest.main()
