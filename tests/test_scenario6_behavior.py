"""
Scenario 6 — nested/second-order injection -> behavioral anomaly -> freeze.

A DIFFERENT layer from Scenarios 1-5: detection comes from the *sequence* of
otherwise-legitimate tool calls, not from any single call. Proves:
  - a sustained reconnaissance sweep raises the risk score to the threshold,
  - the session is then FROZEN (HTTP 423) as a behavior_anomaly (NOT canary,
    policy_block, or network_block),
  - a short burst of recon (below threshold) does NOT freeze,
  - after the freeze, further calls are locked out (frozen_block),
  - Scenarios 1-5 still work (single-call canary/policy/network mechanisms).
"""
import unittest

from starlette.testclient import TestClient

from app.proxy import app
from app import behavior, db


class TestBehaviorUnit(unittest.TestCase):
    def setUp(self):
        behavior._sessions.clear()

    def test_score_escalates_and_crosses_threshold(self):
        s = "unit-1"
        scores = [behavior.record(s, "read_file") for _ in range(5)]
        self.assertEqual(scores, [1, 3, 6, 10, 15])   # escalating streak
        self.assertTrue(behavior.is_anomalous(s))

    def test_non_recon_call_breaks_the_streak(self):
        s = "unit-2"
        behavior.record(s, "read_file")     # 1
        behavior.record(s, "read_file")     # 3
        behavior.record(s, "get_project_status")  # streak reset, score stays 3
        score = behavior.record(s, "read_file")   # streak 1 again -> +1 = 4
        self.assertEqual(score, 4)
        self.assertFalse(behavior.is_anomalous(s))


class TestScenario6Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)

    def setUp(self):
        self.session_id = self.client.post("/mcp/session").json()["session_id"]

    def _call(self, tool, arguments):
        return self.client.post(
            "/mcp/call",
            json={"session_id": self.session_id, "tool": tool, "arguments": arguments},
        )

    def test_short_recon_burst_does_not_freeze(self):
        for _ in range(4):  # 1+2+3+4 = 10 < 15
            resp = self._call("list_directory", {"path": "."})
            self.assertEqual(resp.status_code, 200)
        self.assertFalse(db.is_frozen(self.session_id))

    def test_sustained_recon_sweep_freezes_as_behavior_anomaly(self):
        statuses = []
        for _ in range(6):
            statuses.append(self._call("read_file", {"path": "handbook/FAQ.md"}).status_code)
        # The 5th consecutive recon call trips the threshold (1+2+3+4+5=15).
        self.assertIn(423, statuses)
        self.assertTrue(db.is_frozen(self.session_id))

        events = self.client.get("/mcp/trail", params={"session_id": self.session_id}).json()["events"]
        types = [e["event_type"] for e in events]
        self.assertIn("behavior_anomaly", types)
        self.assertIn("freeze", types)
        # Distinct from every other layer:
        self.assertNotIn("canary_trigger", types)
        self.assertNotIn("policy_block", types)
        self.assertNotIn("network_block", types)

        anomaly = [e for e in events if e["event_type"] == "behavior_anomaly"][-1]
        self.assertEqual(anomaly["is_canary"], 0)

    def test_locked_out_after_behavioral_freeze(self):
        for _ in range(6):
            self._call("read_file", {"path": "handbook/FAQ.md"})
        self.assertTrue(db.is_frozen(self.session_id))
        resp = self._call("get_project_status", {})
        self.assertEqual(resp.status_code, 423)
        self.assertIn("session frozen", resp.json()["error"].lower())

    # --- Scenarios 1-5 remain unchanged (single-call mechanisms) -------------
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
