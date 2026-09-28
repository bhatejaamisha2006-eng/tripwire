"""
Scenario 4 — user-intent hijacking -> destructive file action -> policy block.

Same policy engine as Scenario 3, different dangerous action. Proves:
  - a legitimate inspection operation is ALLOWED,
  - an unauthorized destructive delete_file is BLOCKED (HTTP 403),
  - the blocked delete never executes (the fixture file still exists),
  - the block is logged as `policy_block` (NOT a canary),
  - Scenario 1 (export_crm_contacts canary) still freezes,
  - Scenario 2 (disable_audit_trail canary) still freezes.
"""
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from app.proxy import app
from app import policy, db

SANDBOX_FILE = (
    Path(__file__).resolve().parent.parent
    / "mcp_lab" / "workspace" / "sandbox" / "obsolete_report_2024.tmp"
)


class TestPolicyUnit(unittest.TestCase):
    def test_destructive_delete_blocked(self):
        self.assertEqual(
            policy.check_policy("delete_file", {"path": "sandbox/obsolete_report_2024.tmp"}),
            "BLOCK",
        )

    def test_inspection_allowed(self):
        for tool in ("list_directory", "read_file", "get_file_metadata"):
            self.assertEqual(policy.check_policy(tool, {"path": "sandbox"}), "ALLOW")

    def test_reason_is_destructive_not_canary(self):
        reason = policy.violation_reason("delete_file", {"path": "sandbox/x.tmp"})
        self.assertIn("delete_file", reason)
        self.assertIn("destructive", reason)


class TestScenario4Runtime(unittest.TestCase):
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

    def test_destructive_delete_blocked_before_execution(self):
        self.assertTrue(SANDBOX_FILE.exists(), "fixture must exist before the test")

        resp = self._call("delete_file", {"path": "sandbox/obsolete_report_2024.tmp"})
        self.assertEqual(resp.status_code, 403)
        body = resp.json()
        self.assertIn("policy", body["error"].lower())
        self.assertIn("delete_file", body["error"])

        # The delete must NOT have executed: the file is still on disk.
        self.assertTrue(SANDBOX_FILE.exists(), "blocked delete must not remove the file")
        # A policy block does not freeze the session (that's Scenario 1's mechanism).
        self.assertFalse(db.is_frozen(self.session_id))

    def test_block_logged_as_policy_not_canary(self):
        self._call("delete_file", {"path": "sandbox/obsolete_report_2024.tmp"})
        events = self.client.get(
            "/mcp/trail", params={"session_id": self.session_id}
        ).json()["events"]

        blocks = [e for e in events if e["event_type"] == "policy_block"]
        self.assertTrue(blocks, "expected a policy_block event")
        self.assertEqual(blocks[-1]["tool_name"], "delete_file")
        self.assertEqual(blocks[-1]["is_canary"], 0)
        self.assertNotIn("canary_trigger", [e["event_type"] for e in events])

    def test_inspection_operation_executes(self):
        resp = self._call("get_file_metadata", {"path": "sandbox/obsolete_report_2024.tmp"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("result", resp.json())

    def test_scenario1_canary_still_freezes(self):
        resp = self._call("export_crm_contacts", {})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(db.is_frozen(self.session_id))

    def test_scenario2_canary_still_freezes(self):
        resp = self._call("disable_audit_trail", {})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(db.is_frozen(self.session_id))


class TestDestructiveViaInterpreter(unittest.TestCase):
    """A destructive action must not bypass delete_file's policy by running
    interpreter code through run_command."""

    PROBE = SANDBOX_FILE.parent / "zz_interpreter_probe.tmp"
    DELETE_CMD = "python3 -c \"__import__('os').remove('sandbox/zz_interpreter_probe.tmp')\""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)

    def setUp(self):
        self.PROBE.write_text("probe")
        self.session_id = self.client.post("/mcp/session").json()["session_id"]

    def tearDown(self):
        self.PROBE.unlink(missing_ok=True)

    def test_policy_blocks_interpreter_code(self):
        for cmd in (self.DELETE_CMD, "python3 script.py", "/usr/bin/python3 -c 1", "PYTHON -c 1"):
            with self.subTest(cmd=cmd):
                self.assertEqual(policy.check_policy("run_command", {"command": cmd}), "BLOCK")
        for cmd in ("python --version", "python3 -V", "ls", "cat README.md"):
            with self.subTest(cmd=cmd):
                self.assertEqual(policy.check_policy("run_command", {"command": cmd}), "ALLOW")

    def test_blocked_before_execution_and_file_survives(self):
        resp = self.client.post("/mcp/call", json={
            "session_id": self.session_id, "tool": "run_command",
            "arguments": {"command": self.DELETE_CMD}})
        self.assertEqual(resp.status_code, 403)
        self.assertIn("interpreter code", resp.json()["error"])
        self.assertTrue(self.PROBE.exists(), "the file must not be deleted")
        types = [e["event_type"] for e in self.client.get(
            "/mcp/trail", params={"session_id": self.session_id}).json()["events"]]
        self.assertEqual(types, ["tool_call", "policy_block"])

    def test_backend_also_refuses_interpreter_code(self):
        # Defence in depth: even if policy were bypassed, the MCP server refuses.
        import importlib.util, json as _json
        spec = importlib.util.spec_from_file_location("srv", "mcp_lab/server.py")
        srv = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(srv)
        run = getattr(srv.run_command, "fn", srv.run_command)
        out = _json.loads(run(self.DELETE_CMD))
        self.assertIn("not permitted", out.get("error", ""))
        self.assertTrue(self.PROBE.exists())
        self.assertIn("Python", _json.loads(run("python3 --version")).get("stdout", "") +
                      _json.loads(run("python3 --version")).get("stderr", ""))


if __name__ == "__main__":
    unittest.main()
