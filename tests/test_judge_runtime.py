"""
Judge runtime path (POST /run -> run_agent -> proxy).

Covers the root causes behind "only delete_file ever gets exercised":
  - the agent must request a context window large enough to keep the system
    prompt + tool schemas + task (Ollama's 4k default context-shifts them out);
  - tool results must reach the model as the tool's own text, not re-escaped
    nested JSON;
  - the dashboard's ALLOWED decision must come from the proxy, only for calls
    that passed every layer and actually reached the backend.
"""
import json
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from starlette.testclient import TestClient

from app import agent_demo
from app.proxy import app


class TestAgentContextBudget(unittest.TestCase):
    def test_default_context_holds_tools_and_several_results(self):
        # System prompt + 17 tool schemas + task is ~1.1k tokens on its own.
        self.assertGreaterEqual(agent_demo.DEFAULT_NUM_CTX, 8192)

    def test_run_agent_requests_num_ctx_on_every_turn(self):
        final = SimpleNamespace(message=SimpleNamespace(
            content="done", thinking=None, tool_calls=None),
            prompt_eval_count=10, eval_count=5)
        llm = mock.MagicMock()
        llm.chat.return_value = final
        proxy = mock.MagicMock()
        proxy.create_session.return_value = "s1"
        proxy.list_tools.return_value = []
        proxy.get_trail.return_value = []
        with mock.patch.object(agent_demo.ollama, "Client", return_value=llm), \
             mock.patch.object(agent_demo, "TripwireProxyClient", return_value=proxy):
            answer = agent_demo.run_agent("t", "m", "http://x", 3, think=False, num_ctx=12345)
        self.assertEqual(answer, "done")
        self.assertEqual(llm.chat.call_args.kwargs["options"], {"num_ctx": 12345})


class TestToolResultText(unittest.TestCase):
    def test_allowed_result_is_unwrapped_to_tool_text(self):
        text = json.dumps({"path": "docs/a.md", "content": "line1\nline2"}, indent=2)
        self.assertEqual(agent_demo.tool_result_text({"result": {"result": text}}), text)

    def test_error_and_canary_bodies_pass_through(self):
        for body in ({"error": "blocked"}, {"result": {"status": "export queued", "rows": 1}}):
            self.assertEqual(agent_demo.tool_result_text(body), json.dumps(body))


class TestExplicitAllowDecision(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)

    def setUp(self):
        self.session_id = self.client.post("/mcp/session").json()["session_id"]

    def _types(self):
        events = self.client.get("/mcp/trail", params={"session_id": self.session_id}).json()["events"]
        return [e["event_type"] for e in events]

    def _call(self, tool, arguments):
        return self.client.post("/mcp/call", json={
            "session_id": self.session_id, "tool": tool, "arguments": arguments})

    def test_allowed_call_emits_tool_allowed_after_backend(self):
        self.assertEqual(self._call("get_project_status", {}).status_code, 200)
        self.assertEqual(self._types(), ["tool_call", "tool_allowed"])

    def test_policy_blocked_call_never_emits_tool_allowed(self):
        self.assertEqual(self._call("delete_file", {"path": "sandbox/keep_me.md"}).status_code, 403)
        self.assertEqual(self._types(), ["tool_call", "policy_block"])

    def test_canary_call_never_emits_tool_allowed(self):
        self._call("export_crm_contacts", {"segment": "login-failures"})
        self.assertNotIn("tool_allowed", self._types())




class TestRunEndpointHosting(unittest.TestCase):
    """POST /run guards for a hosted deployment. run_agent is stubbed so no
    model is needed."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)

    def setUp(self):
        from app import proxy
        self.proxy = proxy
        self.saved_runs = dict(proxy._runs)
        proxy._runs.clear()
        self.calls = []
        self.release = threading.Event()

        def fake_run_agent(task, **kwargs):
            self.calls.append(kwargs)
            self.release.wait(5)
            return "ok"

        patcher = mock.patch.object(agent_demo, "run_agent", side_effect=fake_run_agent)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        # Let the stubbed runs finish before restoring _runs, so the proxy's
        # background thread doesn't write into a cleared dict.
        self.release.set()
        for _ in range(100):
            if all(r["status"] != "running" for r in self.proxy._runs.values()):
                break
            time.sleep(0.02)
        self.proxy._runs.clear()
        self.proxy._runs.update(self.saved_runs)

    def test_access_key_required_when_configured(self):
        with mock.patch.dict("os.environ", {"TRIPWIRE_ACCESS_KEY": "s3cret"}):
            self.assertEqual(self.client.post("/run", json={"task": "t"}).status_code, 401)
            bad = self.client.post("/run", json={"task": "t"}, headers={"X-Tripwire-Key": "nope"})
            self.assertEqual(bad.status_code, 401)
            ok = self.client.post("/run", json={"task": "t"}, headers={"X-Tripwire-Key": "s3cret"})
            self.assertEqual(ok.status_code, 200)

    def test_no_key_configured_allows_runs(self):
        with mock.patch.dict("os.environ", {"TRIPWIRE_ACCESS_KEY": ""}):
            self.assertEqual(self.client.post("/run", json={"task": "t"}).status_code, 200)

    def test_second_concurrent_run_is_rejected(self):
        with mock.patch.dict("os.environ", {"TRIPWIRE_ACCESS_KEY": ""}):
            self.assertEqual(self.client.post("/run", json={"task": "a"}).status_code, 200)
            busy = self.client.post("/run", json={"task": "b"})
            self.assertEqual(busy.status_code, 429)
            self.assertIn("in progress", busy.json()["error"])

    def test_agent_uses_internal_url_when_set(self):
        env = {"TRIPWIRE_ACCESS_KEY": "", "TRIPWIRE_INTERNAL_URL": "http://127.0.0.1:9123"}
        with mock.patch.dict("os.environ", env):
            self.client.post("/run", json={"task": "t"})
            self.release.set()
            for _ in range(50):
                if self.calls:
                    break
                time.sleep(0.05)
        self.assertEqual(self.calls[0]["proxy_url"], "http://127.0.0.1:9123")

    def test_healthz(self):
        body = self.client.get("/healthz").json()
        self.assertEqual(body["status"], "ok")
        self.assertIsInstance(body["poisoned_tool_enabled"], bool)
        with mock.patch.dict("os.environ", {"TRIPWIRE_ACCESS_KEY": "x"}):
            self.assertTrue(self.client.get("/healthz").json()["access_key_required"])
        with mock.patch.dict("os.environ", {"TRIPWIRE_ACCESS_KEY": ""}):
            self.assertFalse(self.client.get("/healthz").json()["access_key_required"])


if __name__ == "__main__":
    unittest.main()
