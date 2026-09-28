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


if __name__ == "__main__":
    unittest.main()
