"""
The live dashboard event contract.

The dashboard only visualizes what the proxy decided. These tests pin what the
proxy broadcasts so the UI never has to infer a decision:
  - each broadcast carries the persisted row's event_id and timestamp;
  - every event of one tool call shares a call_id;
  - each decision event carries the real, ordered check trace for that call;
  - arguments/reasons are redacted in the broadcast but kept raw in SQLite;
  - /run emits session_started, the agent's live progress, and
    session_completed with the real outcome.
"""
import asyncio
import json
import threading
import time
import unittest
from unittest import mock

from starlette.testclient import TestClient

from app import agent_demo, db, proxy, redact
from app.proxy import app


def _layers(event):
    return [(c["layer"], c["verdict"]) for c in event["checks"]]


class _Capture:
    """Subscribe to the proxy's broadcast queue like the SSE stream does."""

    def __enter__(self):
        self.q = asyncio.Queue()
        proxy._subscribers.append(self.q)
        return self

    def __exit__(self, *exc):
        proxy._subscribers.remove(self.q)

    def peek(self):
        return list(self.q._queue)

    def drain(self, session_id):
        out = []
        while not self.q.empty():
            e = self.q.get_nowait()
            if e.get("session_id") == session_id:
                out.append(e)
        return out


class TestDecisionEvents(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)

    def setUp(self):
        self.sid = self.client.post("/mcp/session").json()["session_id"]

    def _call(self, tool, arguments):
        return self.client.post("/mcp/call", json={
            "session_id": self.sid, "tool": tool, "arguments": arguments})

    def _run(self, tool, arguments):
        with _Capture() as cap:
            resp = self._call(tool, arguments)
            return resp, cap.drain(self.sid)

    def test_event_ids_match_the_forensic_trail(self):
        _, events = self._run("get_project_status", {})
        trail = self.client.get("/mcp/trail", params={"session_id": self.sid}).json()["events"]
        self.assertEqual([e["event_id"] for e in events], [r["id"] for r in trail])
        self.assertEqual([e["ts"] for e in events], [r["ts"] for r in trail])

    def test_allowed_call_trace(self):
        _, events = self._run("get_project_status", {})
        self.assertEqual([e["event_type"] for e in events], ["tool_call", "tool_allowed"])
        self.assertEqual(len({e["call_id"] for e in events}), 1)
        self.assertEqual(_layers(events[-1]), [
            ("Session Freeze", "pass"), ("Tool Integrity", "pass"), ("Network Policy", "n/a"),
            ("Canary", "pass"), ("Action Policy", "pass"), ("Behavioral", "pass")])
        self.assertEqual(events[-1]["risk_threshold"], 15)

    def test_policy_block_trace_stops_at_action_policy(self):
        _, events = self._run("delete_file", {"path": "sandbox/keep_me.md"})
        block = events[-1]
        self.assertEqual(block["event_type"], "policy_block")
        self.assertEqual(_layers(block)[-1], ("Action Policy", "block"))
        self.assertNotIn("Behavioral", [layer for layer, _ in _layers(block)])

    def test_network_block_trace(self):
        _, events = self._run("send_http_request", {"url": "http://127.0.0.1:9999/unapproved"})
        self.assertEqual([e["event_type"] for e in events], ["network_block"])
        self.assertEqual(_layers(events[0])[-1], ("Network Policy", "block"))

    def test_canary_trace_and_freeze(self):
        _, events = self._run("export_crm_contacts", {"segment": "x"})
        self.assertEqual(_layers(events[-1])[-1], ("Canary", "trigger"))
        self.assertTrue(db.is_frozen(self.sid))
        _, events = self._run("get_project_status", {})
        self.assertEqual(events[0]["event_type"], "frozen_block")
        self.assertEqual(_layers(events[0]), [("Session Freeze", "block")])

    def test_behavioral_freeze_trace_carries_risk(self):
        self._call("search_files", {"query": "credential"})
        self._call("search_files", {"query": "secret"})
        _, events = self._run("read_file", {"path": "config/app.env"})
        types = [e["event_type"] for e in events]
        self.assertEqual(types, ["tool_call", "policy_block", "behavior_anomaly"])
        anomaly = events[-1]
        self.assertEqual(_layers(anomaly)[-2:], [("Action Policy", "block"), ("Behavioral", "freeze")])
        self.assertEqual(anomaly["risk_score"], 16)
        self.assertEqual(len({e["call_id"] for e in events}), 1)

    def test_arguments_redacted_in_broadcast_but_raw_in_trail(self):
        args = {"url": "http://127.0.0.1:9999/x", "data": "SIGNING_KEY=abc123 AWS=AKIA_FAKE_EXAMPLE_0000"}
        _, events = self._run("send_http_request", args)
        shown = json.dumps(events)
        self.assertNotIn("abc123", shown)
        self.assertNotIn("AKIA_FAKE_EXAMPLE_0000", shown)
        trail = self.client.get("/mcp/trail", params={"session_id": self.sid}).json()["events"]
        self.assertIn("abc123", trail[-1]["arguments"])  # forensic log keeps raw


class TestRedact(unittest.TestCase):
    def test_env_fixture_fully_redacted(self):
        with open("mcp_lab/workspace/config/app.env") as f:
            text = redact.redact_text(f.read(), limit=None)
        for secret in ("placeholder_not_real", "AKIA_FAKE_EXAMPLE_0000"):
            self.assertNotIn(secret, text)
        self.assertIn("APP_ENV=demo", text)

    def test_bearer_token_not_leaked_by_key_value_rule(self):
        out = redact.redact_text("Authorization: Bearer abcdefgh12345678")
        self.assertNotIn("abcdefgh12345678", out)

    def test_ordinary_text_untouched(self):
        for text in ("auth/config_loader.py:41: could not load", "author: Sam",
                     "cat config/app.env", "read docs/troubleshooting-login.md"):
            self.assertEqual(redact.redact_text(text), text)

    def test_secret_named_keys(self):
        self.assertEqual(redact.redact({"api_key": "k", "path": "p"}),
                         {"api_key": "[REDACTED]", "path": "p"})


class TestRunLifecycleEvents(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)

    def setUp(self):
        self.saved = dict(proxy._runs)
        proxy._runs.clear()

    def tearDown(self):
        proxy._runs.clear()
        proxy._runs.update(self.saved)

    def test_session_started_progress_and_completed(self):
        def fake_run_agent(task, **kw):
            kw["on_event"]("agent_thinking", step=1, max_steps=12, model="m")
            kw["on_event"]("agent_decided", step=1, tool_calls=[], final=True,
                           generated_tokens=5, model_seconds=0.1)
            return "Found DB_PASSWORD=hunter2 in the file."

        with mock.patch.object(agent_demo, "run_agent", side_effect=fake_run_agent), \
             mock.patch.dict("os.environ", {"TRIPWIRE_ACCESS_KEY": ""}):
            with _Capture() as cap:
                sid = self.client.post("/run", json={"task": "t"}).json()["session_id"]
                for _ in range(100):
                    if proxy._runs[sid]["status"] != "running":
                        break
                    time.sleep(0.02)
                # Thread-side broadcasts are scheduled onto the app loop.
                for _ in range(100):
                    if any(e.get("event_type") == "session_completed" for e in cap.peek()):
                        break
                    time.sleep(0.02)
                events = cap.drain(sid)

        types = [e["event_type"] for e in events]
        self.assertEqual(types, ["session_started", "agent_thinking", "agent_decided",
                                 "session_completed"])
        self.assertEqual(events[-1]["outcome"], "completed")
        self.assertTrue(str(events[1]["event_id"]).startswith("live-"))  # not persisted
        trail = [r["event_type"] for r in self.client.get(
            "/mcp/trail", params={"session_id": sid}).json()["events"]]
        self.assertEqual(trail, ["session_started", "session_completed"])
        status = self.client.get("/run/status", params={"session_id": sid}).json()
        self.assertNotIn("hunter2", status["response"])


if __name__ == "__main__":
    unittest.main()
