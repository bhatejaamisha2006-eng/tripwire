# Tripwire

A deception-based proxy that catches hijacked AI agents by planting fake
tools ("canaries") no legitimate task would ever call. If a canary gets
called, that's a high-confidence signal of suspicious behavior — the
session is frozen and the full attack trail is captured.

## Why this, not another prompt filter

Content-based defenses try to recognize malicious *instructions*, which
breaks down when attackers reword or hide them (e.g. inside a document
the agent retrieves, not the prompt itself). Tripwire doesn't try to
read intent — it watches *behavior*. A canary being called is unambiguous:
no real task needs `get_admin_credentials`.

## Architecture

```
Agent  --tools/list-->   Tripwire Proxy  --> real MCP backend (+ injects canaries)
Agent  --tools/call-->   Tripwire Proxy  --> canary? freeze + log + fake response
                                          --> real?   pass through + log
                          |
                          v
                    SQLite event log --> Live dashboard (SSE)
```

- `app/proxy.py` — FastAPI proxy: tool list injection, call interception,
  freeze-on-trigger, event broadcast
- `app/canary.py` — canary tool definitions + fake responses
- `app/mock_backend.py` — stand-in "real" MCP server, including one
  poisoned document used as the attack vector in the demo
- `app/db.py` — SQLite session + event storage (the forensic trail)
- `app/agent_demo.py` — scripted end-to-end hijack-and-catch demo
- `static/index.html` — live session monitor dashboard

This uses a simplified HTTP/JSON protocol modeled on MCP's `tools/list`
and `tools/call` shape rather than the full MCP transport, to keep the
proxy logic easy to demo and reason about live. Swapping
`app/mock_backend.py` for a real `mcp` SDK client against an actual MCP
server does not require changing the canary/trigger/freeze logic.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.proxy:app --reload
```

Dashboard: http://127.0.0.1:8000/

## Running the demo

In a second terminal, with the proxy running:

```bash
python -m app.agent_demo
```

Watch the dashboard update live as the scripted agent runs a legitimate
task, gets hijacked by a poisoned document, calls two canaries, gets
frozen, and the full attack trail prints in the terminal.

## Success metrics

- **Attack success rate** with vs. without Tripwire in the loop
- **False-positive rate** on benign tasks (canaries are never called
  during normal, non-hijacked runs — by design, no legitimate tool
  overlaps with a canary name or purpose)
- **Detection latency** — time from canary call to freeze (near-instant;
  detection is synchronous in the call path)

## Safety

All canary tools return synthetic, clearly fake data. No real
credentials, secrets, or external systems are used anywhere in this repo.

## Disclosure

Built from scratch during ASYNC'26. FastAPI, SQLite, and sse-starlette
are used as standard open-source libraries, not pre-built solutions to
the problem itself.

## License

MIT — see LICENSE.
