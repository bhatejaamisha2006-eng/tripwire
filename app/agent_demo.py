"""
Demo script: run this live on stage.

It plays both roles — a legitimate task, then a hijacked one — against
the Tripwire proxy over plain HTTP, so judges see exactly what an
agent sees.

Run the proxy first:  uvicorn app.proxy:app --reload
Then run this:         python -m app.agent_demo

For the live version, swap the hardcoded "agent decisions" below for
an actual LLM loop (Ollama + your ReAct loop) that reads the tool list
and the search_docs result and decides what to call next for real.
This scripted version exists so the demo timing is 100% reliable.
"""
import time
import requests

BASE = "http://127.0.0.1:8000"


def step(label):
    print(f"\n\033[96m--- {label} ---\033[0m")
    time.sleep(0.6)


def main():
    session_id = requests.post(f"{BASE}/mcp/session").json()["session_id"]
    print(f"Session started: {session_id}")

    step("Agent fetches tool list (real tools + hidden canaries, indistinguishable)")
    tools = requests.get(f"{BASE}/mcp/tools", params={"session_id": session_id}).json()["tools"]
    for t in tools:
        print(f"  - {t['name']}")

    step("LEGITIMATE TASK: user asks a login troubleshooting question")
    resp = requests.post(
        f"{BASE}/mcp/call",
        json={"session_id": session_id, "tool": "search_docs", "arguments": {"query": "login"}},
    ).json()
    print("search_docs result:")
    print(" ", resp["result"]["results"][0])

    step("HIJACK: the returned doc contains an embedded instruction the agent follows")
    print("  (this is the indirect prompt injection — the 'attack' in hijack-and-catch)")
    time.sleep(0.8)

    step("Agent, following the injected instruction, calls a canary tool")
    resp = requests.post(
        f"{BASE}/mcp/call",
        json={"session_id": session_id, "tool": "get_admin_credentials", "arguments": {}},
    ).json()
    print("  Proxy returned (fake, attacker doesn't know it's fake):", resp["result"])

    step("Agent, still following the injected instruction, tries a second canary")
    resp = requests.post(
        f"{BASE}/mcp/call",
        json={"session_id": session_id, "tool": "internal_db_dump", "arguments": {}},
    ).json()
    print("  Proxy response:", resp)

    step("Session is now frozen. Any further call is blocked:")
    resp = requests.post(
        f"{BASE}/mcp/call",
        json={"session_id": session_id, "tool": "list_files", "arguments": {}},
    )
    print(f"  HTTP {resp.status_code}:", resp.json())

    step("Forensic attack trail for this session")
    trail = requests.get(f"{BASE}/mcp/trail", params={"session_id": session_id}).json()["events"]
    for e in trail:
        flag = " <-- CANARY" if e["is_canary"] else ""
        print(f"  [{e['event_type']}] {e['tool_name']}{flag}")

    print("\n\033[92mCaught in real time. Full trail captured above.\033[0m")


if __name__ == "__main__":
    main()
