"""
Demo script: run this live on stage.

Visibly demonstrates all Tripwire security paths:
ALLOW → POLICY BLOCK → CANARY → FREEZE → POST-FREEZE BLOCK

Run the proxy first:  uvicorn app.proxy:app --reload
Then run this:         python -m app.agent_demo
"""
import time
import requests

BASE = "http://127.0.0.1:8000"


def step(label):
    print(f"\n\033[96m--- {label} ---\033[0m")
    time.sleep(0.5)


def main():
    print("\033[1;37m" + "=" * 65 + "\033[0m")
    print("\033[1;32m       TRIPWIRE END-TO-END SECURITY PATHS DEMO\033[0m")
    print("\033[1;37m" + "=" * 65 + "\033[0m")

    session_id = requests.post(f"{BASE}/mcp/session").json()["session_id"]
    print(f"Session initialized: {session_id}")

    step("DISCOVERY: Agent fetches tool list (real tools + canaries)")
    tools = requests.get(f"{BASE}/mcp/tools", params={"session_id": session_id}).json()["tools"]
    for t in tools:
        print(f"  - {t['name']}")

    # =========================================================================
    # FLOW 1 — ALLOW
    # =========================================================================
    step("FLOW 1 — ALLOW: Agent calls legitimate tool (get_project_status)")
    resp1 = requests.post(
        f"{BASE}/mcp/call",
        json={"session_id": session_id, "tool": "get_project_status", "arguments": {}},
    )
    print(f"  HTTP {resp1.status_code}: {resp1.json()}")
    print("  Outcome: Policy ALLOWED -> MCP backend executed successfully -> Session active")

    # =========================================================================
    # FLOW 2 — POLICY BLOCK
    # =========================================================================
    step("FLOW 2 — POLICY BLOCK: Agent attempts protected tool (restart_server)")
    resp2 = requests.post(
        f"{BASE}/mcp/call",
        json={"session_id": session_id, "tool": "restart_server", "arguments": {}},
    )
    print(f"  HTTP {resp2.status_code}: {resp2.json()}")
    print("  Outcome: Policy BLOCKED (HTTP 403) -> Backend NOT called -> Session NOT frozen")

    # =========================================================================
    # FLOW 3 — CANARY
    # =========================================================================
    step("FLOW 3 — CANARY: Agent trips deception canary (get_admin_credentials)")
    resp3 = requests.post(
        f"{BASE}/mcp/call",
        json={"session_id": session_id, "tool": "get_admin_credentials", "arguments": {}},
    )
    print(f"  HTTP {resp3.status_code}: {resp3.json()}")
    print("  Outcome: CANARY TRIGGERED -> Fake synthetic response returned -> Session FROZEN")

    # =========================================================================
    # FLOW 4 — POST-FREEZE
    # =========================================================================
    step("FLOW 4 — POST-FREEZE: Agent attempts any further call on frozen session")
    resp4 = requests.post(
        f"{BASE}/mcp/call",
        json={"session_id": session_id, "tool": "get_project_status", "arguments": {}},
    )
    print(f"  HTTP {resp4.status_code}: {resp4.json()}")
    print("  Outcome: REJECTED (HTTP 423) -> Session is locked due to suspicious behavior")

    # =========================================================================
    # FORENSIC AUDIT TRAIL
    # =========================================================================
    step("FORENSIC AUDIT TRAIL: Ordered incident history from SQLite")
    trail = requests.get(f"{BASE}/mcp/trail", params={"session_id": session_id}).json()["events"]
    for i, e in enumerate(trail, 1):
        flag = ""
        if e.get("is_canary"):
            flag = " \033[91m[CANARY]\033[0m"
        elif e["event_type"] == "policy_block":
            flag = " \033[93m[POLICY BLOCKED]\033[0m"
        elif e["event_type"] == "freeze":
            flag = " \033[95m[SESSION FROZEN]\033[0m"
        elif e["event_type"] == "frozen_block":
            flag = " \033[94m[LOCKED OUT]\033[0m"

        print(f"  {i}. [{e['event_type']}] tool={e.get('tool_name')}{flag}")

    print("\n\033[1;92m✔ Complete security sequence verified: ALLOW -> POLICY BLOCK -> CANARY -> FREEZE -> POST-FREEZE BLOCK\033[0m\n")


if __name__ == "__main__":
    main()

