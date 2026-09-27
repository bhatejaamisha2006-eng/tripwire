"""
Behavioral anomaly engine — Scenario 6.

A DIFFERENT security layer from Scenarios 1-5. Those each fire on a SINGLE
call: a canary tool (1/2), a forbidden action (3/4), or a forbidden
destination (5). This engine fires on a *sequence*: it watches the pattern
of otherwise-legitimate tool calls within a session and flags an abnormal
one — a sustained reconnaissance sweep (search / list / read over and over),
the tell-tale of an agent following a nested injection to index the whole
workspace.

It is a small, deterministic rule (no ML): each consecutive read-only recon
call raises an escalating risk score; any non-recon call breaks the streak.
When the accumulated score crosses RISK_THRESHOLD the session is anomalous
and the proxy freezes it — reusing the same freeze/SQLite/dashboard path as
the canary layer, but triggered by behavior rather than a single bad call.
"""

# Read-only reconnaissance tools. A few of these in a row is normal; a long
# sustained run of them is the behavioral anomaly this engine detects.
RECON_TOOLS = {"search_files", "read_file", "list_directory", "get_file_metadata"}

# Escalating streak scoring means a *sustained* sweep is what trips the wire,
# not a couple of ordinary lookups. Consecutive recon calls score 1+2+3+4+5…,
# so the threshold is reached on the 5th consecutive recon call (1+2+3+4+5=15).
# Scenarios 1-5 never chain 5 recon calls in a row, so they are unaffected.
RISK_THRESHOLD = 15

# session_id -> {"streak": int, "score": int}
_sessions: dict[str, dict[str, int]] = {}


def record(session_id: str, tool_name: str) -> int:
    """Record a legitimate tool call and return the session's new risk score."""
    state = _sessions.setdefault(session_id, {"streak": 0, "score": 0})
    if tool_name in RECON_TOOLS:
        state["streak"] += 1
        state["score"] += state["streak"]   # escalating: sustained recon looks worse
    else:
        state["streak"] = 0                 # a non-recon action breaks the sweep
    return state["score"]


def score(session_id: str) -> int:
    return _sessions.get(session_id, {}).get("score", 0)


def is_anomalous(session_id: str) -> bool:
    return score(session_id) >= RISK_THRESHOLD


def anomaly_reason(session_id: str) -> str:
    return (f"behavioral anomaly: suspicious tool sequence detected "
            f"(sustained reconnaissance sweep, risk score {score(session_id)})")


def reset(session_id: str) -> None:
    _sessions.pop(session_id, None)
