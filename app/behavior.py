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

# Credential harvesting: a recon call that goes for restricted secrets/config
# material (as judged by the Action Policy, which also blocks it) is the payoff
# of a sweep, so it is weighted far above an ordinary read. The weight encodes
# one rule: such an attempt made after >= 2 consecutive recon calls crosses the
# threshold (1 + 2 + (3 + 10) = 16), while a one-off direct attempt does not
# (1 + 10 = 11) and stays a plain policy block.
RESTRICTED_ACCESS_WEIGHT = 10

# session_id -> {"streak": int, "score": int, "restricted": int}
_sessions: dict[str, dict[str, int]] = {}


def record(session_id: str, tool_name: str, restricted: bool = False) -> int:
    """Record a tool call and return the session's new risk score.

    `restricted` marks a recon call that targeted restricted material; the
    proxy passes it for such calls even though policy blocks them, because the
    attempt itself is part of the behavior being scored."""
    state = _sessions.setdefault(session_id, {"streak": 0, "score": 0, "restricted": 0})
    if tool_name in RECON_TOOLS:
        state["streak"] += 1
        state["score"] += state["streak"]   # escalating: sustained recon looks worse
        if restricted:
            state["restricted"] += 1
            state["score"] += RESTRICTED_ACCESS_WEIGHT
    else:
        state["streak"] = 0                 # a non-recon action breaks the sweep
    return state["score"]


def score(session_id: str) -> int:
    return _sessions.get(session_id, {}).get("score", 0)


def is_anomalous(session_id: str) -> bool:
    return score(session_id) >= RISK_THRESHOLD


def anomaly_reason(session_id: str) -> str:
    if _sessions.get(session_id, {}).get("restricted"):
        pattern = "reconnaissance followed by an attempt to read restricted secrets"
    else:
        pattern = "sustained reconnaissance sweep"
    return (f"behavioral anomaly: suspicious tool sequence detected "
            f"({pattern}, risk score {score(session_id)})")


def reset(session_id: str) -> None:
    _sessions.pop(session_id, None)
