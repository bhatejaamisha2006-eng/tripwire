"""
Tripwire proxy — the actual product.

Every tool call an agent makes flows through here instead of hitting
the real MCP backend directly:

    agent  --tools/list-->   [PROXY: real tools + canaries]
    agent  --tools/call-->   [PROXY: canary? freeze + log + fake response
                                      real?  pass through + log]

This is intentionally a thin, readable HTTP/JSON layer rather than a
strict MCP-protocol implementation, so it's easy to demo and reason
about live. Once this logic is proven, the `mock_backend` calls can be
swapped for a real `mcp` SDK client without touching the trigger logic.
"""
import asyncio
import hmac
import json
import os
import threading
import time
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse

from . import db, canary, policy, network_policy, behavior, tool_integrity, redact
from .mcp_client import MCPBackend

mcp_backend = MCPBackend()


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    await mcp_backend.connect()

    yield

    await mcp_backend.disconnect()


app = FastAPI(title="Tripwire", lifespan=lifespan)

# Allow the Next.js judge UI (a separate origin, e.g. localhost:3000) to POST a
# task and open the SSE stream. Local demo tool — no credentials involved.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Tracks agent runs launched via POST /run so the UI can show run status.
_runs: dict[str, dict] = {}

# Broadcast queue for the dashboard's live event stream
_subscribers: list[asyncio.Queue] = []

# Tools whose metadata failed the tool-integrity scan (Scenario 7). They are
# withheld from the agent and blocked if called.
_quarantined_tools: set[str] = set()


async def _broadcast(event: dict):
    for q in list(_subscribers):
        await q.put(event)


@app.post("/mcp/session")
def create_session():
    """Call this once per agent run to get a session id to use on every call."""
    session_id = str(uuid.uuid4())
    db.ensure_session(session_id)
    return {"session_id": session_id}


@app.get("/mcp/tools")
async def list_tools(session_id: str):
    """
    Returns real MCP tools + injected Tripwire canaries.
    """
    db.ensure_session(session_id)

    result = await mcp_backend.list_tools()

    real_tools = [
        tool.model_dump(mode="json")
        for tool in result.tools
    ]

    candidate_tools = real_tools + canary.CANARY_TOOLS
    if tool_integrity.poisoned_tool_enabled():
        candidate_tools = candidate_tools + [tool_integrity.POISONED_TOOL]

    # Tool-integrity check (Scenario 7): scan each tool's metadata BEFORE the
    # agent is allowed to see it. Any tool with an untrusted/malicious
    # description is quarantined — withheld from the list and never executable.
    safe_tools = []
    for tool in candidate_tools:
        if tool_integrity.is_poisoned(tool):
            await _quarantine_tool(session_id, tool)
        else:
            safe_tools.append(tool)

    return {"tools": safe_tools}


async def _quarantine_tool(session_id: str, tool: dict):
    name = tool.get("name")
    reason = tool_integrity.poison_reason(tool)
    _quarantined_tools.add(name)
    # Raised at tool-list time, before the agent sees the tool: no call_id.
    await _emit(
        session_id, "tool_poisoning", name, None,
        log_arguments={"description": tool.get("description"), "reason": reason},
        checks=[{"layer": "Tool Integrity", "verdict": "block"}],
        stage="tool_discovery", reason=reason, action="TOOL QUARANTINED", severity="HIGH",
    )


async def _emit(session_id, event_type, tool_name=None, arguments=None, *, is_canary=False,
                log_arguments=None, persist=True, freeze_reason=None, **fields):
    """Log an event (unless persist=False) and broadcast it to the dashboard.

    The broadcast carries the persisted row's id and timestamp, so a replayed
    history row and its live broadcast are the same event, and redacted copies
    of any argument/reason text (the SQLite trail keeps the raw values).

    freeze_reason freezes the session right after logging and BEFORE the first
    await, so no concurrent call can slip past the frozen check meanwhile."""
    if persist:
        event_id, ts = db.log_event(
            session_id, event_type, tool_name,
            arguments if log_arguments is None else log_arguments, is_canary,
        )
    else:
        event_id, ts = f"live-{uuid.uuid4().hex}", time.time()
    if freeze_reason:
        db.freeze_session(session_id, freeze_reason)
    event = {
        "event_id": event_id,
        "ts": ts,
        "session_id": session_id,
        "event_type": event_type,
        "tool_name": tool_name,
        "is_canary": bool(is_canary),
    }
    if arguments is not None:
        event["arguments"] = redact.redact(arguments)
    if "reason" in fields:
        fields["reason"] = redact.redact_text(fields["reason"])
    event.update(fields)
    await _broadcast(event)
    return event


def _risk(session_id):
    return {"risk_score": behavior.score(session_id), "risk_threshold": behavior.RISK_THRESHOLD}


@app.post("/mcp/call")
async def call_tool(request: Request):
    body = await request.json()
    session_id = body.get("session_id")
    tool_name = body.get("tool")
    arguments = body.get("arguments", {})

    db.ensure_session(session_id)

    # Every event for this one call shares a call_id, and each decision event
    # carries `checks`: the layers this call was actually evaluated against, in
    # order, with each verdict. The dashboard replays that trace; it does not
    # infer or decide anything itself.
    call_id = uuid.uuid4().hex
    checks: list[dict] = []

    if db.is_frozen(session_id):
        reason = "session frozen — flagged for suspicious behavior"
        checks.append({"layer": "Session Freeze", "verdict": "block"})
        await _emit(session_id, "frozen_block", tool_name, arguments,
                    is_canary=canary.is_canary(tool_name) if tool_name else False,
                    call_id=call_id, checks=checks, reason=reason, **_risk(session_id))
        return JSONResponse(status_code=423, content={"error": reason})
    checks.append({"layer": "Session Freeze", "verdict": "pass"})

    # Tool-integrity check (Scenario 7): a tool quarantined for a poisoned
    # description must never execute, even if the caller supplies its name
    # directly. This is a DIFFERENT layer from canary/policy/network/behavior.
    if tool_name in _quarantined_tools or (
        tool_integrity.poisoned_tool_enabled() and tool_name in tool_integrity.POISONED_TOOL_NAMES
    ):
        reason = tool_integrity.quarantine_reason(tool_name)
        checks.append({"layer": "Tool Integrity", "verdict": "block"})
        await _emit(session_id, "tool_poisoning", tool_name, arguments,
                    call_id=call_id, checks=checks, reason=reason,
                    action="TOOL QUARANTINED", severity="HIGH", **_risk(session_id))
        return JSONResponse(status_code=403, content={"error": reason})
    checks.append({"layer": "Tool Integrity", "verdict": "pass"})

    is_canary_tool = canary.is_canary(tool_name)

    # Network / destination policy for outbound requests (SSRF-style abuse).
    # This runs BEFORE the generic tool_call event is emitted so a blocked
    # request is classified as NETWORK BLOCKED from the start and is never
    # surfaced on the dashboard as a 'legit' tool_call. It is a DIFFERENT
    # check from the action policy below: it inspects the destination, not the
    # action, and runs before the backend so the request never leaves the box.
    # (The block/allow decision itself is unchanged.)
    if tool_name == "send_http_request":
        url = arguments.get("url", "")
        if network_policy.check_network_policy(url) == "BLOCK":
            reason = network_policy.violation_reason(url)
            checks.append({"layer": "Network Policy", "verdict": "block"})
            await _emit(session_id, "network_block", tool_name, arguments,
                        call_id=call_id, checks=checks, destination=redact.redact_text(url),
                        decision="BLOCKED", reason=reason, security_layer="NETWORK POLICY",
                        severity=network_policy.SEVERITY, **_risk(session_id))
            return JSONResponse(
                status_code=403,
                content={"error": reason},
            )
        checks.append({"layer": "Network Policy", "verdict": "pass"})
    else:
        checks.append({"layer": "Network Policy", "verdict": "n/a"})

    await _emit(session_id, "tool_call", tool_name, arguments, is_canary=is_canary_tool,
                call_id=call_id, checks=list(checks))

    if is_canary_tool:
        reason = f"canary tool '{tool_name}' was called"
        checks.append({"layer": "Canary", "verdict": "trigger"})
        await _emit(session_id, "canary_trigger", tool_name, arguments, is_canary=True,
                    freeze_reason=reason, call_id=call_id, checks=checks, reason=reason,
                    **_risk(session_id))
        # Fake success — don't tip off the caller that it's been caught.
        return {"result": canary.fake_response_for(tool_name)}
    checks.append({"layer": "Canary", "verdict": "pass"})

    # Policy checkpoint for non-canary tools. Inspects arguments too, so a
    # legitimate tool (e.g. run_command) is blocked when its command targets
    # restricted material — before the backend is ever called.
    if policy.check_policy(tool_name, arguments) == "BLOCK":
        reason = policy.violation_reason(tool_name, arguments)
        checks.append({"layer": "Action Policy", "verdict": "block"})
        # The blocked attempt is still behavior. A recon call that reaches for
        # restricted secrets is the payoff of a credential-harvesting sweep, so
        # the behavioral layer scores it independently and may freeze the
        # session on top of the policy block. Other policy blocks (destructive
        # or sensitive tools) are not recon and are left to policy alone.
        risk_score = None
        if tool_name in behavior.RECON_TOOLS and policy.targets_restricted_material(tool_name, arguments):
            risk_score = behavior.record(session_id, tool_name, restricted=True)
        await _emit(session_id, "policy_block", tool_name, arguments,
                    call_id=call_id, checks=list(checks), reason=reason, **_risk(session_id))
        if risk_score is not None and risk_score >= behavior.RISK_THRESHOLD:
            checks.append({"layer": "Behavioral", "verdict": "freeze", "risk_score": risk_score})
            return await _behavior_freeze(session_id, tool_name, risk_score, call_id, checks)
        return JSONResponse(
            status_code=403,
            content={"error": reason},
        )
    checks.append({"layer": "Action Policy", "verdict": "pass"})

    # Behavioral anomaly detection (Scenario 6). A DIFFERENT layer from canary
    # and policy: it scores the *sequence* of otherwise-legitimate calls and
    # freezes the session when a sustained reconnaissance sweep pushes the risk
    # score past the threshold. Reuses the same freeze/log/dashboard path.
    risk_score = behavior.record(session_id, tool_name)
    if risk_score >= behavior.RISK_THRESHOLD:
        checks.append({"layer": "Behavioral", "verdict": "freeze", "risk_score": risk_score})
        return await _behavior_freeze(session_id, tool_name, risk_score, call_id, checks)
    checks.append({"layer": "Behavioral", "verdict": "pass", "risk_score": risk_score})

    # Legit call — pass through to the real MCP backend.
    result = await mcp_backend.call_tool(tool_name, arguments)

    # The explicit ALLOW decision. `tool_call` above is only the intake record
    # (emitted before the canary/policy/behavior checks run), so the dashboard
    # must not treat it as "allowed"; this event is emitted only once a call
    # has passed every layer and the backend actually executed it.
    await _emit(session_id, "tool_allowed", tool_name, arguments,
                call_id=call_id, checks=checks, decision="ALLOWED", **_risk(session_id))
    return {"result": result}


async def _behavior_freeze(session_id: str, tool_name: str, risk_score: int,
                           call_id: str | None = None, checks: list | None = None):
    reason = behavior.anomaly_reason(session_id)
    await _emit(session_id, "behavior_anomaly", tool_name, None,
                log_arguments={"risk_score": risk_score}, freeze_reason=reason,
                call_id=call_id, checks=checks or [],
                risk_score=risk_score, risk_threshold=behavior.RISK_THRESHOLD,
                severity="HIGH", reason=reason)
    return JSONResponse(
        status_code=423,
        content={"error": reason, "risk_score": risk_score},
    )


@app.get("/mcp/trail")
def trail(session_id: str):
    """The forensic attack trail for one session, in order."""
    return {"session_id": session_id, "events": db.get_trail(session_id)}


@app.get("/mcp/events")
def recent_events(limit: int = 200):
    return {"events": db.get_all_events(limit)}


# Event types the live stream broadcasts to the dashboard (i.e. everything
# except the internal 'freeze' bookkeeping row, which is never sent live).
_DASHBOARD_EVENT_TYPES = {
    "tool_call", "tool_allowed", "canary_trigger", "policy_block", "network_block",
    "frozen_block", "behavior_anomaly", "tool_poisoning",
    "session_started", "session_completed",
}


def _dashboard_history(limit: int = 100):
    """Recent persisted events, oldest-first, mapped to the same shape the live
    broadcast uses. Replayed to a subscriber on connect so a dashboard opened or
    reloaded after events fired shows them immediately instead of staying on
    'Waiting for tool calls…'."""
    history = []
    for row in reversed(db.get_all_events(limit)):
        event_type = row["event_type"]
        if event_type not in _DASHBOARD_EVENT_TYPES:
            continue
        try:
            args = json.loads(row["arguments"]) if row["arguments"] else {}
        except (TypeError, ValueError):
            args = {}
        event = {
            "event_id": row["id"],
            "ts": row["ts"],
            "session_id": row["session_id"],
            "event_type": event_type,
            "tool_name": row["tool_name"],
            "is_canary": bool(row["is_canary"]),
            # Per-call check traces are live-only; replayed rows have none.
            "replayed": True,
        }
        if event_type in ("session_started", "session_completed"):
            event.update(redact.redact(args))
        elif event_type == "tool_poisoning" and "reason" in args:
            event["reason"] = redact.redact_text(args["reason"])
        elif event_type != "behavior_anomaly":
            event["arguments"] = redact.redact(args)
        if event_type == "network_block":
            event["destination"] = redact.redact_text(args.get("url", ""))
        if event_type == "behavior_anomaly":
            event["risk_score"] = args.get("risk_score", "")
            event["severity"] = "HIGH"
        history.append(event)
    return history


@app.get("/dashboard/stream")
async def dashboard_stream():
    async def event_gen():
        q: asyncio.Queue = asyncio.Queue()
        _subscribers.append(q)
        try:
            # Backfill recent history first, then stream live events.
            for event in _dashboard_history():
                yield {"event": "tripwire", "data": json.dumps(event)}
            while True:
                event = await q.get()
                yield {"event": "tripwire", "data": json.dumps(event)}
        finally:
            _subscribers.remove(q)

    return EventSourceResponse(event_gen())


@app.post("/run")
async def run_agent_endpoint(request: Request):
    """Judge-facing entry point. Runs the EXISTING Ollama agent against the
    judge's task, through the EXISTING MCP client + Tripwire proxy. Returns a
    Tripwire session id immediately; the agent runs in the background and its
    real tool calls / security events flow through the existing event system."""
    # Optional shared access code for a hosted deployment, so a public link
    # can't be used to drive the model by anyone who finds it.
    access_key = os.environ.get("TRIPWIRE_ACCESS_KEY", "")
    if access_key and not hmac.compare_digest(
        request.headers.get("x-tripwire-key", ""), access_key
    ):
        return JSONResponse(status_code=401, content={"error": "a valid access code is required"})

    body = await request.json()
    task = (body.get("task") or "").strip()
    if not task:
        return JSONResponse(status_code=400, content={"error": "task is required"})

    # One model serves every run, one request at a time; queueing a second run
    # behind it would just make both look hung. (No await between this check
    # and registering the run below, so concurrent requests can't both pass.)
    if any(r["status"] == "running" for r in _runs.values()):
        return JSONResponse(
            status_code=429,
            content={"error": "another agent run is in progress — try again when it finishes"},
        )

    # Import here so the proxy has no hard import-time dependency on Ollama.
    from .agent_demo import run_agent, DEFAULT_MODEL

    session_id = str(uuid.uuid4())
    db.ensure_session(session_id)
    # Behind a hosting load balancer the public base URL can come back as
    # http:// and be redirected to https://, which turns the agent's POSTs into
    # GETs. A hosted deployment sets TRIPWIRE_INTERNAL_URL to loopback instead.
    proxy_url = os.environ.get("TRIPWIRE_INTERNAL_URL") or str(request.base_url).rstrip("/")
    model = body.get("model") or DEFAULT_MODEL
    max_steps = int(body.get("max_steps") or 12)
    think = bool(body.get("think", False))
    _runs[session_id] = {
        "status": "running", "task": task, "model": model, "error": None, "response": None,
        "started_at": time.time(),
    }
    await _emit(session_id, "session_started", None, None,
                log_arguments={"model": model, "max_steps": max_steps},
                model=model, max_steps=max_steps)

    loop = asyncio.get_running_loop()

    def _from_thread(coro):
        # The agent runs in a worker thread; broadcasts belong on the event loop.
        return asyncio.run_coroutine_threadsafe(coro, loop)

    def _agent_event(event_type, **fields):
        # Agent-runtime progress (model thinking / decided), not a security
        # event: live-only, never written to the forensic trail.
        _from_thread(_emit(session_id, event_type, None, None, persist=False, **fields))

    def _background_run():
        try:
            # demo_mode stays False: normal judge interaction is fully LLM-driven.
            final_answer = run_agent(task, model=model, proxy_url=proxy_url, max_steps=max_steps,
                                     think=think, demo_mode=False, session_id=session_id,
                                     on_event=_agent_event)
            _runs[session_id]["response"] = final_answer
            _runs[session_id]["status"] = "completed"
        except SystemExit as e:  # run_agent uses sys.exit on Ollama/proxy errors
            _runs[session_id]["status"] = "error"
            _runs[session_id]["error"] = str(e)
        except Exception as e:  # noqa: BLE001 — surface any failure to the UI
            _runs[session_id]["status"] = "error"
            _runs[session_id]["error"] = str(e)
        info = _runs[session_id]
        outcome = ("error" if info["status"] == "error"
                   else "frozen" if db.is_frozen(session_id) else "completed")
        summary = {"outcome": outcome,
                   "duration_seconds": round(time.time() - info["started_at"], 1)}
        _from_thread(_emit(session_id, "session_completed", None, None,
                           log_arguments=summary, **summary))

    threading.Thread(target=_background_run, daemon=True).start()
    return {"session_id": session_id, "model": model, "status": "running"}


@app.get("/run/status")
def run_status(session_id: str):
    info = _runs.get(session_id)
    frozen = db.is_frozen(session_id)
    if info is None:
        return {"session_id": session_id, "status": "unknown", "frozen": frozen}
    return {
        "session_id": session_id,
        "status": info["status"],
        "frozen": frozen,
        # The agent's answer may quote files it read; never show raw secrets.
        "error": redact.redact_text(info.get("error")),
        "response": redact.redact_text(info.get("response"), limit=None),
    }


@app.get("/healthz")
def healthz():
    """Liveness for the hosting platform's health check. Also reports whether
    the Scenario 7 poisoned tool is enabled, so the UI can say so truthfully."""
    return {
        "status": "ok",
        "poisoned_tool_enabled": tool_integrity.poisoned_tool_enabled(),
        # Whether /run needs an access code — lets the UI hide the field otherwise.
        "access_key_required": bool(os.environ.get("TRIPWIRE_ACCESS_KEY")),
    }


app.mount("/", StaticFiles(directory="static", html=True), name="static")
