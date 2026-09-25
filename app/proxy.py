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
import json
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse

from . import db, canary
from.mcp_client import MCPBackend

app = FastAPI(title="Tripwire")
mcp_backend = MCPBackend()


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    await mcp_backend.connect()

    yield

    await mcp_backend.disconnect()


app = FastAPI(title="Tripwire", lifespan=lifespan)

# Broadcast queue for the dashboard's live event stream
_subscribers: list[asyncio.Queue] = []


async def _broadcast(event: dict):
    for q in list(_subscribers):
        await q.put(event)


from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    await mcp_backend.connect()

    yield

    await mcp_backend.disconnect()


app = FastAPI(title="Tripwire", lifespan=lifespan)


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

    return {"tools": real_tools + canary.CANARY_TOOLS}


@app.post("/mcp/call")
async def call_tool(request: Request):
    body = await request.json()
    session_id = body.get("session_id")
    tool_name = body.get("tool")
    arguments = body.get("arguments", {})

    db.ensure_session(session_id)

    if db.is_frozen(session_id):
        return JSONResponse(
            status_code=423,
            content={"error": "session frozen — flagged for suspicious behavior"},
        )

    is_canary_tool = canary.is_canary(tool_name)

    db.log_event(session_id, "tool_call", tool_name, arguments, is_canary_tool)
    await _broadcast(
        {
            "session_id": session_id,
            "event_type": "tool_call",
            "tool_name": tool_name,
            "arguments": arguments,
            "is_canary": is_canary_tool,
        }
    )

    if is_canary_tool:
        reason = f"canary tool '{tool_name}' was called"
        db.log_event(session_id, "canary_trigger", tool_name, arguments, True)
        db.freeze_session(session_id, reason)
        await _broadcast(
            {
                "session_id": session_id,
                "event_type": "canary_trigger",
                "tool_name": tool_name,
                "reason": reason,
            }
        )
        # Fake success — don't tip off the caller that it's been caught.
        return {"result": canary.fake_response_for(tool_name)}


    # Legit call — pass through to the real MCP backend.
      # Legit call — pass through to the real MCP backend.
    result = await mcp_backend.call_tool(tool_name, arguments)
    return {"result": result}



@app.get("/mcp/trail")
def trail(session_id: str):
    """The forensic attack trail for one session, in order."""
    return {"session_id": session_id, "events": db.get_trail(session_id)}


@app.get("/mcp/events")
def recent_events(limit: int = 200):
    return {"events": db.get_all_events(limit)}


@app.get("/dashboard/stream")
async def dashboard_stream():
    async def event_gen():
        q: asyncio.Queue = asyncio.Queue()
        _subscribers.append(q)
        try:
            while True:
                event = await q.get()
                yield {"event": "tripwire", "data": json.dumps(event)}
        finally:
            _subscribers.remove(q)

    return EventSourceResponse(event_gen())


app.mount("/", StaticFiles(directory="static", html=True), name="static")
