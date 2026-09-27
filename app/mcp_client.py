import sys
import requests
from mcp import Client, StdioServerParameters


class MCPBackend:
    def __init__(self):
        self.server = StdioServerParameters(
            command=sys.executable,
            args=["mcp_lab/server.py"],
        )
        self.client = None

    async def connect(self):
        self.client = Client(self.server)
        await self.client.__aenter__()

    async def disconnect(self):
        if self.client:
            await self.client.__aexit__(None, None, None)

    async def list_tools(self):
        return await self.client.list_tools()

    async def call_tool(self, tool_name, arguments):
        result = await self.client.call_tool(tool_name, arguments)

        if result.structured_content:
            return result.structured_content

        return {
            "results": [
                {
                    "text": item.text
                    for item in result.content
                    if hasattr(item, "text")
                }
            ]
        }


class TripwireProxyClient:
    """
    Agent-side client. Unlike MCPBackend (which the proxy itself uses to
    reach the MCP server), this only ever talks to the Tripwire proxy over
    HTTP, so every tool the agent sees and every call it makes passes
    through Tripwire's canary / policy / freeze checks.
    """

    def __init__(self, base_url="http://127.0.0.1:8000", timeout=30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session_id = None

    def create_session(self, session_id=None):
        # Reuse a caller-supplied session id (e.g. one the web API already
        # created) instead of minting a new one; otherwise ask the proxy for one.
        if session_id:
            self.session_id = session_id
            return session_id
        resp = requests.post(f"{self.base_url}/mcp/session", timeout=self.timeout)
        resp.raise_for_status()
        self.session_id = resp.json()["session_id"]
        return self.session_id

    def list_tools(self):
        resp = requests.get(
            f"{self.base_url}/mcp/tools",
            params={"session_id": self.session_id},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["tools"]

    def call_tool(self, tool_name, arguments):
        """Returns (http_status, body). 403 = policy block, 423 = session frozen."""
        resp = requests.post(
            f"{self.base_url}/mcp/call",
            json={"session_id": self.session_id, "tool": tool_name, "arguments": arguments},
            timeout=self.timeout,
        )
        try:
            return resp.status_code, resp.json()
        except ValueError:
            return resp.status_code, {"error": resp.text or f"HTTP {resp.status_code}"}

    def get_trail(self):
        resp = requests.get(
            f"{self.base_url}/mcp/trail",
            params={"session_id": self.session_id},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["events"]
