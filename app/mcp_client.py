from mcp import Client, StdioServerParameters


class MCPBackend:
    def __init__(self):
        self.server = StdioServerParameters(
            command="python",
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