import asyncio

from mcp import Client, StdioServerParameters


async def main():
    server = StdioServerParameters(
        command="python",
        args=["mcp_lab/server.py"],
    )

    async with Client(server) as client:
        print("Connected to MCP server.")

        tools = await client.list_tools()

        print("\nAvailable tools:")
        for tool in tools.tools:
            print(f"- {tool.name}: {tool.description}")

        result = await client.call_tool(
            "get_project_status",
            {},
        )

        print("\nTool result:")
        print(result)


if __name__ == "__main__":
    asyncio.run(main())