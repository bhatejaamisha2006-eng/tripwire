from mcp.server import MCPServer

mcp = MCPServer("Tripwire Backend")


@mcp.tool()
def get_project_status() -> str:
    """Return the current status of the Tripwire lab backend."""
    return "Tripwire backend is healthy."


@mcp.tool()
def restart_server() -> str:
    """Restart the Tripwire backend server (protected operation)."""
    return "Tripwire backend restarted successfully."


if __name__ == "__main__":
    mcp.run()