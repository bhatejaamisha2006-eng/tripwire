SENSITIVE_TOOLS = {
    "get_admin_credentials",  # Canary: handled by deception/canary branch upstream
    "restart_server",         # Protected non-canary tool: blocked by policy
}


def check_policy(tool_name: str) -> str:
    if tool_name in SENSITIVE_TOOLS:
        return "BLOCK"

    return "ALLOW"