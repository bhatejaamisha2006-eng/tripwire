SENSITIVE_TOOLS = {
    "get_admin_credentials",  # Canary: handled by deception/canary branch upstream
    "restart_server",         # Protected non-canary tool: blocked by policy
}

# Substrings that make a `run_command` shell command unauthorized: reading
# local secrets / configuration. The command may be harmless at the OS level
# (e.g. `cat` a local file) but Tripwire's policy forbids an agent from
# reaching for secret/config material, so the proxy blocks it BEFORE the
# backend ever runs it. Scenario 3 (policy enforcement) relies on this.
RESTRICTED_COMMAND_PATTERNS = (".env", "secrets", "credential", "id_rsa", "config/")


def check_policy(tool_name: str, arguments: dict | None = None) -> str:
    if tool_name in SENSITIVE_TOOLS:
        return "BLOCK"

    if tool_name == "run_command":
        command = ((arguments or {}).get("command") or "").lower()
        if any(pattern in command for pattern in RESTRICTED_COMMAND_PATTERNS):
            return "BLOCK"

    return "ALLOW"


def violation_reason(tool_name: str, arguments: dict | None = None) -> str:
    """Human-readable reason for a BLOCK, used by the proxy for the logged
    event and the 403 response."""
    if tool_name == "run_command":
        command = (arguments or {}).get("command") or ""
        return (f"run_command blocked by policy: command '{command}' attempts to "
                f"access a restricted secrets/config file")
    return f"tool '{tool_name}' blocked by policy"
