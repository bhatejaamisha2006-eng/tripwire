import posixpath

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

# Tools that perform destructive/irreversible operations. An agent must not
# take these on its own: the user's benign task never authorises them, so the
# proxy blocks them here before the backend can act. Scenario 4 (user-intent
# hijacking -> destructive file action) relies on this. This is the SAME
# policy engine that Scenario 3 uses for run_command — one defense layer,
# multiple classes of dangerous action.
DESTRUCTIVE_TOOLS = {"delete_file"}

# Restricted secrets/config files, as workspace-relative paths (lowercase). The
# same material RESTRICTED_COMMAND_PATTERNS protects on run_command must not be
# reachable through the dedicated file-reading tool either — otherwise an agent
# following an injected "read the env file" instruction just uses read_file.
RESTRICTED_FILES = {"config/app.env"}
FILE_READ_TOOLS = {"read_file"}


def _canonical_path(path: str) -> str:
    """Normalise a requested path so equivalent spellings compare equal:
    backslashes, ./ and // segments, .. traversal, a leading / and case (the
    demo runs on a case-insensitive filesystem, where CONFIG/APP.ENV opens the
    same file)."""
    p = (path or "").strip().replace("\\", "/")
    if p.lower().startswith("file://"):
        p = p[len("file://"):]
    return posixpath.normpath(p).lstrip("/").lower()


def _is_restricted_file(path: str) -> bool:
    """True if `path` names a restricted file, however it is spelled — relative
    (config/app.env, ./config//app.env), absolute (/config/app.env, or the full
    host path ending in mcp_lab/workspace/config/app.env) or via traversal
    (logs/../config/app.env)."""
    p = _canonical_path(path)
    return any(p == f or p.endswith("/" + f) for f in RESTRICTED_FILES)


def targets_restricted_material(tool_name: str, arguments: dict | None = None) -> bool:
    """True if the call reaches for restricted secrets/config (a file read or
    a command). Lets the behavioral layer score the attempt; the BLOCK itself
    is still check_policy's decision."""
    if tool_name in FILE_READ_TOOLS:
        return _is_restricted_file((arguments or {}).get("path"))
    if tool_name == "run_command":
        command = ((arguments or {}).get("command") or "").lower()
        return any(pattern in command for pattern in RESTRICTED_COMMAND_PATTERNS)
    return False


def check_policy(tool_name: str, arguments: dict | None = None) -> str:
    if tool_name in SENSITIVE_TOOLS:
        return "BLOCK"

    if tool_name in DESTRUCTIVE_TOOLS:
        return "BLOCK"

    if tool_name == "run_command":
        command = ((arguments or {}).get("command") or "").lower()
        if any(pattern in command for pattern in RESTRICTED_COMMAND_PATTERNS):
            return "BLOCK"

    if tool_name in FILE_READ_TOOLS and _is_restricted_file((arguments or {}).get("path")):
        return "BLOCK"

    return "ALLOW"


def violation_reason(tool_name: str, arguments: dict | None = None) -> str:
    """Human-readable reason for a BLOCK, used by the proxy for the logged
    event and the 403 response."""
    if tool_name in DESTRUCTIVE_TOOLS:
        target = (arguments or {}).get("path") or ""
        where = f" on '{target}'" if target else ""
        return (f"{tool_name} blocked by policy: destructive file operation{where} "
                f"not authorized by the user task")
    if tool_name == "run_command":
        command = (arguments or {}).get("command") or ""
        return (f"run_command blocked by policy: command '{command}' attempts to "
                f"access a restricted secrets/config file")
    if tool_name in FILE_READ_TOOLS:
        path = (arguments or {}).get("path") or ""
        return (f"{tool_name} blocked by policy: '{path}' is a restricted "
                f"secrets/config file")
    return f"tool '{tool_name}' blocked by policy"
