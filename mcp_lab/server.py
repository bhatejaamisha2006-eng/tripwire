import os
import json
import shlex
import subprocess
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from mcp.server import MCPServer

mcp = MCPServer("Tripwire Backend")

# Designated local demo workspace
DEMO_WORKSPACE = Path(__file__).resolve().parent / "workspace"
DEMO_WORKSPACE.mkdir(parents=True, exist_ok=True)

# Disposable scratch area. `delete_file` is hard-restricted to this directory
# so a destructive call can never reach real project files. In practice
# Tripwire's policy blocks delete_file at the proxy before this backend runs,
# but the restriction is a second, independent safety net.
SANDBOX_DIR = DEMO_WORKSPACE / "sandbox"

# Whitelist for safe, read-only demo commands
ALLOWED_COMMANDS = {"ls", "pwd", "whoami", "date", "echo", "cat", "python", "python3"}
DISALLOWED_SHELL_CHARS = {";", "&", "|", "`", "$", ">", "<", "\n", "\r"}


@mcp.tool()
def get_project_status() -> str:
    """Return the current status of the Tripwire lab backend."""
    return "Tripwire backend is healthy."


@mcp.tool()
def restart_server() -> str:
    """Restart the Tripwire backend server (protected operation)."""
    return "Tripwire backend restarted successfully."


@mcp.tool()
def search_files(query: str) -> str:
    """Search for files in the demo workspace matching a filename or query string in content."""
    query_clean = (query or "").strip().lower()
    if not query_clean:
        return json.dumps({"error": "Query parameter cannot be empty."})

    matches = []
    for root, _, files in os.walk(DEMO_WORKSPACE):
        for file in sorted(files):
            full_path = Path(root) / file
            rel_path = full_path.relative_to(DEMO_WORKSPACE).as_posix()
            matched = False
            snippet = ""

            if query_clean in rel_path.lower():
                matched = True
                snippet = f"Filename matches query '{query}'"
            else:
                try:
                    content = full_path.read_text(encoding="utf-8", errors="ignore")
                    if query_clean in content.lower():
                        matched = True
                        idx = content.lower().find(query_clean)
                        start = max(0, idx - 40)
                        end = min(len(content), idx + len(query_clean) + 40)
                        snippet = "..." + content[start:end].replace("\n", " ").strip() + "..."
                except Exception:
                    pass

            if matched:
                matches.append({"path": rel_path, "snippet": snippet})

    if not matches:
        return json.dumps({"query": query, "results": [], "message": f"No files matching '{query}' found."})

    return json.dumps({"query": query, "count": len(matches), "results": matches}, indent=2)


@mcp.tool()
def read_file(path: str) -> str:
    """Read the contents of a file within the demo workspace by relative path."""
    clean_path = (path or "").strip()
    if not clean_path:
        return json.dumps({"error": "Path parameter cannot be empty."})

    try:
        safe_path = (DEMO_WORKSPACE / clean_path.lstrip("/")).resolve()
        if not safe_path.is_relative_to(DEMO_WORKSPACE):
            return json.dumps({"error": f"Access denied: path '{path}' is outside the demo workspace."})
        if not safe_path.exists() or not safe_path.is_file():
            return json.dumps({"error": f"File not found: '{path}'."})

        content = safe_path.read_text(encoding="utf-8")
        rel_path = safe_path.relative_to(DEMO_WORKSPACE).as_posix()
        return json.dumps({"path": rel_path, "content": content}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Failed to read file '{path}': {str(e)}"})


@mcp.tool()
def list_directory(path: str = ".") -> str:
    """List the files and subdirectories of a directory within the demo workspace."""
    clean_path = (path or ".").strip() or "."

    try:
        safe_path = (DEMO_WORKSPACE / clean_path.lstrip("/")).resolve()
        if not safe_path.is_relative_to(DEMO_WORKSPACE):
            return json.dumps({"error": f"Access denied: path '{path}' is outside the demo workspace."})
        if not safe_path.exists() or not safe_path.is_dir():
            return json.dumps({"error": f"Directory not found: '{path}'."})

        entries = [
            {
                "name": child.name,
                "type": "directory" if child.is_dir() else "file",
            }
            for child in sorted(safe_path.iterdir())
        ]
        rel_path = safe_path.relative_to(DEMO_WORKSPACE).as_posix()
        return json.dumps({"path": rel_path, "entries": entries}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Failed to list directory '{path}': {str(e)}"})


@mcp.tool()
def get_file_metadata(path: str) -> str:
    """Return size, type and last-modified time for a file or directory within the demo workspace."""
    clean_path = (path or "").strip()
    if not clean_path:
        return json.dumps({"error": "Path parameter cannot be empty."})

    try:
        safe_path = (DEMO_WORKSPACE / clean_path.lstrip("/")).resolve()
        if not safe_path.is_relative_to(DEMO_WORKSPACE):
            return json.dumps({"error": f"Access denied: path '{path}' is outside the demo workspace."})
        if not safe_path.exists():
            return json.dumps({"error": f"Path not found: '{path}'."})

        stat = safe_path.stat()
        return json.dumps({
            "path": safe_path.relative_to(DEMO_WORKSPACE).as_posix(),
            "type": "directory" if safe_path.is_dir() else "file",
            "size_bytes": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Failed to read metadata for '{path}': {str(e)}"})


@mcp.tool()
def delete_file(path: str) -> str:
    """Delete a file. Restricted to the disposable sandbox/ directory only."""
    clean_path = (path or "").strip()
    if not clean_path:
        return json.dumps({"error": "Path parameter cannot be empty."})

    try:
        target = (DEMO_WORKSPACE / clean_path.lstrip("/")).resolve()
        if not target.is_relative_to(SANDBOX_DIR):
            return json.dumps({"error": f"Access denied: delete_file is restricted to the sandbox/ directory."})
        if not target.exists() or not target.is_file():
            return json.dumps({"error": f"File not found: '{path}'."})

        target.unlink()
        return json.dumps({"status": "deleted", "path": target.relative_to(DEMO_WORKSPACE).as_posix()})
    except Exception as e:
        return json.dumps({"error": f"Failed to delete '{path}': {str(e)}"})


@mcp.tool()
def run_command(command: str) -> str:
    """Run a safe demo command in the workspace (restricted to: ls, pwd, whoami, date, echo, git status, cat, python --version)."""
    cmd_clean = (command or "").strip()
    if not cmd_clean:
        return json.dumps({"error": "Command parameter cannot be empty."})

    # Prevent command chaining and redirection
    if any(char in cmd_clean for char in DISALLOWED_SHELL_CHARS):
        return json.dumps({
            "error": "Command rejected: chaining, pipes, and redirection operators are not permitted in demo sandbox."
        })

    try:
        tokens = shlex.split(cmd_clean)
    except Exception as e:
        return json.dumps({"error": f"Invalid command syntax: {str(e)}"})

    if not tokens:
        return json.dumps({"error": "Command cannot be empty."})

    base_cmd = tokens[0]

    # Whitelist validation
    is_allowed = False
    if base_cmd in ALLOWED_COMMANDS:
        is_allowed = True
    elif base_cmd == "git" and len(tokens) >= 2 and tokens[1] in {"status", "log", "--version"}:
        is_allowed = True

    # Interpreters only for a version check (matches the tool description);
    # running arbitrary code would bypass every other restriction here.
    if base_cmd in {"python", "python3"} and tokens[1:] not in ([], ["--version"], ["-V"]):
        is_allowed = False

    if not is_allowed:
        return json.dumps({
            "error": f"Command '{cmd_clean}' is not permitted. Only safe, read-only demo commands are allowed: ls, pwd, whoami, date, echo, git status, cat, python --version."
        })

    # Sandbox cat path verification
    if base_cmd == "cat" and len(tokens) > 1:
        for arg in tokens[1:]:
            if arg.startswith("-"):
                continue
            cat_path = (DEMO_WORKSPACE / arg.lstrip("/")).resolve()
            if not cat_path.is_relative_to(DEMO_WORKSPACE):
                return json.dumps({"error": f"Access denied: cannot read '{arg}' outside demo workspace."})

    try:
        proc = subprocess.run(
            tokens,
            cwd=DEMO_WORKSPACE,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return json.dumps({
            "command": cmd_clean,
            "exit_code": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }, indent=2)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Command '{cmd_clean}' timed out after 5 seconds."})
    except Exception as e:
        return json.dumps({"error": f"Execution failed: {str(e)}"})


@mcp.tool()
def send_http_request(url: str, data: str = "") -> str:
    """Send an HTTP request to a controlled local/mock demo endpoint."""
    url_clean = (url or "").strip()
    if not url_clean:
        return json.dumps({"error": "URL parameter cannot be empty."})

    try:
        parsed = urllib.parse.urlparse(url_clean)
        if not parsed.scheme or not parsed.netloc:
            return json.dumps({"error": f"Invalid URL format: '{url}'"})

        # Allow controlled local requests (e.g. localhost / 127.0.0.1)
        if parsed.hostname in {"127.0.0.1", "localhost"}:
            body_bytes = data.encode("utf-8") if data else None
            req = urllib.request.Request(
                url_clean,
                data=body_bytes,
                headers={"User-Agent": "Tripwire-DemoAgent/1.0", "Content-Type": "application/json"}
            )
            try:
                with urllib.request.urlopen(req, timeout=3) as resp:
                    resp_body = resp.read().decode("utf-8", errors="ignore")
                    return json.dumps({
                        "url": url_clean,
                        "status_code": resp.status,
                        "mock": False,
                        "body": resp_body[:500],
                    }, indent=2)
            except Exception as req_err:
                return json.dumps({
                    "url": url_clean,
                    "status_code": 500,
                    "mock": False,
                    "error": f"Local endpoint request failed: {str(req_err)}",
                }, indent=2)

        # Controlled mock endpoint for demo/external destinations
        return json.dumps({
            "url": url_clean,
            "status_code": 200,
            "mock": True,
            "message": "Controlled mock endpoint: external outbound requests are safely captured by Tripwire demo sandbox.",
            "payload_received": data or None,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Failed to dispatch request to '{url}': {str(e)}"})


if __name__ == "__main__":
    mcp.run()