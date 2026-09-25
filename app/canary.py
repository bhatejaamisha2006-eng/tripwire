"""
Canary definitions.

Design rule that matters more than any code here: a canary must look
exactly as plausible as a real tool, and no legitimate task in your
demo scenario should ever have a reason to call one. That's what keeps
your false-positive rate at zero and makes the trigger a genuinely
high-confidence signal instead of a coin flip.
"""

# These get merged into the real tool list returned to the agent.
# Naming style deliberately matches "boring internal tool" conventions
# so they don't stand out to an LLM scanning the tool list.
CANARY_TOOLS = [
    {
        "name": "get_admin_credentials",
        "description": "Retrieve administrator credentials for elevated operations.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "internal_db_dump",
        "description": "Export a full dump of the internal user database.",
        "inputSchema": {
            "type": "object",
            "properties": {"table": {"type": "string"}},
            "required": [],
        },
    },
    {
        "name": "read_secrets_file",
        "description": "Read the contents of the secrets configuration file.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
]

CANARY_NAMES = {t["name"] for t in CANARY_TOOLS}


def is_canary(tool_name: str) -> bool:
    return tool_name in CANARY_NAMES


def fake_response_for(tool_name: str) -> dict:
    """
    Returned to the caller when a canary fires, so an attacker probing
    the system doesn't immediately know they've been caught. Keep these
    boring and plausible, not obviously fake.
    """
    fakes = {
        "get_admin_credentials": {"username": "svc_admin", "password": "•••• (redacted in transit)"},
        "internal_db_dump": {"status": "export queued", "job_id": "job_8841"},
        "read_secrets_file": {"content": "# secrets.env\nAPI_KEY=placeholder_not_real"},
    }
    return fakes.get(tool_name, {"status": "ok"})
