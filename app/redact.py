"""
Redaction for anything Tripwire sends to a browser.

The dashboard shows tool arguments and the agent's final answer. Either can
carry secrets — an agent exfiltrating `.env` values puts them in a
send_http_request payload, and an agent that read a config file may quote it
back. This module scrubs secret-shaped values before a live event or run
status leaves the server. It is display hygiene only: it never influences a
security decision, and the SQLite forensic log keeps the raw values.
"""
import re

REDACTED = "[REDACTED]"
MAX_STRING = 500

# Names whose values are secrets (dict keys, KEY=VALUE, "key": "value").
_SECRET_NAME = r"[A-Za-z0-9_\-]*(?:secret|passw(?:or)?d|pwd|token|api[_\-]?key|access[_\-]?key|private[_\-]?key|signing[_\-]?key|credential|authorization|auth[_\-]?(?:token|key))[A-Za-z0-9_\-]*"
_SECRET_NAME_RE = re.compile(rf"^{_SECRET_NAME}$", re.I)

_PATTERNS = (
    # Bearer tokens first, so "Authorization: Bearer <token>" can't be split by
    # the KEY: VALUE rule below into a redacted "Bearer" and a visible token.
    (re.compile(r"\bBearer\s+[A-Za-z0-9._\-+/=]{8,}", re.I), f"Bearer {REDACTED}"),
    # KEY=VALUE / KEY: VALUE, as in .env files and logs.
    (re.compile(rf"(\b{_SECRET_NAME}\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)", re.I), rf"\1{REDACTED}"),
    # "key": "value" inside JSON text.
    (re.compile(rf"(\"{_SECRET_NAME}\"\s*:\s*)\"[^\"]*\"", re.I), rf'\1"{REDACTED}"'),
    # Well-known credential formats.
    (re.compile(r"\bAKIA[0-9A-Z_]{8,}\b"), REDACTED),
    (re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_\-]{16,}\b"), REDACTED),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|github_pat|xox[abprs])_[A-Za-z0-9_\-]{10,}\b"), REDACTED),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), REDACTED),
)


def redact_text(text, limit=MAX_STRING):
    """Redact secret-shaped substrings; truncate to `limit` chars (None = keep all)."""
    if not isinstance(text, str):
        return text
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    if limit is not None and len(text) > limit:
        text = text[:limit] + "…"
    return text


def redact(value):
    """Recursively redact a JSON-like value (dicts, lists, strings)."""
    if isinstance(value, dict):
        return {
            k: (REDACTED if isinstance(k, str) and _SECRET_NAME_RE.match(k) and v not in (None, "")
                else redact(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    return redact_text(value)
