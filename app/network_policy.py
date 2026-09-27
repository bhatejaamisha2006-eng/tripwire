"""
Network / destination policy — Scenario 5.

A SEPARATE concern from app/policy.py. policy.py answers "is this *action*
allowed?" (sensitive/destructive tools, restricted commands). This module
answers a different question: "is this *destination* allowed?" — the
SSRF / unauthorized-network-access class of agent abuse.

It inspects only the destination (scheme/host/port) of an outbound request,
never the payload contents. The proxy calls check_network_policy() for
send_http_request before the backend is allowed to contact anything.
"""
import urllib.parse

# Explicit allowlist of approved outbound destinations, as host:port. Only
# local/synthetic destinations are used in this demo. Everything else — other
# ports, other hosts, cloud metadata IPs, internal ranges — is blocked.
ALLOWED_DESTINATIONS = {
    "127.0.0.1:9000",   # approved local mock telemetry service
    "localhost:9000",
}

SEVERITY = "HIGH"


def _destination(url: str) -> str:
    """Return 'host:port' for a URL, defaulting the port by scheme."""
    parsed = urllib.parse.urlparse((url or "").strip())
    host = parsed.hostname or ""
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return f"{host}:{port}"


def check_network_policy(url: str) -> str:
    """ALLOW only if the destination host:port is on the allowlist."""
    parsed = urllib.parse.urlparse((url or "").strip())
    if not parsed.scheme or not parsed.hostname:
        return "BLOCK"
    return "ALLOW" if _destination(url) in ALLOWED_DESTINATIONS else "BLOCK"


def violation_reason(url: str) -> str:
    return (f"send_http_request blocked by network policy: destination "
            f"'{_destination(url)}' is not on the approved allowlist "
            f"(unauthorized destination)")
