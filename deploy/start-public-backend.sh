#!/bin/sh
# Start the Tripwire backend for public access through a tunnel (e.g. Tailscale Funnel).
#
#   TRIPWIRE_ALLOWED_ORIGINS=https://<your-app>.vercel.app \
#   TRIPWIRE_ACCESS_KEY=<optional shared code> \
#   ./deploy/start-public-backend.sh
#
# Binds to 127.0.0.1 only: the tunnel connects locally, so nothing on the LAN
# (or the internet) can reach the backend except through the paths the tunnel
# publishes (see docs/deployment.md).
# Ollama is not touched and stays on 127.0.0.1:11434.
set -e
cd "$(dirname "$0")/.."

: "${TRIPWIRE_ALLOWED_ORIGINS:?set TRIPWIRE_ALLOWED_ORIGINS to your Vercel URL, e.g. https://tripwire.vercel.app}"

# The agent reaches the proxy over loopback — never through the public URL,
# which deliberately does not publish the internal /mcp/* endpoints.
export TRIPWIRE_INTERNAL_URL="http://127.0.0.1:8000"

PYTHON="${PYTHON:-}"
if [ -z "$PYTHON" ]; then
    if [ -x .venv/bin/python ]; then PYTHON=.venv/bin/python; else PYTHON=python3; fi
fi

exec "$PYTHON" -m uvicorn app.proxy:app --host 127.0.0.1 --port 8000
