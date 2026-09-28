#!/bin/sh
# Container entrypoint: start Ollama, preload the model, then serve Tripwire.
set -e

PORT="${PORT:-8000}"
MODEL="${TRIPWIRE_MODEL:-qwen3:4b-instruct-2507-q4_K_M}"
NUM_CTX="${TRIPWIRE_NUM_CTX:-16384}"

# One model, kept resident, one request at a time (the agent is sequential).
# q8 KV cache halves the context's memory at a negligible quality cost.
export OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:--1}"
export OLLAMA_NUM_PARALLEL="${OLLAMA_NUM_PARALLEL:-1}"
export OLLAMA_FLASH_ATTENTION="${OLLAMA_FLASH_ATTENTION:-1}"
export OLLAMA_KV_CACHE_TYPE="${OLLAMA_KV_CACHE_TYPE:-q8_0}"

ollama serve &

i=0
until curl -sf http://127.0.0.1:11434/api/version > /dev/null; do
    i=$((i + 1))
    if [ "$i" -ge 60 ]; then echo "ollama did not start" >&2; exit 1; fi
    sleep 1
done

# Load the model into RAM in the background, with the same context size the
# agent requests (a different num_ctx would force a reload on the first run).
curl -sf http://127.0.0.1:11434/api/generate \
    -d "{\"model\": \"$MODEL\", \"keep_alive\": -1, \"options\": {\"num_ctx\": $NUM_CTX}}" \
    > /dev/null &

# The agent reaches the proxy over loopback, not the public URL.
export TRIPWIRE_INTERNAL_URL="http://127.0.0.1:$PORT"

exec uvicorn app.proxy:app --host 0.0.0.0 --port "$PORT" \
    --proxy-headers --forwarded-allow-ips='*'
