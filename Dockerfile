# Tripwire backend + a local Ollama running qwen3:4b-instruct-2507-q4_K_M, in one container.
#
# The FastAPI proxy, the stdio MCP server and the Ollama model server all run
# here, so the hosted demo needs nothing on anyone's laptop. The model is
# pulled at build time and baked into the image, so a restart does not
# re-download it. CPU-only: expect each agent step to take tens of seconds.
FROM python:3.13-slim

ARG OLLAMA_VERSION=0.34.4
ARG TRIPWIRE_MODEL=qwen3:4b-instruct-2507-q4_K_M

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates zstd \
    && curl -fsSL https://ollama.com/install.sh | OLLAMA_VERSION=${OLLAMA_VERSION} sh \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV OLLAMA_MODELS=/models \
    OLLAMA_HOST=http://127.0.0.1:11434 \
    TRIPWIRE_MODEL=${TRIPWIRE_MODEL}

# Pull the model into the image (needs a temporary server during the build).
RUN set -e; \
    ollama serve > /tmp/ollama-build.log 2>&1 & pid=$!; \
    for i in $(seq 1 60); do curl -sf http://127.0.0.1:11434/api/version > /dev/null && break; sleep 1; done; \
    ollama pull ${TRIPWIRE_MODEL}; \
    kill $pid

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY mcp_lab ./mcp_lab
COPY static ./static
COPY start.sh .
RUN chmod +x start.sh

CMD ["./start.sh"]
