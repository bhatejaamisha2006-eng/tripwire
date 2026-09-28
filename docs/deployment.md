# Deployment

Tripwire's demo deployment splits the dashboard from the security engine:

```
Browser ──► Vercel (Next.js dashboard)
               │  HTTPS: /healthz, /run, /run/status, /dashboard/stream
               ▼
        Tailscale Funnel (public *.ts.net URL)
               │
               ▼
        Mac / host ─ Tripwire backend on 127.0.0.1:8000
                       ├─ MCP tool server (stdio, local subprocess)
                       └─ Ollama on 127.0.0.1:11434 (never published)
```

The frontend is a static Next.js build hosted on Vercel. The backend — proxy,
security layers, MCP tool server and the local model — runs on a machine you
control and is reached through a tunnel. It is not permanently hosted: the host
machine must be on and running the backend for the public dashboard to work.

## 1. Backend

Bind to loopback only and allow the dashboard's origin:

```bash
TRIPWIRE_ALLOWED_ORIGINS="https://<your-app>.vercel.app,http://localhost:3000" \
./deploy/start-public-backend.sh
```

The script sets `TRIPWIRE_INTERNAL_URL=http://127.0.0.1:8000`, so the agent
reaches the proxy over loopback and never through the public URL. Add
`TRIPWIRE_ACCESS_KEY=<code>` to require an access code for starting runs.

## 2. Tunnel (Tailscale Funnel)

Funnel gives the host a free public HTTPS name (`https://<machine>.<tailnet>.ts.net`).
Publish only the four endpoints the dashboard uses — Funnel answers every
other path, including `/mcp/*`, with 404 before it reaches the backend:

```bash
tailscale funnel --bg --set-path /healthz          http://127.0.0.1:8000/healthz
tailscale funnel --bg --set-path /run              http://127.0.0.1:8000/run
tailscale funnel --bg --set-path /dashboard/stream http://127.0.0.1:8000/dashboard/stream
tailscale funnel status
```

The first `tailscale funnel` command on a new tailnet opens an approval flow
that enables HTTPS certificates and the Funnel permission. `/run` also serves
`/run/status`. To take everything offline: `tailscale funnel reset`.

Never publish port 11434 (Ollama) or the `/mcp/*` endpoints.

## 3. Frontend (Vercel)

- Root directory: `frontend`
- Framework preset: Next.js (no output-directory override)
- Environment variable: `NEXT_PUBLIC_TRIPWIRE_API=https://<machine>.<tailnet>.ts.net`
  (no trailing slash; it is compiled into the build, so redeploy after changing it)

## 4. Verify

From a device outside your tailnet:

| Request | Expected |
|---|---|
| `GET /healthz` | `200 {"status":"ok",…}` |
| `GET /dashboard/stream` | `200 text/event-stream` |
| `GET /mcp/events`, `POST /mcp/call` | `404` |
| port `11434` | unreachable |

## Container image (optional, unverified)

`Dockerfile` and `start.sh` package the backend, the MCP server and Ollama with
the model baked in, for hosts that can run an 8 GB container. This path is
provided for convenience and is not part of the deployment described above; it
has not been validated end to end in this repository.
