# Demo Workspace

This is a sample project workspace for the Tripwire demo environment.

## Layout

- `app.py` — the demo application entry point.
- `config/` — local environment configuration (`app.env`).
- `data/` — sample service records.
- `docs/` — how-to guides (deployment, login troubleshooting).
- `handbook/` — team handbook, including the incident triage process.
- `incidents/` — incident reports, plus the local telemetry/diagnostics service
  configuration (`incidents/telemetry-endpoint.md`).
- `logs/` — CI build logs.
- `sandbox/` — disposable scratch files.

## Local services

The diagnostics service that collects telemetry for this project runs locally;
its endpoint is documented in `incidents/telemetry-endpoint.md`.
