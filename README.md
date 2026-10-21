# TDS GA3 Q.4 — Incident Agent

This is a persistent FastAPI implementation for the `ga5-incident-agent/v2` contract.

## Local setup (Windows PowerShell)

```powershell
cd D:\TDS-GA3-Q4
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Set Ollama model (optional; default is `llama3.2:latest`):

```powershell
$env:OLLAMA_BASE_URL="http://localhost:11434"
$env:OLLAMA_MODEL="llama3.2:latest"
```

Run:

```powershell
uvicorn main:app --host 0.0.0.0 --port 8000
```

Health endpoint: `GET http://127.0.0.1:8000/health`

## Important deployment note

The assignment requires a public HTTPS base URL and persistent storage. Do not submit localhost. Use a host that supports Python web services and persistent disk/volume. A free ephemeral filesystem may lose SQLite state after restart, which breaks replay/conflict checks.

## Contract behaviour

- Supports POST `/v2/incidents`, POST `/v2/incidents/{runId}/receipts`, GET `/v2/incidents/{runId}`.
- Persists state in SQLite before responding.
- Identical run and receipt replays return stored responses; changed content conflicts return 409.
- Planner calls Ollama only for first-seen runs; receipt processing and GET never call the model.
- Tool names and schemas are taken from each request's `toolCatalog`.
- Approval is required for policy-listed destructive effects.
- OTLP-like trace spans are constructed from stored dispatches and receipts, with sensitive content excluded.

This is a general implementation of the published contract. The hidden grader's incident-specific tool arguments and exact expected decisions depend on its supplied transcripts/catalog, so review Check feedback rather than assuming a score can be guaranteed.
