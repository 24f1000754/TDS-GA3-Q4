# TDS GA3 Q4 - Incident Agent (ga5-incident-agent/v2)

Files: main.py (HTTP), engine.py (state machine), agent.py (Gemini planner), tools.py (ids, trace, OTLP), database.py (SQLite).

Env vars: GEMINI_API_KEY (required), GEMINI_MODEL (optional, default gemini-2.5-flash),
INCIDENT_DB_PATH (optional).

Run: uvicorn main:app --host 0.0.0.0 --port 8000
Render start command: uvicorn main:app --host 0.0.0.0 --port $PORT
