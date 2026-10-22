import sys

import httpx

ARG = sys.argv[1] if len(sys.argv) > 1 else "8001"
BASE = ARG.rstrip("/") if ARG.startswith("http") else f"http://127.0.0.1:{ARG}"

payload = {
    "profile": "ga5-incident-agent/v2",
    "runId": "test-run-" + __import__("uuid").uuid4().hex[:8],
    "agentName": "incident-response",
    "publicMarker": "mk",
    "sensitive": {"accessToken": "SECRET"},
    "incident": {
        "incidentId": "i1",
        "title": "High latency",
        "service": "api",
        "severity": "SEV-1",
        "transcript": (
            "[ev_001] api p99 latency rose after deploy v42\n"
            "[ev_002] error rate 5xx up on api\n"
            "[ev_003] unrelated billing note"
        ),
        "allowedRootCauses": ["bad_deploy", "capacity_exhausted"],
    },
    "toolCatalog": [
        {
            "name": "query_metrics",
            "description": "metrics",
            "inputSchema": {"type": "object", "required": ["service"], "properties": {"service": {"type": "string"}}},
        },
        {
            "name": "rollback_deployment",
            "description": "rollback",
            "inputSchema": {"type": "object", "required": ["service"], "properties": {"service": {"type": "string"}}},
        },
    ],
    "policy": {
        "maximumDiagnostics": 3,
        "effectTools": ["rollback_deployment"],
        "approvalRequiredFor": ["rollback_deployment"],
        "doNotExport": [],
    },
}

r = httpx.post(f"{BASE}/v2/incidents", json=payload, timeout=30)
print("HTTP status:", r.status_code)
if r.status_code != 200:
    print(r.text[:500])
    sys.exit(1)

data = r.json()
print("status    :", data["status"])
print("diagnosis :", data["diagnosis"])
print("dispatches:", [(d["toolName"], d["arguments"]) for d in data["dispatches"]])
print("suppressed:", data["suppressed"])
print("SECRET leaked?:", "SECRET" in r.text)