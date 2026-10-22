import json

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from agent import plan_incident
from database import canonical_json, create_run, digest, get_receipt, get_run, init_db, save_receipt, save_state
from engine import EngineError, apply_receipt, create_state, public_state

app = FastAPI(title="GA5 Incident Agent", version="2.0")
init_db()


@app.exception_handler(RequestValidationError)
async def _validation(_req, _exc):  # never echo the input body
    return JSONResponse({"detail": "invalid request"}, status_code=422)


async def read_json(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="invalid JSON")
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="body must be an object")
    return body


@app.get("/health")
async def health():
    return {"ok": True}


@app.post("/v2/incidents")
async def create_incident(request: Request):
    payload = await read_json(request)
    if payload.get("profile") != "ga5-incident-agent/v2":
        raise HTTPException(status_code=400, detail="unsupported profile")
    run_id = payload.get("runId")
    inc = payload.get("incident")
    if (not isinstance(run_id, str) or len(run_id.strip()) < 8 or not isinstance(payload.get("publicMarker"), str)
            or not isinstance(inc, dict) or not isinstance(inc.get("transcript"), str)
            or not isinstance(payload.get("toolCatalog"), list) or not isinstance(payload.get("policy"), dict)):
        raise HTTPException(status_code=422, detail="invalid request")
    request_hash = digest(payload)
    existing = get_run(run_id)
    if existing:
        if existing["request_hash"] != request_hash:
            raise HTTPException(status_code=409, detail="runId content conflict")
        return JSONResponse(public_state(json.loads(existing["state_json"])))
    try:
        plan = await plan_incident(payload)
        state = create_state(payload, plan, request.headers.get("traceparent"), request.headers.get("tracestate"))
    except ValueError:
        raise HTTPException(status_code=422, detail="invalid incident evidence")
    try:
        # request_json holds only a redacted summary; the sensitive object is never persisted.
        create_run(run_id, request_hash, "{}", canonical_json(state))
    except Exception:
        existing = get_run(run_id)
        if existing and existing["request_hash"] == request_hash:
            return JSONResponse(public_state(json.loads(existing["state_json"])))
        raise HTTPException(status_code=409, detail="runId conflict")
    return JSONResponse(public_state(state))


@app.get("/v2/incidents/{run_id}")
async def get_incident(run_id: str):
    row = get_run(run_id)
    if not row:
        raise HTTPException(status_code=404, detail="run not found")
    return JSONResponse(public_state(json.loads(row["state_json"])))


@app.post("/v2/incidents/{run_id}/receipts")
async def post_receipts(run_id: str, request: Request):
    body = await read_json(request)
    row = get_run(run_id)
    if not row:
        raise HTTPException(status_code=404, detail="run not found")
    receipt_id = body.get("receiptId")
    if not isinstance(receipt_id, str) or len(receipt_id.strip()) < 8:
        raise HTTPException(status_code=422, detail="invalid receiptId")
    receipt_hash = digest(body)
    old = get_receipt(run_id, receipt_id)
    if old:
        if old["receipt_hash"] != receipt_hash:
            raise HTTPException(status_code=409, detail="receiptId content conflict")
        return JSONResponse(json.loads(old["response_json"]))
    try:
        state = apply_receipt(json.loads(row["state_json"]), receipt_id, body)
    except EngineError as e:
        raise HTTPException(status_code=e.code, detail=e.msg)
    response = public_state(state)
    save_state(run_id, state)
    try:
        save_receipt(run_id, receipt_id, receipt_hash, canonical_json(response))
    except Exception:
        existing = get_receipt(run_id, receipt_id)
        if existing and existing["receipt_hash"] == receipt_hash:
            return JSONResponse(json.loads(existing["response_json"]))
        raise HTTPException(status_code=409, detail="receipt conflict")
    return JSONResponse(response)
