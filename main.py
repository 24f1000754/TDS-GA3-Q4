import copy
import json
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from agent import plan_incident
from database import canonical_json, create_run, digest, get_receipt, get_run, init_db, save_receipt, save_state
from tools import (
    args_digest, build_otlp, dispatch_record, new_span_id, new_trace_id,
    opaque_id, tool_schema_map, valid_traceparent, validate_arguments
)

app = FastAPI(title="GA5 Incident Agent", version="2.0")
init_db()

DESTRUCTIVE = {"rollback_deployment", "disable_feature"}


def public_state(state: dict) -> dict:
    result = copy.deepcopy(state)
    result.pop("request", None)
    result.pop("requestHash", None)
    result.pop("traceId", None)
    result.pop("serverSpanId", None)
    result.pop("agentSpanId", None)
    result.pop("modelSpanId", None)
    result.pop("logicalSpanIds", None)
    result.pop("joinSpanId", None)
    result.pop("approvalSpanId", None)
    result.pop("model", None)
    result.pop("publicMarker", None)
    for d in result.get("actionLog", []):
        d.pop("_clientSpanId", None)
    # OTLP remains safe/redacted and is part of the required response.
    return result


def make_initial_state(payload: dict, plan: dict) -> dict:
    run_id = payload["runId"]
    marker = payload["publicMarker"]
    incoming = valid_traceparent(payload.get("traceparent") or payload.get("tracing", {}).get("traceparent"))
    trace_id = incoming["trace_id"] if incoming else new_trace_id()
    parent = incoming["parent_span_id"] if incoming else None
    server_id = new_span_id()
    agent_id = new_span_id()
    model_id = new_span_id()
    state = {
        "runId": run_id, "status": "waiting", "diagnosis": plan["diagnosis"],
        "chosenEffect": (plan.get("effect") or {}).get("toolName"),
        "suppressed": [], "actionLog": [], "receiptLog": [], "approvalLog": [],
        "dispatches": [], "approvals": [], "pending": {},
        "traceId": trace_id, "serverSpanId": server_id, "agentSpanId": agent_id,
        "modelSpanId": model_id, "model": plan.get("model", "unknown"),
        "publicMarker": marker, "logicalSpanIds": {}, "joinSpanId": new_span_id(),
        "approvalSpanId": new_span_id(), "request": payload,
        "requestHash": digest(payload), "effectPlan": plan.get("effect"),
        "diagnosticsRemaining": [], "createdParentSpanId": parent,
    }
    catalog = tool_schema_map(payload.get("toolCatalog", []))
    diagnostics = []
    for call in plan.get("diagnostics", []):
        tool = catalog.get(call["toolName"])
        if not tool or not validate_arguments(tool, call["arguments"]):
            continue
        diagnostics.append(call)
    if not diagnostics:
        # Do not fabricate tool arguments: return failed safely if model cannot produce valid calls.
        state["status"] = "failed"
        state["suppressed"].append({"reason": "no_valid_diagnostic_plan"})
        state["dispatches"] = []
        state["approvals"] = []
        state["otlp"] = build_otlp(state)
        return state
    for call in diagnostics:
        action_id, call_id = opaque_id("action"), opaque_id("call")
        logical_key = f"{action_id}:{call_id}"
        logical_span_id = new_span_id()
        state["logicalSpanIds"][logical_key] = logical_span_id
        d = dispatch_record(call["toolName"], call["arguments"], call["evidence"], "diagnostic", trace_id,
                            run_id, action_id=action_id, call_id=call_id)
        state["actionLog"].append(d)
        state["dispatches"].append(copy.deepcopy(d))
        state["pending"][logical_key] = {"actionId": action_id, "callId": call_id, "attempt": 1, "phase": "diagnostic", "toolName": call["toolName"], "arguments": call["arguments"], "evidence": call["evidence"], "logicalKey": logical_key}
    state["otlp"] = build_otlp(state)
    return state


@app.get("/health")
async def health():
    return {"ok": True}


@app.post("/v2/incidents")
async def create_incident(payload: dict):
    if payload.get("profile") != "ga5-incident-agent/v2":
        raise HTTPException(status_code=400, detail="unsupported profile")
    run_id = payload.get("runId")
    if not isinstance(run_id, str) or len(run_id.strip()) < 8:
        raise HTTPException(status_code=422, detail="invalid runId")
    required = ["agentName", "publicMarker", "incident", "toolCatalog", "policy"]
    if any(k not in payload for k in required) or not isinstance(payload.get("incident"), dict):
        raise HTTPException(status_code=422, detail="invalid request")
    existing = get_run(run_id)
    request_hash = digest(payload)
    if existing:
        if existing["request_hash"] != request_hash:
            raise HTTPException(status_code=409, detail="runId content conflict")
        return JSONResponse(public_state(json.loads(existing["state_json"])))
    try:
        plan = await plan_incident(payload)
        state = make_initial_state(payload, plan)
    except ValueError:
        raise HTTPException(status_code=422, detail="invalid incident evidence")
    # Persist before responding. A simultaneous duplicate may conflict at SQLite; reread safely.
    try:
        create_run(run_id, request_hash, canonical_json(payload), canonical_json(state))
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
async def post_receipts(run_id: str, body: dict):
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
    state = json.loads(row["state_json"])
    if state["status"] in ("completed", "failed"):
        raise HTTPException(status_code=422, detail="run already terminal")
    outcomes = body.get("outcomes", [])
    approvals = body.get("approvals", [])
    if not isinstance(outcomes, list) or not isinstance(approvals, list):
        raise HTTPException(status_code=422, detail="invalid receipt")
    pending = state.get("pending", {})
    new_dispatches = []
    # Validate all incoming outcomes against pending calls before mutating state.
    for outcome in outcomes:
        if not isinstance(outcome, dict):
            raise HTTPException(status_code=422, detail="invalid outcome")
        key = f'{outcome.get("actionId")}:{outcome.get("callId")}'
        item = pending.get(key)
        if not item or item["attempt"] != outcome.get("attempt"):
            raise HTTPException(status_code=422, detail="outcome is not pending")
    for outcome in outcomes:
        key = f'{outcome["actionId"]}:{outcome["callId"]}'
        item = pending.pop(key)
        entry = {
            "receiptId": receipt_id, "actionId": outcome["actionId"], "callId": outcome["callId"],
            "attempt": outcome["attempt"], "status": outcome.get("status"),
            "resultClass": outcome.get("resultClass"), "nonce": outcome.get("nonce"),
        }
        state["receiptLog"].append(entry)
        if item["phase"] == "diagnostic" and outcome.get("status") == 503 and item["attempt"] == 1:
            # Exactly one retry; same logical action/call IDs, new CLIENT span ID.
            item["attempt"] = 2
            logical_key = item["logicalKey"]
            retry = dispatch_record(item["toolName"], item["arguments"], item["evidence"], "diagnostic",
                                    state["traceId"], run_id, action_id=item["actionId"], call_id=item["callId"], attempt=2)
            # Logical span remains the same; append retry dispatch to action log.
            state["actionLog"].append(retry)
            state["dispatches"].append(copy.deepcopy(retry))
            pending[logical_key] = item
            new_dispatches.append(copy.deepcopy(retry))
        elif item["phase"] == "diagnostic":
            if outcome.get("status") == 200 and outcome.get("resultClass") == "diagnosis_confirmed":
                item["succeeded"] = True
            else:
                item["failed"] = True
            state["diagnosticsRemaining"].append(item)
    state["pending"] = pending
    # Approvals only accepted for an exact outstanding approval request.
    for approval in approvals:
        if not isinstance(approval, dict):
            raise HTTPException(status_code=422, detail="invalid approval")
        req = next((a for a in state.get("approvals", []) if a.get("approvalId") == approval.get("approvalId")), None)
        if not req:
            raise HTTPException(status_code=422, detail="approval is not pending")
        if approval.get("decision") != "approved":
            state["status"] = "failed"
            state["suppressed"].append({"reason": "approval_denied"})
            state["approvals"] = []
            state["pending"] = {}
            state["dispatches"] = []
            continue
        state["approvalLog"].append({"receiptId": receipt_id, "approvalId": approval["approvalId"], "decision": "approved", "nonce": approval.get("nonce")})
        state["approvals"] = []
        effect = state.get("effectPlan")
        if not effect:
            state["status"] = "failed"
            state["suppressed"].append({"reason": "missing_justified_effect"})
            continue
        tool = tool_schema_map(state["request"].get("toolCatalog", [])).get(effect["toolName"])
        if not tool or not validate_arguments(tool, effect["arguments"]):
            state["status"] = "failed"
            state["suppressed"].append({"reason": "invalid_effect_arguments"})
            continue
        key = f'{req["actionId"]}:{req["actionId"]}'
        logical_span_id = new_span_id()
        state["logicalSpanIds"][key] = logical_span_id
        d = dispatch_record(effect["toolName"], effect["arguments"], state["diagnosis"]["evidence"], "effect",
                            state["traceId"], run_id, action_id=req["actionId"], call_id=req["actionId"],
                            approval={"approvalId": req["approvalId"], "nonce": approval.get("nonce")})
        state["actionLog"].append(d)
        state["dispatches"].append(copy.deepcopy(d))
        state["pending"][key] = {"actionId": d["actionId"], "callId": d["callId"], "attempt": 1, "phase": "effect", "toolName": d["toolName"], "arguments": d["arguments"], "evidence": d["evidence"], "logicalKey": key}
        new_dispatches.append(copy.deepcopy(d))
    # If all diagnostics have finished, no pending diagnostics remain, and no effect has run:
    diag_pending = any(v["phase"] == "diagnostic" for v in state.get("pending", {}).values())
    if not diag_pending and state.get("diagnosticsRemaining") and state["status"] == "waiting" and not state.get("approvals") and not any(x.get("phase") == "effect" for x in state["actionLog"]):
        all_ok = all(x.get("succeeded") for x in state["diagnosticsRemaining"])
        if not all_ok:
            state["status"] = "failed"
            state["suppressed"].append({"reason": "diagnostic_failed"})
            state["chosenEffect"] = None
            state["dispatches"] = []
        else:
            effect = state.get("effectPlan")
            if not effect:
                state["status"] = "failed"
                state["suppressed"].append({"reason": "no_justified_effect"})
                state["dispatches"] = []
            else:
                effect_name = effect["toolName"]
                policy = state["request"].get("policy", {})
                approval_tools = set(policy.get("approvalRequiredFor", [])) | DESTRUCTIVE
                tool = tool_schema_map(state["request"].get("toolCatalog", [])).get(effect_name)
                if not tool or not validate_arguments(tool, effect["arguments"]):
                    state["status"] = "failed"
                    state["suppressed"].append({"reason": "invalid_effect_arguments"})
                    state["dispatches"] = []
                elif effect_name in approval_tools:
                    approval_req = {
                        "approvalId": opaque_id("approval"), "actionId": opaque_id("action"),
                        "toolName": effect_name, "argumentsDigest": args_digest(effect["arguments"])
                    }
                    state["approvals"] = [approval_req]
                    state["dispatches"] = []
                else:
                    key = f'{opaque_id("action")}:{opaque_id("call")}'
                    action_id, call_id = key.split(":")
                    state["logicalSpanIds"][key] = new_span_id()
                    d = dispatch_record(effect_name, effect["arguments"], state["diagnosis"]["evidence"], "effect",
                                        state["traceId"], run_id, action_id=action_id, call_id=call_id)
                    state["actionLog"].append(d)
                    state["dispatches"].append(copy.deepcopy(d))
                    state["pending"][key] = {"actionId": action_id, "callId": call_id, "attempt": 1, "phase": "effect", "toolName": effect_name, "arguments": effect["arguments"], "evidence": state["diagnosis"]["evidence"], "logicalKey": key}
                    new_dispatches.append(copy.deepcopy(d))
    # A successful effect receipt completes the run; effect failure fails it.
    for outcome in outcomes:
        key = f'{outcome.get("actionId")}:{outcome.get("callId")}'
        # pending was popped above, find its phase from the action log.
        dispatch = next((d for d in reversed(state["actionLog"]) if d["actionId"] == outcome.get("actionId") and d["callId"] == outcome.get("callId") and d["attempt"] == outcome.get("attempt")), None)
        if dispatch and dispatch.get("phase") == "effect":
            state["status"] = "completed" if outcome.get("status") == 200 else "failed"
            if outcome.get("status") != 200:
                state["suppressed"].append({"reason": "effect_failed"})
            state["dispatches"] = []
    # If no pending work but waiting and all diagnostic success led to approval, keep waiting.
    state["otlp"] = build_otlp(state)
    response_state = public_state(state)
    save_state(run_id, state)
    response_json = canonical_json(response_state)
    try:
        save_receipt(run_id, receipt_id, receipt_hash, response_json)
    except Exception:
        existing = get_receipt(run_id, receipt_id)
        if existing and existing["receipt_hash"] == receipt_hash:
            return JSONResponse(json.loads(existing["response_json"]))
        raise HTTPException(status_code=409, detail="receipt conflict")
    return JSONResponse(response_state)
