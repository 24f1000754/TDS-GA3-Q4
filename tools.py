import hashlib
import json
import secrets
import uuid
from typing import Any

from database import canonical_json


def opaque_id(prefix: str = "id") -> str:
    return f"{prefix}_{secrets.token_hex(12)}"


def new_trace_id() -> str:
    while True:
        value = secrets.token_hex(16)
        if int(value, 16) != 0:
            return value


def new_span_id() -> str:
    while True:
        value = secrets.token_hex(8)
        if int(value, 16) != 0:
            return value


def valid_traceparent(value: str | None):
    if not isinstance(value, str):
        return None
    parts = value.split("-")
    if len(parts) != 4 or parts[0] != "00":
        return None
    if not re_hex(parts[1], 32) or int(parts[1], 16) == 0:
        return None
    if not re_hex(parts[2], 16) or int(parts[2], 16) == 0:
        return None
    if not re_hex(parts[3], 2):
        return None
    return {"trace_id": parts[1], "parent_span_id": parts[2], "flags": parts[3]}


def re_hex(s, n):
    import re
    return isinstance(s, str) and len(s) == n and bool(re.fullmatch(r"[0-9a-f]+", s))


def args_digest(args: dict) -> str:
    return hashlib.sha256(canonical_json(args).encode()).hexdigest()


def tool_schema_map(catalog):
    return {x.get("name"): x for x in catalog if isinstance(x, dict) and isinstance(x.get("name"), str)}


def validate_arguments(tool: dict, args: dict) -> bool:
    schema = tool.get("inputSchema", {})
    if not isinstance(schema, dict):
        return False
    required = schema.get("required", [])
    props = schema.get("properties", {})
    if isinstance(required, list) and any(k not in args for k in required):
        return False
    if schema.get("additionalProperties") is False and isinstance(props, dict):
        if any(k not in props for k in args):
            return False
    if isinstance(props, dict):
        for key, spec in props.items():
            if key not in args or not isinstance(spec, dict):
                continue
            typ = spec.get("type")
            val = args[key]
            if typ == "string" and not isinstance(val, str):
                return False
            if typ == "integer" and (not isinstance(val, int) or isinstance(val, bool)):
                return False
            if typ == "number" and (not isinstance(val, (int, float)) or isinstance(val, bool)):
                return False
            if typ == "boolean" and not isinstance(val, bool):
                return False
            if typ == "array" and not isinstance(val, list):
                return False
            if typ == "object" and not isinstance(val, dict):
                return False
            if "enum" in spec and val not in spec["enum"]:
                return False
    return True


def dispatch_record(tool_name, arguments, evidence, phase, trace_id, run_id, action_id=None, call_id=None, attempt=1, approval=None):
    action_id = action_id or opaque_id("action")
    call_id = call_id or opaque_id("call")
    client_span_id = new_span_id()
    record = {
        "actionId": action_id,
        "callId": call_id,
        "phase": phase,
        "toolName": tool_name,
        "arguments": arguments,
        "evidence": evidence,
        "attempt": attempt,
        "traceparent": f"00-{trace_id}-{client_span_id}-01",
        "_clientSpanId": client_span_id,
    }
    if approval:
        record["approvalId"] = approval["approvalId"]
        record["approvalNonce"] = approval["nonce"]
    return record


def otlp_span(name, kind, trace_id, span_id, parent_span_id, attrs, status_code=0, status_message=None, links=None):
    span = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": kind,
        "startTimeUnixNano": str(1),
        "endTimeUnixNano": str(2),
        "attributes": [{"key": k, "value": _otlp_value(v)} for k, v in attrs.items() if v is not None],
        "status": {"code": status_code},
    }
    if parent_span_id:
        span["parentSpanId"] = parent_span_id
    if status_message:
        span["status"]["message"] = status_message
    if links:
        span["links"] = links
    return span


def _otlp_value(v):
    if isinstance(v, bool):
        return {"boolValue": v}
    if isinstance(v, int):
        return {"intValue": v}
    if isinstance(v, float):
        return {"doubleValue": v}
    return {"stringValue": str(v)}


def build_otlp(state):
    trace_id = state["traceId"]
    server_id = state["serverSpanId"]
    agent_id = state["agentSpanId"]
    common = {"ga5.run.id": state["runId"], "ga5.public.marker": state["publicMarker"]}
    spans = []
    spans.append(otlp_span("POST /v2/incidents", 2, trace_id, server_id, None, common))
    spans.append(otlp_span(
        "invoke_agent incident-response", 1, trace_id, agent_id, server_id, common
    ))
    spans.append(otlp_span(
        "chat incident-plan", 3, trace_id, state["modelSpanId"], agent_id,
        {**common, "gen_ai.operation.name": "chat", "gen_ai.request.model": state.get("model", "unknown")}
    ))
    tool_span_ids = []
    for dispatch in state.get("actionLog", []):
        logical_key = f'{dispatch["actionId"]}:{dispatch["callId"]}'
        logical_span_id = state["logicalSpanIds"].get(logical_key)
        if not logical_span_id:
            continue
        spans.append(otlp_span(
            f'execute_tool {dispatch["toolName"]}', 1, trace_id, logical_span_id, agent_id,
            {**common, "ga5.action.id": dispatch["actionId"], "gen_ai.tool.name": dispatch["toolName"],
             "gen_ai.tool.call.id": dispatch["callId"], "gen_ai.operation.name": "execute_tool"}
        ))
        client_attrs = {
            **common,
            "ga5.action.id": dispatch["actionId"],
            "ga5.attempt": dispatch["attempt"],
            "http.request.method": "POST",
            "http.request.resend_count": dispatch["attempt"] - 1,
        }
        # Receipt values are correlated from stored receipt logs, never from untrusted transcript.
        receipt = next((r for r in state.get("receiptLog", []) if r.get("actionId") == dispatch["actionId"] and r.get("callId") == dispatch["callId"] and r.get("attempt") == dispatch["attempt"]), None)
        if receipt:
            client_attrs["ga5.receipt.id"] = receipt.get("receiptId")
            client_attrs["ga5.receipt.nonce"] = receipt.get("nonce")
            status = receipt.get("status")
            if status == 503:
                client_attrs["http.response.status_code"] = 503
                client_attrs["error.type"] = "503"
                client_status = 2
            elif status == 0:
                client_attrs["error.type"] = "timeout"
                client_status = 2
            elif isinstance(status, int):
                client_attrs["http.response.status_code"] = status
                client_status = 0
            else:
                client_status = 0
        else:
            client_status = 0
        spans.append(otlp_span(
            f'POST tool/{dispatch["toolName"]}', 3, trace_id, dispatch["_clientSpanId"],
            logical_span_id, client_attrs, status_code=client_status
        ))
        tool_span_ids.append(logical_span_id)
    diag = [d for d in state.get("actionLog", []) if d.get("phase") == "diagnostic"]
    if len({d["actionId"] for d in diag}) > 1:
        links = [{"traceId": trace_id, "spanId": state["logicalSpanIds"][f'{d["actionId"]}:{d["callId"]}']} for d in diag if f'{d["actionId"]}:{d["callId"]}' in state["logicalSpanIds"]]
        spans.append(otlp_span("incident.join", 1, trace_id, state["joinSpanId"], agent_id, common, links=links))
    if state.get("approvalLog"):
        approval = state["approvalLog"][-1]
        spans.append(otlp_span(
            "approval_gate", 1, trace_id, state["approvalSpanId"], agent_id,
            {**common, "ga5.approval.id": approval.get("approvalId"), "ga5.approval.receipt.nonce": approval.get("nonce")}
        ))
    # Internal implementation keys are not exported.
    return {"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}
