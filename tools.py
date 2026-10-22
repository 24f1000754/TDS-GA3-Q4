import hashlib
import re
import secrets

from database import canonical_json

STEP = 1_000_000  # 1 ms in ns


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


def _hex(s, n):
    return isinstance(s, str) and len(s) == n and bool(re.fullmatch(r"[0-9a-f]+", s))


def valid_traceparent(value):
    if not isinstance(value, str):
        return None
    parts = value.strip().split("-")
    if len(parts) != 4 or parts[0] != "00":
        return None
    if not _hex(parts[1], 32) or int(parts[1], 16) == 0:
        return None
    if not _hex(parts[2], 16) or int(parts[2], 16) == 0:
        return None
    if not _hex(parts[3], 2):
        return None
    return {"trace_id": parts[1], "parent_span_id": parts[2], "flags": parts[3]}


def args_digest(args: dict) -> str:
    return hashlib.sha256(canonical_json(args).encode()).hexdigest()


def tool_schema_map(catalog):
    return {x.get("name"): x for x in catalog if isinstance(x, dict) and isinstance(x.get("name"), str)}


def validate_arguments(tool: dict, args: dict) -> bool:
    schema = tool.get("inputSchema", {})
    if not isinstance(schema, dict) or not isinstance(args, dict):
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


def dispatch_record(tool_name, arguments, evidence, phase, trace_id, action_id, call_id,
                    attempt=1, approval=None, tracestate=None):
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
    }
    if tracestate:
        record["tracestate"] = tracestate
    if approval:
        record["approvalId"] = approval["approvalId"]
        record["approvalNonce"] = approval["nonce"]
    record["_clientSpanId"] = client_span_id  # internal, stripped from every response
    return record


def _otlp_value(v):
    if isinstance(v, bool):
        return {"boolValue": v}
    if isinstance(v, int):
        return {"intValue": v}
    if isinstance(v, float):
        return {"doubleValue": v}
    return {"stringValue": str(v)}


def otlp_span(name, kind, trace_id, span_id, parent_span_id, attrs, start, end,
              status_code=0, links=None):
    span = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": kind,
        "startTimeUnixNano": str(start),
        "endTimeUnixNano": str(end),
        "attributes": [{"key": k, "value": _otlp_value(v)} for k, v in attrs.items() if v is not None],
        "status": {"code": status_code},
    }
    if parent_span_id:
        span["parentSpanId"] = parent_span_id
    if links:
        span["links"] = links
    return span


def build_otlp(state):
    """Built only from stored dispatches + receipts. Never calls a model."""
    trace_id = state["traceId"]
    server_id, agent_id = state["serverSpanId"], state["agentSpanId"]
    t0 = int(state["t0"])
    common = {"ga5.run.id": state["runId"], "ga5.public.marker": state["publicMarker"]}
    body, cursor = [], t0 + STEP

    body.append(otlp_span(
        "chat incident-plan", 3, trace_id, state["modelSpanId"], agent_id,
        {**common, "gen_ai.operation.name": "chat", "gen_ai.request.model": state.get("model") or "unknown"},
        cursor, cursor + STEP // 2))
    cursor += STEP

    logical, order = {}, []
    for d in state["actionLog"]:
        key = f'{d["actionId"]}:{d["callId"]}'
        if key not in logical:
            logical[key] = []
            order.append(key)
        logical[key].append(d)

    diag_span_ids = []
    for key in order:
        ds = logical[key]
        first = ds[0]
        lid = state["logicalSpanIds"][key]
        lstart = cursor
        clients = []
        for d in ds:
            cs = cursor + STEP // 10
            ce = cs + STEP // 2
            attrs = {**common, "ga5.action.id": d["actionId"], "ga5.attempt": d["attempt"],
                     "http.request.method": "POST", "http.request.resend_count": d["attempt"] - 1}
            code = 0
            r = next((r for r in state["receiptLog"] if r.get("actionId") == d["actionId"]
                      and r.get("callId") == d["callId"] and r.get("attempt") == d["attempt"]), None)
            if r:
                attrs["ga5.receipt.id"] = r["receiptId"]
                attrs["ga5.receipt.nonce"] = r["nonce"]
                st = r.get("status")
                if st == 0:
                    attrs["error.type"] = "timeout"
                    code = 2
                elif isinstance(st, int):
                    attrs["http.response.status_code"] = st
                    if st >= 400:
                        attrs["error.type"] = str(st)
                        code = 2
            clients.append(otlp_span(f'POST tool/{d["toolName"]}', 3, trace_id, d["_clientSpanId"], lid,
                                     attrs, cs, ce, status_code=code))
            cursor += STEP
        lspan = otlp_span(
            f'execute_tool {first["toolName"]}', 1, trace_id, lid, agent_id,
            {**common, "ga5.action.id": first["actionId"], "gen_ai.tool.name": first["toolName"],
             "gen_ai.tool.call.id": first["callId"], "gen_ai.operation.name": "execute_tool"},
            lstart, cursor)
        body.append(lspan)
        body.extend(clients)
        if first["phase"] == "diagnostic":
            diag_span_ids.append(lid)

    if len(diag_span_ids) > 1:
        body.append(otlp_span(
            "incident.join", 1, trace_id, state["joinSpanId"], agent_id, common, cursor, cursor + STEP // 2,
            links=[{"traceId": trace_id, "spanId": s} for s in diag_span_ids]))
        cursor += STEP

    approvals = [a for a in state["receiptLog"] if "approvalId" in a]
    if approvals:
        a = approvals[-1]
        body.append(otlp_span(
            "approval_gate", 1, trace_id, state["approvalSpanId"], agent_id,
            {**common, "ga5.approval.id": a["approvalId"], "ga5.approval.receipt.nonce": a["nonce"],
             "ga5.approval.decision": a["decision"]},
            cursor, cursor + STEP // 2))
        cursor += STEP

    end = cursor + STEP
    spans = [
        otlp_span("POST /v2/incidents", 2, trace_id, server_id, state.get("parentSpanId"), common, t0, end),
        otlp_span("invoke_agent incident-response", 1, trace_id, agent_id, server_id, common,
                  t0 + STEP // 10, end - STEP // 10),
    ] + body
    if state.get("tracestate"):
        for sp in spans:
            sp["traceState"] = state["tracestate"]
    return {"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}