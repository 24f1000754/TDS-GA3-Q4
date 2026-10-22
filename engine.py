"""Receipt-driven state machine. Pure Python: no model calls, no HTTP, no FastAPI."""
import copy
import time

from tools import (args_digest, build_otlp, dispatch_record, new_span_id, new_trace_id,
                   opaque_id, tool_schema_map, valid_traceparent, validate_arguments)

TERMINAL = ("completed", "failed")
DESTRUCTIVE = {"rollback_deployment", "disable_feature"}


class EngineError(Exception):
    def __init__(self, code, msg):
        self.code, self.msg = code, msg


def _issue(state, item, attempt=1):
    d = dispatch_record(item["toolName"], item["arguments"], item["evidence"], item["phase"],
                        state["traceId"], item["actionId"], item["callId"], attempt=attempt,
                        approval=item.get("approval"), tracestate=state.get("tracestate"))
    state["actionLog"].append(d)
    return d


def _new_item(state, phase, tool, args, evidence, action_id=None, call_id=None, approval=None):
    action_id = action_id or opaque_id("action")
    call_id = call_id or opaque_id("call")
    key = f"{action_id}:{call_id}"
    state["logicalSpanIds"][key] = new_span_id()
    item = {"actionId": action_id, "callId": call_id, "phase": phase, "toolName": tool,
            "arguments": args, "evidence": evidence, "attempt": 1, "key": key}
    if approval:
        item["approval"] = approval
    state["pending"][key] = item
    return item


def _fail(state, reason, tool=None):
    state["status"] = "failed"
    state["chosenEffect"] = None
    state["pending"] = {}
    state["approvals"] = []
    state["suppressed"].append({"toolName": tool, "reason": reason})


def create_state(payload, plan, traceparent=None, tracestate=None):
    inc = valid_traceparent(traceparent)
    state = {
        "runId": payload["runId"], "publicMarker": payload["publicMarker"], "status": "waiting",
        "diagnosis": plan["diagnosis"], "chosenEffect": None,
        "suppressed": [], "actionLog": [], "receiptLog": [], "dispatches": [], "approvals": [],
        "pending": {}, "diagResults": {}, "effectIssued": False, "effectPlan": plan.get("effect"),
        "traceId": inc["trace_id"] if inc else new_trace_id(),
        "parentSpanId": inc["parent_span_id"] if inc else None,
        "tracestate": tracestate if (inc and tracestate) else None,
        "serverSpanId": new_span_id(), "agentSpanId": new_span_id(), "modelSpanId": new_span_id(),
        "joinSpanId": new_span_id(), "approvalSpanId": new_span_id(), "logicalSpanIds": {},
        "model": plan.get("model"), "t0": time.time_ns(),
        # sensitive is deliberately NOT stored; only what the state machine needs later
        "toolCatalog": payload.get("toolCatalog", []), "policy": payload.get("policy", {}),
    }
    for c in plan.get("diagnostics", []):
        item = _new_item(state, "diagnostic", c["toolName"], c["arguments"], c["evidence"])
        state["dispatches"].append(_issue(state, item))
    if not state["dispatches"]:
        _fail(state, "no_valid_diagnostic_plan")
    state["otlp"] = build_otlp(state)
    return state


def _decide(state, new):
    """Runs once all diagnostics are settled. Issues the effect, an approval request, or fails."""
    if state["status"] != "waiting" or state["approvals"] or state["effectIssued"]:
        return
    if any(i["phase"] == "diagnostic" for i in state["pending"].values()):
        return
    if not state["diagResults"]:
        return
    effect = state["effectPlan"]
    name = effect["toolName"] if effect else None
    if not all(state["diagResults"].values()):
        return _fail(state, "diagnostic_failed", name)
    if not effect:
        return _fail(state, "no_justified_effect")
    tools = tool_schema_map(state["toolCatalog"])
    if name not in tools or not validate_arguments(tools[name], effect["arguments"]):
        return _fail(state, "invalid_effect_arguments", name)
    state["effectIssued"] = True
    state["chosenEffect"] = name
    needs = set(state["policy"].get("approvalRequiredFor") or []) | DESTRUCTIVE
    if name in needs:
        state["approvals"] = [{"approvalId": opaque_id("approval"), "actionId": opaque_id("action"),
                               "toolName": name, "argumentsDigest": args_digest(effect["arguments"])}]
    else:
        item = _new_item(state, "effect", name, effect["arguments"], state["diagnosis"]["evidence"])
        new.append(_issue(state, item))


def apply_receipt(state, receipt_id, body):
    state = copy.deepcopy(state)
    if state["status"] in TERMINAL:
        raise EngineError(422, "run already terminal")
    outcomes, approvals = body.get("outcomes", []), body.get("approvals", [])
    if not isinstance(outcomes, list) or not isinstance(approvals, list) or not (outcomes or approvals):
        raise EngineError(422, "invalid receipt")
    seen = set()
    for o in outcomes:
        if not isinstance(o, dict):
            raise EngineError(422, "invalid outcome")
        key = f'{o.get("actionId")}:{o.get("callId")}'
        item = state["pending"].get(key)
        if (not item or item["attempt"] != o.get("attempt") or key in seen
                or not isinstance(o.get("status"), int) or isinstance(o.get("status"), bool)
                or not isinstance(o.get("nonce"), str) or not o["nonce"]):
            raise EngineError(422, "outcome is not pending")
        seen.add(key)
    for a in approvals:
        if (not isinstance(a, dict) or a.get("decision") not in ("approved", "denied")
                or not isinstance(a.get("nonce"), str) or not a["nonce"]
                or not any(r["approvalId"] == a.get("approvalId") for r in state["approvals"])):
            raise EngineError(422, "approval is not pending")

    new = []
    for o in outcomes:
        key = f'{o["actionId"]}:{o["callId"]}'
        item = state["pending"].pop(key)
        state["receiptLog"].append({"receiptId": receipt_id, "actionId": o["actionId"], "callId": o["callId"],
                                    "attempt": o["attempt"], "status": o["status"],
                                    "resultClass": o.get("resultClass"), "nonce": o["nonce"]})
        ok = 200 <= o["status"] < 300
        if o["status"] == 503 and item["attempt"] == 1:
            item["attempt"] = 2
            state["pending"][key] = item
            new.append(_issue(state, item, attempt=2))
        elif item["phase"] == "diagnostic":
            state["diagResults"][key] = ok
        elif ok:
            state["status"] = "completed"
        else:
            _fail(state, "effect_failed", item["toolName"])

    for a in approvals:
        req = next(r for r in state["approvals"] if r["approvalId"] == a["approvalId"])
        state["receiptLog"].append({"receiptId": receipt_id, "approvalId": a["approvalId"],
                                    "decision": a["decision"], "nonce": a["nonce"]})
        state["approvals"] = []
        if a["decision"] != "approved":
            _fail(state, "approval_denied", req["toolName"])
            continue
        eff = state["effectPlan"]
        item = _new_item(state, "effect", eff["toolName"], eff["arguments"], state["diagnosis"]["evidence"],
                         action_id=req["actionId"], call_id=req["actionId"],
                         approval={"approvalId": req["approvalId"], "nonce": a["nonce"]})
        new.append(_issue(state, item))

    _decide(state, new)
    if state["status"] in TERMINAL:
        state["dispatches"], state["approvals"], state["pending"] = [], [], {}
    else:
        state["dispatches"] = new
    state["otlp"] = build_otlp(state)
    return state


def public_state(state):
    def clean(d):
        d = copy.deepcopy(d)
        d.pop("_clientSpanId", None)
        return d
    final = state["status"] in TERMINAL
    return {
        "runId": state["runId"], "status": state["status"], "diagnosis": state["diagnosis"],
        "chosenEffect": state["chosenEffect"], "suppressed": state["suppressed"],
        "dispatches": [] if final else [clean(d) for d in state["dispatches"]],
        "approvals": [] if final else copy.deepcopy(state["approvals"]),
        "actionLog": [clean(d) for d in state["actionLog"]],
        "receiptLog": copy.deepcopy(state["receiptLog"]),
        "otlp": state["otlp"],
    }