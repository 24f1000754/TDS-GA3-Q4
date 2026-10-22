import json, uuid, copy, sys
sys.path.insert(0, ".")
from engine import *
from tools import args_digest

def payload(effect="rollback_deployment"):
    return {"runId": "run_12345678", "publicMarker": "mk-1", "sensitive": {"accessToken": "SECRET123"},
            "toolCatalog": [{"name": n, "inputSchema": {"type": "object", "required": ["service"],
                              "properties": {"service": {"type": "string"}}}} for n in
                            ["query_metrics", "get_logs", "rollback_deployment", "page_owner"]],
            "policy": {"approvalRequiredFor": ["rollback_deployment", "disable_feature"], "effectTools": [effect]}}

def plan(effect="rollback_deployment", n=2):
    diags = [{"toolName": t, "arguments": {"service": "api"}, "evidence": ["ev_1"]} for t in ["query_metrics", "get_logs"][:n]]
    return {"diagnosis": {"rootCause": "x", "evidence": ["ev_1", "ev_2"]}, "diagnostics": diags,
            "effect": {"toolName": effect, "arguments": {"service": "api"}}, "model": "gemini-test"}

def out(d, status=200, rc="diagnosis_confirmed"):
    return {"actionId": d["actionId"], "callId": d["callId"], "attempt": d["attempt"], "status": status,
            "resultClass": rc, "nonce": str(uuid.uuid4())}

def check_trace(pub, expect_join):
    spans = pub["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    ids = [s["spanId"] for s in spans]
    assert len(ids) == len(set(ids)), "dup span ids"
    assert len({s["traceId"] for s in spans}) == 1
    names = [s["name"] for s in spans]
    assert names.count("POST /v2/incidents") == 1 and names.count("chat incident-plan") == 1
    assert names.count("incident.join") == (1 if expect_join else 0)
    logical = {a["actionId"] for a in pub["actionLog"]}
    assert sum(n.startswith("execute_tool") for n in names) == len(logical), names
    assert sum(n.startswith("POST tool/") for n in names) == len(pub["actionLog"])
    for d in pub["actionLog"]:
        assert d["traceparent"].split("-")[2] in ids
    byid = {s["spanId"]: s for s in spans}
    for s in spans:
        if "parentSpanId" in s and s["name"] != "POST /v2/incidents": assert s["parentSpanId"] in byid
    assert "SECRET123" not in json.dumps(pub)
    return names

# Scenario A: parallel diag, one 503 retry, approval, effect success
s = create_state(payload(), plan(), "00-" + "a"*32 + "-" + "b"*16 + "-01", "vendor=x")
p = public_state(s); assert p["chosenEffect"] is None and len(p["dispatches"]) == 2 and p["dispatches"][0]["tracestate"] == "vendor=x"
assert p["dispatches"][0]["traceparent"].split("-")[1] == "a"*32
d1, d2 = p["dispatches"]
s = apply_receipt(s, "receipt_0001", {"receiptId": "receipt_0001", "outcomes": [out(d1, 503, "x"), out(d2)]})
p = public_state(s); assert len(p["dispatches"]) == 1 and p["dispatches"][0]["attempt"] == 2 and not p["approvals"]
assert p["dispatches"][0]["actionId"] == d1["actionId"]
s = apply_receipt(s, "receipt_0002", {"receiptId": "receipt_0002", "outcomes": [out(p["dispatches"][0])]})
p = public_state(s); assert p["dispatches"] == [] and len(p["approvals"]) == 1
ap = p["approvals"][0]; assert ap["argumentsDigest"] == args_digest({"service": "api"})
s = apply_receipt(s, "receipt_0003", {"receiptId": "receipt_0003", "approvals": [{"approvalId": ap["approvalId"], "decision": "approved", "nonce": "n-1"}]})
p = public_state(s); e = p["dispatches"][0]
assert e["phase"] == "effect" and e["approvalId"] == ap["approvalId"] and e["approvalNonce"] == "n-1" and e["actionId"] == ap["actionId"]
s = apply_receipt(s, "receipt_0004", {"receiptId": "receipt_0004", "outcomes": [out(e, 200, "done")]})
p = public_state(s); assert p["status"] == "completed" and p["dispatches"] == [] and p["approvals"] == []
assert p["chosenEffect"] == "rollback_deployment"
assert any("approvalId" in r for r in p["receiptLog"])
print("A spans:", check_trace(p, True))
cs = [x for x in p["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"] if x["name"].startswith("POST tool/")]
print("A resend counts:", [(next(a["value"] for a in c["attributes"] if a["key"]=="http.request.resend_count"), c["status"]["code"]) for c in cs])

# Scenario B: timeout -> effect suppressed
s = create_state(payload(), plan())
d1, d2 = public_state(s)["dispatches"]
s = apply_receipt(s, "receipt_0011", {"receiptId": "receipt_0011", "outcomes": [out(d1), {**out(d2, 0, None), "errorType": "timeout"}]})
p = public_state(s); assert p["status"] == "failed" and p["dispatches"] == [] and p["approvals"] == []
assert not any(d["phase"] == "effect" for d in p["actionLog"]); print("B suppressed:", p["suppressed"]); check_trace(p, True)

# Scenario C: non-destructive effect, single diagnostic, no join
s = create_state(payload("page_owner"), plan("page_owner", 1))
d1 = public_state(s)["dispatches"][0]
s = apply_receipt(s, "receipt_0021", {"receiptId": "receipt_0021", "outcomes": [out(d1)]})
p = public_state(s); e = p["dispatches"][0]; assert e["phase"] == "effect" and "approvalId" not in e
s = apply_receipt(s, "receipt_0022", {"receiptId": "receipt_0022", "outcomes": [out(e, 200, "paged")]})
p = public_state(s); assert p["status"] == "completed"; check_trace(p, False)

# Scenario D: invalid receipts rejected, state unchanged
s = create_state(payload(), plan()); d1 = public_state(s)["dispatches"][0]
for bad in [{"receiptId": "receipt_0031", "outcomes": [{**out(d1), "attempt": 2}]},
            {"receiptId": "receipt_0031", "approvals": [{"approvalId": "nope", "decision": "approved", "nonce": "n"}]},
            {"receiptId": "receipt_0031", "outcomes": [out({"actionId": "zz", "callId": "zz", "attempt": 1})]}]:
    try: apply_receipt(s, "receipt_0031", bad); raise SystemExit("should reject")
    except EngineError as e: assert e.code == 422
print("ALL OK")