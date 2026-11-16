#!/usr/bin/env python3
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# The reconciliation engine — the executable form of spec/04 §5 (intents),
# §6 (levels, expectation rules, inline decision, offline recomputation) and
# §7 (MCP server sessions), on the abstract trace of docs/refreconcile.md.
#
# Ordering is log order and log order only: an intent is open from the
# intent.declared record until its intent.result record or the session seal.
# Timestamps (`ts`) are used for exactly one thing — the §7.1 startup-grace
# duration check — and never for ordering.
import datetime

from . import canon, expect, grants

# 04 §5.2: only these classes can authorize network effects; "local" cannot.
NETWORK_CLASSES = frozenset(("exec", "http", "mcp", "other"))

# 04 §6.4: the levels that satisfy an intent condition, per intentMatch.
_INTENT_OK = {
    "window": frozenset(("EXACT", "WINDOW", "CONTROL")),
    "exact": frozenset(("EXACT", "CONTROL")),
}

_SEV = {"F_ATTRIBUTION_MISMATCH": "error", "F_DECISION_MISMATCH": "error",
        "F_UNATTRIBUTED": "error", "F_CREDENTIAL_SCOPE": "error",
        "F_CLASS_MISMATCH": "error", "F_CONTRACT_STARTUP": "error",
        "F_CONTRACT_IDLE": "error", "F_CONTRACT_PATTERN": "error",
        "F_CONTRACT_MAX_EFFECTS": "error", "F_CONTRACT_ANNOTATION": "error"}


def _ts(s):
    if not isinstance(s, str):
        return None
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


class TraceError(Exception):
    pass


class _Intent:
    __slots__ = ("id", "tool", "cls", "executor", "input", "input_sha256",
                 "open", "consumed", "expectations", "order")

    def __init__(self, rec, order, packs, command_field):
        self.id = rec.get("intent_id")
        self.tool = rec.get("tool")
        self.cls = rec.get("class")
        self.executor = rec.get("executor") or "sandbox"
        self.input = rec.get("input") if isinstance(rec.get("input"), dict) else {}
        self.input_sha256 = rec.get("input_sha256") or canon.canon_sha256(self.input)
        self.open = self.executor == "sandbox"   # 04 §5.3: provider intents never open
        self.consumed = False                    # 04 §6.3: one tools/call per intent
        self.order = order
        self.expectations = expect.intent_expectations(
            {"class": self.cls, "tool": self.tool, "input": self.input,
             "command_field": command_field}, packs)


class _Call:
    __slots__ = ("id", "tool", "args", "effects_used", "order")

    def __init__(self, rec, order):
        self.id = rec.get("call_id")
        self.tool = rec.get("tool")
        self.args = rec.get("contract_args") or rec.get("arguments") or {}
        self.effects_used = 0
        self.order = order


class _Session:
    def __init__(self):
        self.kind = "agent"
        self.mode = "enforce"
        self.policy = {}
        self.contract = None
        self.contract_missing = True
        self.open_ts = None
        self.intents = {}            # intent_id -> _Intent (first declaration wins)
        self.intent_order = []
        self.calls = {}              # call_id -> _Call (in flight)
        self.call_order = []
        self.tools_ann = None        # last mcp.tools annotations
        self.sealed = False
        self.denials = 0             # recorded denials (decision.action == deny)
        self.effects = 0
        self.command_field = "command"
        self.mcp_servers = {}        # server name -> grant (inspect: mcp)


def _finding(code, effect, detail):
    return {"code": code, "severity": _SEV.get(code, "error"),
            "effect": effect, "detail": detail}


def _open_network_intents(st):
    return [i for i in st.intent_order if i.open and i.cls in NETWORK_CLASSES]


def _map_mcp_tool(st, tool_name):
    """04 §6.3 mcpNaming (default mcp__<server>__<tool>) -> (server, tool)."""
    naming = st.policy.get("mcpNaming") or "mcp__<server>__<tool>"
    if naming != "mcp__<server>__<tool>":
        return None                                    # only the default is defined
    if not isinstance(tool_name, str) or not tool_name.startswith("mcp__"):
        return None
    rest = tool_name[len("mcp__"):]
    for srv in st.mcp_servers:
        pre = srv + "__"
        if rest.startswith(pre) and rest[len(pre):]:
            return srv, rest[len(pre):]
    return None


def _match_tool_call(st, grant, mcp):
    """04 §6.3: the open mcp-class intent that names this (server, tool) with
    the same canonical-argument digest and has not matched a call before."""
    server = mcp.get("server") or grant.get("server")
    tool = mcp.get("tool")
    args = mcp.get("arguments")
    args_sha = mcp.get("arguments_sha256") or canon.canon_sha256(args)
    for i in st.intent_order:
        if not i.open or i.consumed or i.cls != "mcp":
            continue
        mapped = _map_mcp_tool(st, i.tool)
        if mapped is None or mapped != (server, tool):
            continue
        if i.input_sha256 != args_sha:
            continue
        return i
    return None


def _level(st, grant, request, mcp):
    """04 §6.1/§6.3: attribution level and intent list of one effect."""
    if grant.get("inspect") == "inference":
        return "CONTROL", [], None
    if grant.get("inspect") == "mcp" and mcp is not None \
            and mcp.get("method") != "tools/call":
        return "CONTROL", [], None                     # 04 §6.1: protocol messages
    if mcp is not None and mcp.get("method") == "tools/call" and (
            mcp.get("server") or grant.get("server")) in st.mcp_servers:
        # 04 §6.3: a tools/call exacts only a declared, unconsumed intent for
        # that same server, tool and canonical arguments — regardless of the
        # grant's inspection mode.
        i = _match_tool_call(st, grant, mcp)
        if i is not None:
            i.consumed = True
            return "EXACT", [i.id], None
        return "NONE", [], "undeclared-call"
    open_i = _open_network_intents(st)
    exacts = [i for i in open_i
              if any(expect.expectation_matches(e, request, grant)
                     for e in i.expectations)]
    if exacts:
        return "EXACT", [i.id for i in exacts], None
    if open_i:
        return "WINDOW", [i.id for i in open_i], None
    if grant.get("requires") == "none":
        return "STANDING", [], None
    return "NONE", [], None


def _proceed(cls):
    """Per-class action when the condition lets the effect through (05 §2)."""
    return ("stage", "STAGED") if cls == "staged" else ("allow", "OK")


def _decide(st, grant, cond, cls, level, lreason):
    """04 §6.4 + 05 §2, enforce semantics: -> (action, reason, no_auto)."""
    if cond == "deny":
        return "deny", "AUTONOMY_DENY", False
    if cond == "review" and cls != "control":
        # 05 §1: control effects are never staged, held or undone.
        return (("stage", "STAGED", True) if cls == "staged"
                else ("hold", "REVIEW_REQUIRED", False))
    if cond == "intent":
        if level not in _INTENT_OK[grant.get("intentMatch") or "window"]:
            return ("deny",
                    "UNDECLARED_TOOL_CALL" if lreason == "undeclared-call"
                    else "NO_INTENT", False)
    a, r = _proceed(cls)
    return a, r, False


def _compare(rec, res, findings):
    """04 §6.5: compare the recorded broker fields with the recomputation.
    An effect record that carries no decision/attribution/class makes no
    broker claim and is skipped (the recomputed values still stand)."""
    if "decision" not in rec and "attribution" not in rec and "class" not in rec:
        return
    rid = rec.get("effect_id")
    dec = rec.get("decision") or {}
    att = rec.get("attribution") or {}
    if (rec.get("class") or None) != res["class"]:
        findings.append(_finding("F_CLASS_MISMATCH", rid,
                                 "class %r recorded, %r recomputed"
                                 % (rec.get("class"), res["class"])))
    if (dec.get("requires") or None) != res["condition"]:
        findings.append(_finding("F_CLASS_MISMATCH", rid,
                                 "condition %r recorded, %r recomputed"
                                 % (dec.get("requires"), res["condition"])))
    if (att.get("level") or None) != res["level"] \
            or (att.get("intents") or []) != res["intents"]:
        findings.append(_finding(
            "F_ATTRIBUTION_MISMATCH", rid,
            "attribution (%r,%r) recorded, (%r,%r) recomputed"
            % (att.get("level"), att.get("intents"),
               res["level"], res["intents"])))
    if (dec.get("grant") or None) != res["grant"]:
        findings.append(_finding("F_DECISION_MISMATCH", rid,
                                 "grant %r recorded, %r recomputed"
                                 % (dec.get("grant"), res["grant"])))
    if (dec.get("action") or None) != res["action"] \
            or (dec.get("reason") or None) != res["reason"] \
            or (dec.get("would_deny") or None) != res["would_deny"]:
        findings.append(_finding("F_DECISION_MISMATCH", rid,
                                 "decision (%r,%r,would_deny=%r) recorded, "
                                 "(%r,%r,would_deny=%r) recomputed"
                                 % (dec.get("action"), dec.get("reason"),
                                    dec.get("would_deny"), res["action"],
                                    res["reason"], res["would_deny"])))
    if dec.get("credentials") and not res.get("grant_has_credential"):
        findings.append(_finding("F_CREDENTIAL_SCOPE", rid,
                                 "credential recorded on a grant without one"))
    # 04 §6.5: an effect the broker allowed (or that recomputation allows)
    # with level NONE under an intent condition is unattributed.
    acted = dec.get("action") if "decision" in rec else res["action"]
    if (acted == "allow" and res["level"] == "NONE"
            and res["condition"] == "intent" and res["mode"] != "learn"):
        findings.append(_finding("F_UNATTRIBUTED", rid,
                                 "allowed effect with no qualifying intent"))


def _eval_effect(st, rec, findings):
    """Recompute one sandbox effect.http (agent session)."""
    req = rec.get("request") or {}
    rid = rec.get("effect_id")
    grant, greason = grants.select_grant(st.policy, req)
    res = {"grant": grant.get("id") if grant else None,
           "grant_has_credential": bool(grant and grant.get("credential")),
           "class": None, "condition": None,
           "level": "NONE", "intents": [],
           "action": "deny", "reason": greason or "NO_GRANT",
           "would_deny": None, "mode": st.mode}
    if greason is not None:
        # 04 §6.4: DENY_GRANT and SMUGGLING_SUSPECT deny in every mode; audit
        # and learn admit a NO_GRANT request so the failure is observed.
        if greason == "NO_GRANT" and st.mode == "audit":
            res.update(action="allow", reason="OK",
                       would_deny={"action": "deny", "reason": "NO_GRANT"})
        elif greason == "NO_GRANT" and st.mode == "learn":
            res.update(action="allow", reason="OK")
    else:
        cls = grants.classify(grant, req)
        cond = grants.condition(st.policy, grant, cls)
        level, intents, lr = _level(st, grant, req, req.get("mcp"))
        a, r, na = _decide(st, grant, cond, cls, level, lr)
        if st.mode == "audit":
            # The request is allowed; would_deny carries the stopped reason.
            if a in ("deny", "hold"):
                a2, wd = "allow", {"action": a, "reason": r}
            else:
                a2, wd = a, None
            res.update({"class": cls, "condition": cond, "level": level,
                        "intents": intents, "action": a2, "reason": "OK",
                        "would_deny": wd})
        elif st.mode == "learn":
            # 04 §6.4: everything not hitting a deny grant is allowed.
            res.update({"class": cls, "condition": cond, "level": level,
                        "intents": intents, "action": "allow",
                        "reason": "OK"})
        else:
            res.update({"class": cls, "condition": cond, "level": level,
                        "intents": intents, "action": a, "reason": r,
                        "no_auto": na or None})
    _compare(rec, res, findings)
    if res["action"] == "deny":
        st.denials += 1
    st.effects += 1
    return res


# --------------------------------------------------------------------------
# Scenario S2 (04 §7): the MCP server's own session.


def _pct_seg(v):
    """Percent-encode one path-segment substitution (04 §7.1): every byte
    outside the unreserved set becomes %XX."""
    out = []
    for byte in str(v).encode("utf-8"):
        c = chr(byte)
        out.append(c if c in grants.UNRES else "%%%02X" % byte)
    return "".join(out)


def _norm_pct(seg):
    """Normalize a wire path segment: decode unreserved, uppercase escapes."""
    return grants.pct_decode_unres(seg)


def _pattern_match(pat, request, args):
    """Match one contract effect pattern {host, method, path} where path
    segments that are exactly {arguments.X} bind the in-flight call's args."""
    host, _ = grants.split_authority(request.get("authority"), 443)
    if pat.get("host") is not None and \
            grants.norm_host(host) != grants.norm_host(pat["host"]):
        return False
    if pat.get("method") is not None and request.get("method") != pat["method"]:
        return False
    tmpl = pat.get("path")
    if tmpl is None:
        return True
    tsegs = tmpl.split("/")
    rsegs = (request.get("path") or "/").split("/")
    if len(tsegs) != len(rsegs):
        return False
    for t, r in zip(tsegs, rsegs):
        if t.startswith("{arguments.") and t.endswith("}"):
            key = t[len("{arguments."):-1]
            v = args.get(key)
            if not isinstance(v, str):               # non-string/missing: unmatchable
                return False
            if _pct_seg(v) != _norm_pct(r):
                return False
        elif _norm_pct(t) != _norm_pct(r):
            return False
    return True


def _contract_for(st, tool):
    tools = ((st.contract or {}).get("spec") or {}).get("tools") or {}
    return tools.get(tool) or {}


def _eval_server_effect(st, rec, findings):
    """04 §7.3 checks on one server-session effect, in order."""
    req = rec.get("request") or {}
    rid = rec.get("effect_id")
    grant, greason = grants.select_grant(st.policy, req)
    res = {"grant": grant.get("id") if grant else None,
           "grant_has_credential": bool(grant and grant.get("credential")),
           "class": None, "condition": None, "level": "NONE", "intents": [],
           "action": "deny", "reason": greason or "NO_GRANT",
           "would_deny": None, "mode": st.mode}
    if greason is not None:
        _compare_server(rec, res, findings)
        st.denials += 1
        st.effects += 1
        return res
    cls = grants.classify(grant, req)
    cond = grants.condition(st.policy, grant, cls)
    res["class"] = cls
    res["condition"] = cond
    contract = (st.contract or {}).get("spec") or {}
    in_flight = sorted(st.calls.values(), key=lambda c: c.order)

    # Check 1 — startup grace: within graceSeconds of session.open the effect
    # must match a startup.effects pattern, else F_CONTRACT_STARTUP. (The
    # only ts use anywhere: a duration bound, never an ordering.)
    grace = (contract.get("startup") or {}).get("graceSeconds")
    ets, ots = _ts(rec.get("ts")), st.open_ts
    in_grace = (grace is not None and ets is not None and ots is not None
                and 0 <= (ets - ots).total_seconds() < grace)

    violation = False
    if in_grace:
        pats = (contract.get("startup") or {}).get("effects") or []
        if not any(_pattern_match(p, req, {}) for p in pats):
            findings.append(_finding("F_CONTRACT_STARTUP", rid,
                                     "effect inside startup grace matches no "
                                     "startup.effects pattern"))
            res.update(action="deny", reason="CONTRACT_VIOLATION")
            violation = True
    elif not in_flight:
        # Check 2 — no call in flight: contract idle rule, else the 05 §12
        # default (deny everything but safe/control outside a call).
        idle_deny = (contract.get("idle", "deny") == "deny" if contract
                     else cls not in ("safe", "control"))
        if idle_deny:
            if contract:
                findings.append(_finding("F_CONTRACT_IDLE", rid,
                                         "effect with no call in flight"))
            res.update(action="deny", reason="EFFECT_OUTSIDE_CALL")
            violation = True
    elif contract:
        # Check 3 — the effect must match a pattern of some in-flight call's
        # contract entry and keep that call within maxEffects.
        matched, over_cap = None, False
        for c in in_flight:
            entry = _contract_for(st, c.tool)
            if not any(_pattern_match(p, req, c.args)
                       for p in entry.get("effects") or []):
                continue
            maxe = entry.get("maxEffects")
            if maxe is None or c.effects_used < maxe:
                matched = c
                break
            over_cap = True
        if matched is not None:
            matched.effects_used += 1
        else:
            findings.append(_finding(
                "F_CONTRACT_MAX_EFFECTS" if over_cap else "F_CONTRACT_PATTERN",
                rid, "in-flight calls admit no matching pattern under "
                     "maxEffects" if over_cap else
                     "no in-flight call's pattern matches"))
            res.update(action="deny", reason="CONTRACT_VIOLATION")
            violation = True

    # Check 4 — annotation check, independent of any contract: a non-GET/HEAD
    # effect while every in-flight call's tool is advertised readOnlyHint.
    if not violation and in_flight and st.tools_ann is not None \
            and all((st.tools_ann.get(c.tool) or {}).get("readOnlyHint")
                    is True for c in in_flight) \
            and req.get("method") not in ("GET", "HEAD"):
        findings.append(_finding("F_CONTRACT_ANNOTATION", rid,
                                 "write during read-only tool call"))
        res.update(action="deny", reason="ANNOTATION_VIOLATION")
        violation = True

    if not violation:
        a, r, _ = _decide(st, grant, cond, cls, "NONE", None)
        res.update(action=a, reason=r)
    _compare_server(rec, res, findings)
    if res["action"] == "deny":
        st.denials += 1
    st.effects += 1
    return res


def _compare_server(rec, res, findings):
    """Server-session effects: compare class, condition, attribution and
    decision fields (server effects still carry level NONE / empty intents
    on the abstract trace)."""
    if "decision" not in rec and "class" not in rec \
            and "attribution" not in rec:
        return
    rid = rec.get("effect_id")
    dec = rec.get("decision") or {}
    att = rec.get("attribution") or {}
    if (rec.get("class") or None) != res["class"]:
        findings.append(_finding("F_CLASS_MISMATCH", rid,
                                 "class %r recorded, %r recomputed"
                                 % (rec.get("class"), res["class"])))
    if (dec.get("requires") or None) != res["condition"]:
        findings.append(_finding("F_CLASS_MISMATCH", rid,
                                 "condition %r recorded, %r recomputed"
                                 % (dec.get("requires"), res["condition"])))
    if "attribution" in rec:
        if (att.get("level") or "NONE") != "NONE" \
                or (att.get("intents") or []):
            findings.append(_finding("F_ATTRIBUTION_MISMATCH", rid,
                                     "server-session effect carries intent "
                                     "attribution"))
    if (dec.get("grant") or None) != res["grant"]:
        findings.append(_finding("F_DECISION_MISMATCH", rid,
                                 "grant %r recorded, %r recomputed"
                                 % (dec.get("grant"), res["grant"])))
    if (dec.get("action") or None) != res["action"] \
            or (dec.get("reason") or None) != res["reason"]:
        findings.append(_finding("F_DECISION_MISMATCH", rid,
                                 "decision (%r,%r) recorded, (%r,%r) recomputed"
                                 % (dec.get("action"), dec.get("reason"),
                                    res["action"], res["reason"])))
    if dec.get("credentials") and not res.get("grant_has_credential"):
        findings.append(_finding("F_CREDENTIAL_SCOPE", rid,
                                 "credential recorded on a grant without one"))


# --------------------------------------------------------------------------


def reconcile(meta, records, packs):
    """Run one trace. `meta` is the trace.meta object; `records` the record
    bodies in log order; `packs` the flattened §6.2 rule list.

    Returns {"effects": {id: result}, "findings": [...], "verdict": str}.
    """
    st = _Session()
    st.policy = meta.get("policy") or {}
    st.command_field = st.policy.get("commandField") or "command"
    for g in st.policy.get("grants") or []:
        if g.get("inspect") == "mcp" and g.get("server"):
            st.mcp_servers[g["server"]] = g
    contracts = meta.get("contracts") or {}
    st.contract = meta.get("contract") or \
        (next(iter(contracts.values())) if len(contracts) == 1 else None)
    effects, findings = {}, []
    for rec in records:
        t = rec.get("type")
        if t == "session.open":
            st.kind = rec.get("kind") or "agent"
            st.mode = rec.get("mode") or st.policy.get("mode") or "enforce"
            st.open_ts = _ts(rec.get("ts"))
        elif t == "intent.declared":
            iid = rec.get("intent_id")
            if iid is not None and iid not in st.intents:   # 04 §5.2: not a new intent
                i = _Intent(rec, len(st.intent_order), packs, st.command_field)
                st.intents[iid] = i
                st.intent_order.append(i)
        elif t == "intent.result":
            i = st.intents.get(rec.get("intent_id"))
            if i is not None:
                i.open = False
        elif t == "intent.unparsed":
            pass                                           # 04 §5.4: nothing opens
        elif t == "mcp.call.begin":
            cid = rec.get("call_id")
            if cid is not None and cid not in st.calls:
                st.calls[cid] = _Call(rec, len(st.call_order))
                st.call_order.append(cid)
        elif t == "mcp.call.end":
            st.calls.pop(rec.get("call_id"), None)
        elif t == "mcp.tools":
            st.tools_ann = {x.get("name"): (x.get("annotations") or {})
                            for x in rec.get("tools") or []}
        elif t in ("effect.http", "effect.tunnel"):
            if rec.get("actor") == "world":
                pass                               # world-side apply/sync: not §5–§7
            elif t == "effect.tunnel":
                rec = dict(rec)
                rec["request"] = {"authority": rec.get("authority"),
                                  "scheme": rec.get("scheme") or "https",
                                  "method": None, "path": "/", "query": "",
                                  "websocket": rec.get("kind") == "websocket"}
                if st.kind == "mcp-server":
                    effects[rec.get("effect_id")] = _eval_server_effect(st, rec, findings)
                else:
                    effects[rec.get("effect_id")] = _eval_effect(st, rec, findings)
            elif st.kind == "mcp-server":
                effects[rec.get("effect_id")] = _eval_server_effect(st, rec, findings)
            else:
                effects[rec.get("effect_id")] = _eval_effect(st, rec, findings)
        elif t == "effect.denied":
            st.denials += 1
            st.effects += 1
        elif t == "session.seal":
            st.sealed = True
            for i in st.intent_order:
                i.open = False                             # 04 §5.3: seal closes all
        elif t in ("sandbox.terminated", "world.closed", "emitter.seal",
                   "context.observed", "taint.added", "stage.entry",
                   "effect.http.result", "effect.tunnel.result",
                   "commit.requested", "commit.decision", "commit.applied",
                   "commit.closed", "prestate.captured", "undo.requested",
                   "undo.applied", "undo.closed", "attestation.issued",
                   "effect.exec", "effect.connect", "observer.gap",
                   "intent.unknown", "replay.divergence", "world.rewound"):
            pass                                           # not inputs to §5–§7
        elif t == "trace.meta":
            raise TraceError("trace.meta must be the first line only")
        else:
            raise TraceError("unknown record type %r" % t)

    # Verdict lattice of 03 §10 (most severe first).
    errs = [f for f in findings if f["severity"] == "error"]
    if not st.sealed:
        verdict = "UNSEALED"
    elif st.mode == "learn":
        verdict = "LEARN"
    elif errs:
        verdict = "VIOLATIONS"
    elif st.denials:
        verdict = "CLEAN_WITH_DENIALS"
    else:
        verdict = "CLEAN"
    out = {}
    for rid, r in effects.items():
        out[rid] = {k: v for k, v in r.items() if v is not None}
    return {"effects": out, "findings": findings, "verdict": verdict}
