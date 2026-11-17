# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""Bundle verification pipeline (spec 03 §10): V1–V11 + V15.

The observable behaviour — verdicts, world state, findings order, error
diagnostics and JSON shape — mirrors the reference verifier exactly.
"""
import hashlib
import json

from . import bundle as _bundle
from . import dsse, keys as _keys, mlog, note
from .dsse import SchemaError
from .strict import _quote


def _f(code, detail):
    return {"code": code, "detail": detail}


def _fat(code, i, detail):
    return {"code": code, "index": i, "detail": detail}


class _Res:
    """The verifier result row; JSON shape mirrors the reference schema."""

    def __init__(self):
        self.verdict = ""
        self.world = "open"
        self.errors = []
        self.warnings = None   # Go nil slice → null; [] only pre-V1
        self.findings = []
        self.stats = {}
        self.sealed = False
        self.learn = False
        self.denied = False


def _emit(res):
    if res.errors:
        res.verdict = "INVALID"
    elif not res.sealed:
        res.verdict = "UNSEALED"
    elif res.learn:
        res.verdict = "LEARN"
    elif res.denied:
        res.verdict = "CLEAN_WITH_DENIALS"
    else:
        res.verdict = "CLEAN"
    return {
        "verdict": res.verdict,
        "world": res.world,
        "errors": res.errors,
        "warnings": res.warnings,
        "findings": res.findings,
        # Go marshals map[string]any with sorted keys.
        "stats": dict(sorted(res.stats.items())),
    }


def _split_lines(data):
    """bytes.TrimSuffix(\n) + Split(\n); empty input → no lines."""
    if data.endswith(b"\n"):
        data = data[:-1]
    if len(data) == 0:
        return []
    return data.split(b"\n")


def _via_of(t, b):
    """viaOf: the via_effect of bodies that carry one (03 §4.4)."""
    if t in ("context.observed", "intent.unparsed"):
        return b["via_effect"]
    return ""


def _verify_structure(recs):
    """V11: referential integrity and §4.5 ordering, single pass, log order."""
    errs = []
    http_eff = {}    # effect_id → index
    tunnel_eff = {}  # effect_id → index
    intents = {}     # intent_id → index
    calls = {}       # call_id → index
    entries = {}     # entry_id → index
    commit_req = {}  # commit_id → index
    commit_dec = {}  # commit_id → index
    undo_req = {}    # undo_id → index
    results = {}     # "http:<id>" / "tunnel:<id>" → result count

    def at(i, msg):
        errs.append(_fat("E_STRUCTURE", i, msg))

    for i, d in enumerate(recs):
        if not d["ok"]:
            continue
        b = d["rec"]["body"]
        t = d["rec"]["type"]
        if t == "effect.http":
            eid = b["effect_id"]
            if eid in http_eff:
                at(i, "duplicate effect_id %s" % eid)
            http_eff[eid] = i
            if b.get("purpose") == "apply":
                fr = b.get("for")
                if fr is None:
                    at(i, "apply effect %s has no for" % eid)
                elif fr not in commit_dec:
                    at(i, "apply effect %s for %s precedes its "
                          "commit.decision" % (eid, fr))
        elif t == "effect.tunnel":
            eid = b["effect_id"]
            if eid in tunnel_eff:
                at(i, "duplicate effect_id %s" % eid)
            tunnel_eff[eid] = i
        elif t == "effect.http.result":
            eid = b["effect_id"]
            ei = http_eff.get(eid)
            if ei is None:
                at(i, "result for unknown effect %s" % eid)
            elif ei >= i:
                at(i, "result precedes effect %s" % eid)
            if results.get("http:" + eid, 0) > 0:
                at(i, "second result for effect %s" % eid)
            results["http:" + eid] = results.get("http:" + eid, 0) + 1
        elif t == "effect.tunnel.result":
            eid = b["effect_id"]
            ei = tunnel_eff.get(eid)
            if ei is None:
                at(i, "result for unknown tunnel %s" % eid)
            elif ei >= i:
                at(i, "result precedes tunnel %s" % eid)
            if results.get("tunnel:" + eid, 0) > 0:
                at(i, "second result for tunnel %s" % eid)
            results["tunnel:" + eid] = results.get("tunnel:" + eid, 0) + 1
        elif t == "intent.declared":
            iid = b["intent_id"]
            intents[iid] = i
            if b["via_effect"] not in http_eff and \
                    b["via_effect"] not in tunnel_eff:
                at(i, "intent %s via unknown effect %s"
                   % (iid, b["via_effect"]))
        elif t == "intent.result":
            iid = b["intent_id"]
            ii = intents.get(iid)
            if ii is None:
                at(i, "result for unknown intent %s" % iid)
            elif ii >= i:
                at(i, "result precedes intent %s" % iid)
        elif t == "stage.entry":
            eid = b["entry_id"]
            entries[eid] = i
            if b["via_effect"] not in http_eff and \
                    b["via_effect"] not in tunnel_eff:
                at(i, "entry %s via unknown effect %s"
                   % (eid, b["via_effect"]))
            sup = b.get("supersedes")
            if sup is not None and sup not in entries:
                at(i, "entry %s supersedes unknown %s" % (eid, sup))
        elif t == "prestate.captured":
            fe = b["for_effect"]
            ei = http_eff.get(fe)
            if ei is None:
                at(i, "prestate for unknown effect %s" % fe)
            elif b["when"] == "before" and \
                    results.get("http:" + fe, 0) > 0:
                at(i, "before-prestate for %s after its result (idx %d)"
                   % (fe, ei))
            if b["via_effect"] not in http_eff:
                at(i, "prestate via unknown effect %s" % b["via_effect"])
        elif t == "commit.requested":
            cid = b["commit_id"]
            commit_req[cid] = i
            for e in b["entries"] or []:
                if e not in entries:
                    at(i, "commit %s requests unknown entry %s" % (cid, e))
        elif t == "commit.decision":
            cid = b["commit_id"]
            commit_dec[cid] = i
            if cid not in commit_req:
                at(i, "decision for unrequested commit %s" % cid)
        elif t == "commit.applied":
            cid = b["commit_id"]
            if cid not in commit_dec:
                at(i, "applied for undecided commit %s" % cid)
            if b["entry_id"] not in entries:
                at(i, "applied unknown entry %s" % b["entry_id"])
            via = b.get("via_effect")
            if via is not None and via not in http_eff:
                at(i, "applied via unknown effect %s" % via)
        elif t == "commit.closed":
            if b["commit_id"] not in commit_dec:
                at(i, "closed for undecided commit %s" % b["commit_id"])
        elif t == "probation.ratified":
            if b["commit_id"] not in commit_dec:
                at(i, "ratified for undecided commit %s" % b["commit_id"])
        elif t == "undo.requested":
            undo_req[b["undo_id"]] = i
        elif t == "undo.applied":
            if b["undo_id"] not in undo_req:
                at(i, "applied for unrequested undo %s" % b["undo_id"])
            via = b.get("via_effect")
            if via is not None and via not in http_eff:
                at(i, "undo applied via unknown effect %s" % via)
        elif t == "undo.closed":
            if b["undo_id"] not in undo_req:
                at(i, "closed for unrequested undo %s" % b["undo_id"])
        elif t == "attestation.issued":
            if b["entry_id"] not in entries:
                at(i, "attestation for unknown entry %s" % b["entry_id"])
        elif t in ("context.observed", "intent.unparsed", "mcp.tools",
                   "replay.divergence"):
            x = _via_of(t, b)
            if x != "" and x not in http_eff and x not in tunnel_eff:
                at(i, "%s via unknown effect %s" % (t, x))
        elif t == "mcp.call.begin":
            calls[b["call_id"]] = i
        elif t == "mcp.call.end":
            cid = b["call_id"]
            ci = calls.get(cid)
            if ci is None:
                at(i, "end for unknown call %s" % cid)
            elif ci >= i:
                at(i, "end precedes call %s" % cid)
    return errs


def _verify_warnings(recs, seal_body):
    """V15 warnings, in the reference order."""
    w = []
    resulted = set()
    http_order = []
    for i, d in enumerate(recs):
        if not d["ok"]:
            continue
        t = d["rec"]["type"]
        b = d["rec"]["body"]
        if t == "effect.http":
            http_order.append((b["effect_id"], i))
        elif t == "effect.http.result":
            resulted.add(b["effect_id"])
        elif t == "observer.gap":
            w.append(_fat("W_OBSERVER_GAP", i, "observer gap recorded"))
        elif t == "intent.unparsed":
            w.append(_fat("W_UNPARSED", i, "unparsed intent recorded"))
        elif t == "commit.closed":
            if b["outcome"] == "partial":
                w.append(_fat("W_PARTIAL_COMMIT", i,
                              "commit closed partial"))
        elif t == "commit.applied":
            if b["outcome"] == "unknown":
                w.append(_fat("W_APPLY_UNKNOWN", i,
                              "apply outcome unknown"))
        elif t == "undo.closed":
            if b["conflicts"] > 0:
                w.append(_fat("W_UNDO_CONFLICT", i, "undo had conflicts"))
    for eid, i in http_order:
        if eid not in resulted:
            w.append(_fat("W_DANGLING", i, "effect %s has no result" % eid))
    if seal_body is not None:
        for i, se in enumerate(seal_body["emitters"] or []):
            if not se["clean"]:
                w.append(_fat("W_UNCLEAN_EMITTER", i,
                              "emitter %s sealed unclean" % se["emitter"]))
    # Go: verifyWarnings returns a nil slice when empty → null in JSON.
    return w or None


def _has_denial(recs):
    return any(d["ok"] and d["rec"]["type"] == "effect.denied"
               for d in recs)


def verify_bundle(data, trusted):
    """Bundle bytes + trusted manifest → result dict (the verifier schema)."""
    res = _Res()
    # V1 — archive well-formed; required entries present; none extra.
    try:
        members = _bundle.read_bundle(data)
    except _bundle.BundleError as e:
        res.errors.append(_f("E_BUNDLE", str(e)))
        res.warnings = []
        res.verdict = "INVALID"
        return _emit(res)
    try:
        man = _bundle.parse_manifest(members["manifest.json"])
    except _bundle.BundleError as e:
        res.errors.append(_f("E_BUNDLE", str(e)))
        res.warnings = []
        res.verdict = "INVALID"
        return _emit(res)
    res.stats["session"] = man["session"]

    # V2 — every line is a strict DSSE envelope + statement + predicate.
    raw_lines = _split_lines(members["records.jsonl"])
    recs = []
    for i, line in enumerate(raw_lines):
        d = {"line": line, "env": None, "st": None, "rec": None, "ok": False}
        try:
            env, st, rec = dsse.decode_record_line(line)
            d.update(env=env, st=st, rec=rec, ok=True)
        except SchemaError as e:
            res.errors.append(_fat("E_SCHEMA", i, str(e)))
            d["line"] = None  # failed lines keep the zero value
        recs.append(d)
    res.stats["records"] = len(raw_lines)

    # V3 — signature under a trusted key, role match, validity window.
    for i, d in enumerate(recs):
        if not d["ok"]:
            continue
        err = _keys.verify_record(d["env"], d["rec"], trusted)
        if err is not None:
            code = "E_KEY" if err.startswith("E_KEY") else "E_SIG"
            res.errors.append(_fat(code, i, err))

    # V4 — subject digest and per-record session equal the manifest's.
    want_subj = hashlib.sha256(man["session"].encode("utf-8")).hexdigest()
    for i, d in enumerate(recs):
        if not d["ok"]:
            continue
        st = d["st"]
        if len(st["subject"]) != 1 or \
                (st["subject"][0]["digest"] or {}).get("sha256") != want_subj:
            dig = ""
            if st["subject"]:
                dig = (st["subject"][0]["digest"] or {}).get("sha256", "")
            res.errors.append(_fat("E_SESSION", i,
                                   "subject digest %s ≠ bundle session"
                                   % _quote(dig)))
        if d["rec"]["session"] != man["session"]:
            res.errors.append(_fat("E_SESSION", i,
                                   "record session %s ≠ %s"
                                   % (_quote(d["rec"]["session"]),
                                      _quote(man["session"]))))

    # V5 — per-emitter chains.
    heads = {}
    order = []
    for i, d in enumerate(recs):
        if not d["ok"]:
            continue
        r = d["rec"]
        em = r["emitter"]
        h = heads.get(em)
        if h is None:
            h = {"eseq": 0, "hash": "", "records": 0}
            heads[em] = h
            order.append(em)
            if r["eseq"] != 0:
                res.errors.append(_fat("E_CHAIN", i,
                                       "%s: first eseq is %d, want 0"
                                       % (em, r["eseq"])))
                continue
            if r["eprev"] != dsse.ZERO_HASH:
                res.errors.append(_fat("E_CHAIN", i,
                                       "%s: first eprev is not 64 zeros"
                                       % em))
                continue
        else:
            if r["eseq"] != h["eseq"] + 1:
                res.errors.append(_fat("E_CHAIN", i,
                                       "%s: eseq gap or reuse at %d after %d"
                                       % (em, r["eseq"], h["eseq"])))
                continue
            if r["eprev"] != h["hash"]:
                res.errors.append(_fat("E_CHAIN", i,
                                       "%s: eprev mismatch at eseq %d"
                                       % (em, r["eseq"])))
                continue
        h["eseq"] = r["eseq"]
        h["hash"] = dsse.record_hash(d["env"])
        h["records"] += 1
    res.stats["emitters"] = len(heads)

    # V6 — checkpoint signed by a log key; origin matches log_origin.
    cp, cp_err = note.parse_checkpoint(members["checkpoint.txt"], trusted)
    if cp_err is not None:
        res.errors.append(_f("E_CHECKPOINT", cp_err))
    elif cp["origin"] != man["log_origin"]:
        res.errors.append(_f("E_CHECKPOINT", "origin %s ≠ %s"
                             % (_quote(cp["origin"]),
                                _quote(man["log_origin"]))))
    if cp is not None:
        res.stats["tree_size"] = cp["size"]

    # V7 — inclusion proofs; log_index strictly increasing.
    try:
        ix = _bundle.parse_index(members["index.json"])
    except _bundle.BundleError as e:
        res.errors.append(_f("E_BUNDLE", str(e)))
        ix = None
    if ix is not None:
        if len(ix) != len(raw_lines):
            res.errors.append(_f("E_BUNDLE",
                                 "index.json has %d entries for %d records"
                                 % (len(ix), len(raw_lines))))
        else:
            prev = -1
            for i, e in enumerate(ix):
                if e["log_index"] <= prev:
                    res.errors.append(_fat("E_INCLUSION", i,
                                           "log_index %d not strictly "
                                           "increasing" % e["log_index"]))
                prev = e["log_index"]
                if cp is None:
                    continue
                if e["log_index"] >= cp["size"]:
                    res.errors.append(_fat("E_INCLUSION", i,
                                           "log_index %d ≥ checkpoint "
                                           "size %d"
                                           % (e["log_index"], cp["size"])))
                    continue
                leaf = mlog.leaf_hash(recs[i]["line"] or b"")
                perr = mlog.inclusion_error(e["log_index"], cp["size"],
                                            leaf, e["proof"], cp["root"])
                if perr is not None:
                    res.errors.append(_fat("E_INCLUSION", i, perr))

    # V8 — first record is session.open; policy and contracts match digests.
    sealed = False
    open_body = None
    if len(recs) == 0 or not recs[0]["ok"] or \
            recs[0]["rec"]["type"] != "session.open":
        res.errors.append(_f("E_OPEN", "first record is not session.open"))
    else:
        open_body = recs[0]["rec"]["body"]
    if open_body is not None:
        pol = members.get("policy.yaml")
        if pol is None or \
                hashlib.sha256(pol).hexdigest() != open_body["policy_digest"]:
            res.errors.append(_f("E_POLICY",
                                 "policy.yaml digest ≠ policy_digest %s"
                                 % open_body["policy_digest"]))
        contract_files = sorted(n for n in members
                                if n.startswith("contracts/"))
        got = [hashlib.sha256(members[n]).hexdigest()
               for n in contract_files]
        want = sorted(open_body["contract_digests"] or [])
        if got != want:
            res.errors.append(_f("E_POLICY", "contract digests %s ≠ %s"
                                 % ("[" + " ".join(got) + "]",
                                    "[" + " ".join(want) + "]")))

    # V9 — world.closed exists, then session.seal as the last controller
    # record. Otherwise verdict UNSEALED (not an error).
    seal_body = None
    world_closed = False
    last_ctrl = -1
    for i, d in enumerate(recs):
        if not d["ok"]:
            continue
        try:
            role, _ = dsse.emitter_role(d["rec"]["emitter"])
        except ValueError:
            role = ""
        if role == "controller":
            last_ctrl = i
        if d["rec"]["type"] == "world.closed":
            world_closed = True
            res.world = d["rec"]["body"]["outcome"]
    seal_rec = None
    if last_ctrl >= 0 and recs[last_ctrl]["rec"]["type"] == "session.seal":
        seal_body = recs[last_ctrl]["rec"]["body"]
        seal_rec = recs[last_ctrl]["rec"]
    sealed = world_closed and seal_body is not None

    # V10 — for each emitter in the seal: final_eseq and head_hash equal the
    # chain's head; no emitter missing; nothing after a sealed head.
    if seal_body is not None:
        claimed = {}
        for se in seal_body["emitters"] or []:
            claimed[se["emitter"]] = True
            h = heads.get(se["emitter"])
            if h is None:
                res.errors.append(_f("E_SEAL",
                                     "seal claims unknown emitter %s"
                                     % se["emitter"]))
                continue
            # The sealing emitter cannot carry its own record hash inside
            # the seal; its entry describes the chain head immediately
            # before session.seal.
            if se["emitter"] == seal_rec["emitter"]:
                if se["final_eseq"] + 1 != h["eseq"] or \
                        se["head_hash"].lower() != seal_rec["eprev"].lower():
                    res.errors.append(
                        _f("E_SEAL",
                           "sealer head %s eseq %d hash %s ≠ pre-seal %d %s"
                           % (se["emitter"], se["final_eseq"],
                              se["head_hash"], h["eseq"],
                              seal_rec["eprev"])))
                continue
            if se["final_eseq"] != h["eseq"] or \
                    se["head_hash"].lower() != h["hash"].lower():
                res.errors.append(
                    _f("E_SEAL",
                       "seal head %s eseq %d hash %s ≠ chain %d %s"
                       % (se["emitter"], se["final_eseq"], se["head_hash"],
                          h["eseq"], h["hash"])))
        for e in order:
            if e not in claimed:
                res.errors.append(_f("E_SEAL",
                                     "emitter %s missing from session.seal"
                                     % e))

    # V11 — structure rules of 03 §4.5 in log order.
    res.errors.extend(_verify_structure(recs))

    # V15 — warnings.
    res.warnings = _verify_warnings(recs, seal_body)

    res.sealed = sealed
    res.learn = open_body is not None and open_body["mode"] == "learn"
    res.denied = _has_denial(recs)
    return _emit(res)


def _dump(res):
    """json.MarshalIndent(v, "", "  ") equivalent incl. HTML escaping."""
    s = json.dumps(res, ensure_ascii=False, indent=2,
                   separators=(",", ": "))
    # Go escapes < > & U+2028 U+2029 inside strings; outside strings these
    # bytes can only appear inside a string value anyway.
    return (s.replace("&", "\\u0026").replace("<", "\\u003c")
             .replace(">", "\\u003e")
             .replace(" ", "\\u2028").replace(" ", "\\u2029"))


def main(argv=None):
    import argparse
    import sys
    ap = argparse.ArgumentParser(prog="refverify")
    ap.add_argument("bundle")
    ap.add_argument("--keys", required=True)
    args = ap.parse_args(argv)
    try:
        with open(args.keys, "rb") as f:
            trusted = _keys.unmarshal_manifest(f.read())
    except OSError as e:
        sys.stderr.write("%s\n" % e)
        return 2
    except _keys.KeysError as e:
        sys.stderr.write("%s\n" % e)
        return 2
    try:
        with open(args.bundle, "rb") as f:
            data = f.read()
    except OSError as e:
        sys.stderr.write("%s\n" % e)
        return 2
    res = verify_bundle(data, trusted)
    sys.stdout.write(_dump(res) + "\n")
    return 0 if res["verdict"] in ("CLEAN", "CLEAN_WITH_DENIALS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
