# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""The verifier algorithm: V1–V11 and V15 of spec 03 §10.

Output object (same schema as csverify):
    {"verdict", "world", "errors", "warnings", "findings", "stats"}
Verdicts, most severe first: INVALID (any E_*) → UNSEALED → LEARN →
VIOLATIONS → CLEAN_WITH_DENIALS → CLEAN. A bundle with no seal is never CLEAN.
"""
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import bundle as bund
from . import dsse
from . import keys as keysmod
from . import mlog
from . import note as notemod
from . import schema
from . import strict
from .errors import VerifyError, err_obj

EFFECT_TYPES = {"effect.http", "effect.tunnel"}
RESULT_OF = {"effect.http": "effect.http.result",
             "effect.tunnel": "effect.tunnel.result"}


def _sha(b):
    return hashlib.sha256(b).digest()


class Rec:
    """A parsed record: envelope, statement and predicate fields."""

    __slots__ = ("pos", "line", "payload", "keyid", "sig", "rtype", "role",
                 "emitter", "eseq", "eprev", "id", "session", "ts", "ts_str",
                 "body", "rh", "subj")

    def __init__(self, pos, line, payload, keyid, sig, st, pred, val):
        self.pos = pos
        self.line = line
        self.payload = payload
        self.keyid = keyid
        self.sig = sig
        self.rtype, self.role, self.eseq, self.eprev, self.ts, self.body = val
        self.emitter = pred["emitter"]
        self.id = pred["id"]
        self.session = pred["session"]
        self.ts_str = pred["ts"]
        self.rh = dsse.record_hash(dsse.PAYLOAD_TYPE, payload)
        self.subj = st["subject"][0]


def verify(members, trusted_keys):
    """Run V1–V11 + V15 over parsed bundle members and the trusted manifest.
    Returns the output dict."""
    errors = []
    warnings = []

    def err(code, detail, record=None, entry=None):
        errors.append(err_obj(code, detail, record, entry))

    def warn(code, detail, record=None):
        warnings.append(err_obj(code, detail, record))

    # ---------------------------------------------------------- V1
    # member names/required members already enforced by bundle.read()
    manifest = strict.loads(members["manifest.json"], "manifest.json",
                            code="E_BUNDLE")
    if not isinstance(manifest, dict):
        raise VerifyError("E_BUNDLE", "manifest.json: not an object")
    if set(manifest) != {"bundle_version", "session", "log_origin", "created"}:
        err("E_BUNDLE", f"manifest.json: keys {sorted(manifest)}")
    else:
        if manifest["bundle_version"] != 1:
            err("E_BUNDLE", "manifest: bundle_version != 1")
        if not isinstance(manifest.get("session"), str) or \
                not manifest["session"]:
            err("E_BUNDLE", "manifest: session missing")
        if not isinstance(manifest.get("log_origin"), str) or \
                not manifest["log_origin"]:
            err("E_BUNDLE", "manifest: log_origin missing")
    sid = manifest.get("session", "") if isinstance(manifest, dict) else ""
    origin = manifest.get("log_origin", "") if isinstance(manifest, dict) \
        else ""

    bundle_keys = {}
    try:
        bundle_keys = keysmod.parse_manifest(
            strict.loads(members["keys.json"], "keys.json", code="E_BUNDLE"),
            "bundle keys.json")
    except VerifyError as e:
        err(e.code, e.detail)

    lines = bund.records_lines(members["records.jsonl"])

    # ---------------------------------------------------------- V2
    recs = []          # Rec objects that parsed cleanly
    for pos, line in enumerate(lines):
        try:
            payload, keyid, sig = dsse.parse_envelope(line, pos)
            st = dsse.parse_statement(payload, pos)
            pred = st["predicate"]
            val = schema.validate(pred, pos)
            recs.append(Rec(pos, line, payload, keyid, sig, st, pred, val))
        except VerifyError as e:
            err(e.code, e.detail, pos)

    # ---------------------------------------------------------- V3
    def trusted(kid):
        return trusted_keys.get(kid)

    for r in recs:
        ent = trusted(r.keyid)
        if ent is None:
            err("E_KEY", f"keyid {r.keyid} not in trusted manifest", r.pos)
            continue
        bk = bundle_keys.get(r.keyid)
        if bk is not None and not bk.same_as(ent):
            err("E_KEY",
                f"bundle keys.json entry for {r.keyid} differs from trusted "
                "manifest", r.pos)
        if ent.role != f"emitter:{r.role}":
            err("E_KEY",
                f"key {r.keyid} role {ent.role} does not match emitter role "
                f"{r.role}", r.pos)
            continue
        if not ent.covers(r.ts):
            err("E_KEY",
                f"key {r.keyid} validity does not cover ts {r.ts_str}", r.pos)
            continue
        try:
            Ed25519PublicKey.from_public_bytes(ent.pub).verify(
                r.sig, dsse.pae(dsse.PAYLOAD_TYPE, r.payload))
        except InvalidSignature:
            err("E_SIG", "signature verification failed", r.pos)
        except ValueError as e:
            err("E_KEY", f"bad public key for {r.keyid}: {e}", r.pos)

    # ---------------------------------------------------------- V4
    for r in recs:
        if r.session != sid:
            err("E_SESSION",
                f"record session {r.session!r} != manifest {sid!r}", r.pos)
        want = f"countersign:session:{sid}"
        if r.subj["name"] != want:
            err("E_SESSION", f"subject name {r.subj['name']!r} != {want!r}",
                r.pos)
        if r.subj["digest"]["sha256"] != \
                hashlib.sha256(sid.encode()).hexdigest():
            err("E_SESSION", "subject digest != sha256(session)", r.pos)

    # ---------------------------------------------------------- V5
    chains = {}                    # emitter -> [Rec]
    seen_ids = {}
    for r in recs:
        if r.id in seen_ids:
            err("E_CHAIN", f"duplicate record id {r.id} "
                f"(records {seen_ids[r.id]} and {r.pos})", r.pos)
        else:
            seen_ids[r.id] = r.pos
        ch = chains.setdefault(r.emitter, [])
        if r.eseq != len(ch):
            err("E_CHAIN",
                f"{r.emitter}: eseq {r.eseq} at position {len(ch)} (gap or "
                "reorder)", r.pos)
        if r.eseq == 0:
            if r.eprev != "0" * 64:
                err("E_CHAIN", f"{r.emitter}: eprev at eseq 0 not 64 zeros",
                    r.pos)
        elif ch and r.eprev != ch[-1].rh:
            err("E_CHAIN", f"{r.emitter}: eprev does not match previous "
                "record hash", r.pos)
        ch.append(r)

    # ---------------------------------------------------------- V6
    cp_size = cp_root = None
    try:
        text, sigs = notemod.parse(members["checkpoint.txt"])
        o, cp_size, cp_root, _ext = notemod.parse_checkpoint_body(text)
        if o != origin.encode():
            err("E_CHECKPOINT",
                f"checkpoint origin {o!r} != manifest log_origin {origin!r}")
        keytab = {origin.encode(): [
            (notemod.note_key_id(origin.encode(), 0x01, k.pub), k.pub, k.role)
            for k in trusted_keys.values()]}
        roles = notemod.verify_text(text, sigs, keytab)
        if roles is None:
            err("E_CHECKPOINT", "no trusted checkpoint signature verifies")
        else:
            if "log" not in roles:
                err("E_CHECKPOINT", "checkpoint not signed by a log key")
            for rl in roles:
                if rl.startswith("emitter:") or rl == "attestor":
                    err("E_CHECKPOINT",
                        f"checkpoint signed by a {rl} key")
                    break
    except VerifyError as e:
        err("E_CHECKPOINT", e.detail)

    # ---------------------------------------------------------- V7
    idx = None
    try:
        idx = strict.loads(members["index.json"], "index.json", code="E_BUNDLE")
        if not isinstance(idx, list):
            raise VerifyError("E_BUNDLE", "index.json: not an array")
        for i, e in enumerate(idx):
            if not isinstance(e, dict) or set(e) != {"log_index",
                                                   "inclusion_proof"}:
                raise VerifyError("E_BUNDLE",
                                  f"index.json[{i}]: keys must be "
                                  "log_index+inclusion_proof")
            if not isinstance(e["log_index"], int) or \
                    isinstance(e["log_index"], bool) or e["log_index"] < 0:
                raise VerifyError("E_BUNDLE",
                                  f"index.json[{i}]: bad log_index")
            if not isinstance(e["inclusion_proof"], list) or \
                    not all(strict.is_hex(p, 64) for p in e["inclusion_proof"]):
                raise VerifyError("E_BUNDLE",
                                  f"index.json[{i}]: bad inclusion_proof")
    except VerifyError as e:
        err(e.code, e.detail)
        idx = None
    if idx is not None and cp_root is not None and cp_size is not None:
        if len(idx) != len(lines):
            err("E_INCLUSION",
                f"index.json has {len(idx)} proofs for {len(lines)} records")
        prev = -1
        for i, e in enumerate(idx[:len(lines)]):
            leaf = mlog.leaf_hash(lines[i])
            proof = [bytes.fromhex(p) for p in e["inclusion_proof"]]
            if e["log_index"] <= prev:
                err("E_INCLUSION",
                    f"log_index not strictly increasing at entry {i}")
            prev = e["log_index"]
            if not mlog.verify_inclusion(leaf, e["log_index"], cp_size,
                                         proof, cp_root):
                err("E_INCLUSION",
                    f"inclusion proof for record {i} (log_index "
                    f"{e['log_index']}) fails")

    # ---------------------------------------------------------- V8
    open_rec = recs[0] if recs and recs[0].pos == 0 and \
        recs[0].rtype == "session.open" else None
    if open_rec is None:
        err("E_OPEN", "first record is not session.open")
    if open_rec is not None:
        pol = members.get("policy.yaml")
        if pol is None:
            err("E_POLICY", "policy.yaml absent")
        elif open_rec.body["policy_digest"] != hashlib.sha256(pol).hexdigest():
            err("E_POLICY", "policy.yaml digest != session.open.policy_digest")
        want = sorted(open_rec.body["contract_digests"])
        got = sorted(hashlib.sha256(v).hexdigest()
                     for k, v in members.items() if k.startswith("contracts/"))
        if want != got:
            err("E_POLICY", "contracts/*.yaml digests != contract_digests")

    # ---------------------------------------------------------- V9 / V10
    world_closed = [r for r in recs if r.rtype == "world.closed"]
    world_outcome = world_closed[-1].body["outcome"] if world_closed else None
    ctrl = [r for r in recs if r.role == "controller"]
    seal = ctrl[-1] if ctrl and ctrl[-1].rtype == "session.seal" else None
    sealed = bool(seal and any(w.pos < seal.pos for w in world_closed))
    if seal:
        # The sealing emitter cannot list its own chain head: the seal's
        # record hash covers emitters[], so its head is the last record it
        # wrote *before* the seal. Other emitters' heads are their last
        # records outright (and nothing may follow a sealed head).
        declared = {e["emitter"]: e for e in seal.body["emitters"]}
        for name, e in declared.items():
            ch = chains.get(name)
            if not ch:
                err("E_SEAL", f"seal lists {name} but it has no records")
                continue
            if name == seal.emitter:
                before = [r for r in ch if r.pos < seal.pos]
                if not before:
                    err("E_SEAL", f"sealer {name} has no record before "
                        "the seal")
                    continue
                head = before[-1]
            else:
                head = ch[-1]
                beyond = [r for r in ch if r.eseq > e["final_eseq"]]
                if beyond:
                    err("E_SEAL", f"{name}: record after sealed head",
                        beyond[0].pos)
            if head.eseq != e["final_eseq"] or head.rh != e["head_hash"]:
                err("E_SEAL",
                    f"seal head for {name} does not match the chain head",
                    head.pos)
        for name in chains:
            if name != seal.emitter and name not in declared:
                err("E_SEAL", f"emitter {name} missing from the seal")

    # ---------------------------------------------------------- V11
    _structure(recs, err)

    # ---------------------------------------------------------- V15
    _warnings(recs, seal, warn)

    # ---------------------------------------------------------- verdict
    denials = sum(1 for r in recs
                  if r.rtype == "effect.denied" or
                  (r.rtype in EFFECT_TYPES and
                   r.body.get("decision", {}).get("action") == "deny"))
    if errors:
        verdict = "INVALID"
    elif not sealed:
        verdict = "UNSEALED"
    elif open_rec is not None and open_rec.body.get("mode") == "learn":
        verdict = "LEARN"
    elif denials:
        verdict = "CLEAN_WITH_DENIALS"
    else:
        verdict = "CLEAN"
    return {"verdict": verdict,
            "world": world_outcome,
            "errors": errors,
            "warnings": warnings,
            "findings": [],
            "stats": {"records": len(lines), "emitters": len(chains),
                      "denials": denials,
                      "tree_size": cp_size}}


def _structure(recs, err):
    """V11: references resolve to earlier records of the right type; ordering
    rules of §4.5 hold in log order."""
    ids = {}        # id -> (pos, kind)
    result_pos = {} # effect_id -> pos of its result
    by_pos = {r.pos: r for r in recs}

    def reg(id_, pos, kind):
        if id_:
            ids.setdefault(id_, (pos, kind))

    for r in recs:
        b = r.body
        if r.rtype in EFFECT_TYPES:
            reg(b["effect_id"], r.pos, r.rtype)
        elif r.rtype == "effect.exec":
            reg(b["exec_id"], r.pos, "effect.exec")
        elif r.rtype == "intent.declared":
            reg(b["intent_id"], r.pos, "intent.declared")
        elif r.rtype == "stage.entry":
            reg(b["entry_id"], r.pos, "stage.entry")
        elif r.rtype == "commit.requested":
            reg(b["commit_id"], r.pos, "commit.requested")
        elif r.rtype == "undo.requested":
            reg(b["undo_id"], r.pos, "undo.requested")
        elif r.rtype == "mcp.call.begin":
            reg(b["call_id"], r.pos, "mcp.call.begin")

    def ref(r, id_, kinds, what):
        got = ids.get(id_)
        if got is None:
            err("E_STRUCTURE", f"{r.rtype}: {what} {id_!r} not found", r.pos)
            return None
        pos, kind = got
        if pos >= r.pos:
            err("E_STRUCTURE",
                f"{r.rtype}: {what} {id_!r} does not precede it", r.pos)
            return None
        if kind not in kinds:
            err("E_STRUCTURE",
                f"{r.rtype}: {what} {id_!r} is {kind}, want {sorted(kinds)}",
                r.pos)
            return None
        return by_pos[pos]

    effects = {}
    for r in recs:
        if r.rtype in EFFECT_TYPES:
            effects[r.body["effect_id"]] = r

    seen_res = set()
    for r in recs:
        b, t = r.body, r.rtype
        if t in ("effect.http.result", "effect.tunnel.result"):
            eff_type = "effect.http" if t.startswith("effect.http") \
                else "effect.tunnel"
            e = ref(r, b["effect_id"], {eff_type}, "effect_id")
            if b["effect_id"] in seen_res:
                err("E_STRUCTURE",
                    f"second result for effect {b['effect_id']}", r.pos)
            seen_res.add(b["effect_id"])
            if e is not None:
                result_pos[b["effect_id"]] = r.pos
        elif t == "intent.result":
            ref(r, b["intent_id"], {"intent.declared"}, "intent_id")
            ref(r, b["via_effect"], EFFECT_TYPES, "via_effect")
        elif t == "intent.declared":
            ref(r, b["via_effect"], EFFECT_TYPES, "via_effect")
        elif t == "intent.unparsed":
            ref(r, b["via_effect"], EFFECT_TYPES, "via_effect")
        elif t == "context.observed":
            ref(r, b["via_effect"], EFFECT_TYPES, "via_effect")
            for nb in b["new_blocks"]:
                if nb.get("intent_id") is not None:
                    ref(r, nb["intent_id"], {"intent.declared"},
                        "new_blocks.intent_id")
        elif t == "taint.added":
            if b.get("source_effect") is not None:
                ref(r, b["source_effect"], EFFECT_TYPES, "source_effect")
        elif t == "mcp.call.end":
            ref(r, b["call_id"], {"mcp.call.begin"}, "call_id")
        elif t == "effect.connect":
            ref(r, b["exec_id"], {"effect.exec"}, "exec_id")
        elif t == "effect.exec":
            if b.get("parent_exec_id") is not None:
                ref(r, b["parent_exec_id"], {"effect.exec"}, "parent_exec_id")
        elif t == "stage.entry":
            foreign = b.get("via_session") is not None and \
                b["via_session"] != r.session
            if not foreign:
                ref(r, b["via_effect"], EFFECT_TYPES, "via_effect")
            if b.get("supersedes") is not None:
                ref(r, b["supersedes"], {"stage.entry"}, "supersedes")
        elif t == "prestate.captured":
            foreign = b.get("for_session") is not None and \
                b["for_session"] != r.session
            if not foreign:
                ref(r, b["for_effect"], EFFECT_TYPES, "for_effect")
                ref(r, b["via_effect"], EFFECT_TYPES, "via_effect")
        elif t == "commit.requested":
            for en in b["entries"]:
                ref(r, en, {"stage.entry"}, "entries[]")
        elif t == "commit.decision":
            ref(r, b["commit_id"], {"commit.requested"}, "commit_id")
        elif t == "commit.applied":
            ref(r, b["commit_id"], {"commit.requested"}, "commit_id")
            ref(r, b["entry_id"], {"stage.entry"}, "entry_id")
            if b.get("via_effect") is not None:
                ref(r, b["via_effect"], EFFECT_TYPES, "via_effect")
        elif t == "commit.closed":
            ref(r, b["commit_id"], {"commit.requested"}, "commit_id")
        elif t == "probation.ratified":
            ref(r, b["commit_id"], {"commit.requested"}, "commit_id")
        elif t == "attestation.issued":
            ref(r, b["commit_id"], {"commit.requested"}, "commit_id")
            ref(r, b["entry_id"], {"stage.entry"}, "entry_id")
        elif t == "undo.requested":
            for tg in b["targets"]:
                if b["scope"] == "commit":
                    ref(r, tg, {"commit.requested"}, "targets[]")
                elif b["scope"] == "effect":
                    ref(r, tg, EFFECT_TYPES, "targets[]")
        elif t == "undo.applied":
            ref(r, b["undo_id"], {"undo.requested"}, "undo_id")
            if ids.get(b["target"]) is None:
                err("E_STRUCTURE",
                    f"undo.applied: target {b['target']!r} not found", r.pos)
            if b.get("via_effect") is not None:
                ref(r, b["via_effect"], EFFECT_TYPES, "via_effect")
        elif t == "undo.closed":
            ref(r, b["undo_id"], {"undo.requested"}, "undo_id")
        elif t == "world.closed":
            for c in b["commits"]:
                ref(r, c, {"commit.requested"}, "commits[]")
        elif t == "world.rewound":
            for en in b["dropped_entries"]:
                ref(r, en, {"stage.entry"}, "dropped_entries[]")
            if b.get("undo_id") is not None:
                ref(r, b["undo_id"], {"undo.requested"}, "undo_id")
        elif t == "effect.http" and b.get("for") is not None:
            tgt = ids.get(b["for"])
            if tgt is None:
                err("E_STRUCTURE",
                    f"effect.http: 'for' {b['for']!r} not found", r.pos)
            elif tgt[0] >= r.pos:
                err("E_STRUCTURE",
                    f"effect.http: 'for' {b['for']!r} does not precede it",
                    r.pos)
            elif tgt[1] not in ("stage.entry", "effect.http", "effect.tunnel"):
                err("E_STRUCTURE",
                    f"effect.http: 'for' {b['for']!r} is {tgt[1]}, want "
                    "entry or effect", r.pos)

    # ---- ordering rules of §4.5 in log order ----
    emitter_sealed = set()
    for r in recs:
        if r.emitter in emitter_sealed:
            err("E_STRUCTURE",
                f"record by {r.emitter} after its emitter.seal", r.pos)
        if r.rtype == "emitter.seal":
            emitter_sealed.add(r.emitter)

    for r in recs:
        b = r.body
        if r.rtype == "intent.declared":
            rp = result_pos.get(b["via_effect"])
            if rp is not None and r.pos > rp:
                err("E_STRUCTURE",
                    "intent.declared after the result of its via_effect",
                    r.pos)
        elif r.rtype == "taint.added":
            se = b.get("source_effect")
            rp = result_pos.get(se)
            if se is not None and rp is not None and r.pos > rp:
                err("E_STRUCTURE",
                    "taint.added after the result of its source_effect",
                    r.pos)
        elif r.rtype == "stage.entry" and \
                not (b.get("via_session") is not None and
                     b["via_session"] != r.session):
            rp = result_pos.get(b["via_effect"])
            if rp is not None and r.pos > rp:
                err("E_STRUCTURE",
                    "stage.entry after the result of its via_effect", r.pos)
        elif r.rtype == "prestate.captured" and b["when"] == "before" and \
                not (b.get("for_session") is not None and
                     b["for_session"] != r.session):
            fe = ids.get(b["for_effect"])
            if fe is not None and r.pos <= fe[0]:
                err("E_STRUCTURE",
                    "prestate.captured{before} not after its for_effect",
                    r.pos)
            rp = result_pos.get(b["for_effect"])
            if rp is not None and r.pos > rp:
                err("E_STRUCTURE",
                    "prestate.captured{before} after the result of its "
                    "for_effect", r.pos)
        elif r.rtype == "commit.applied" and b.get("via_effect") is not None:
            rp = result_pos.get(b["via_effect"])
            if rp is None:
                err("E_STRUCTURE",
                    "commit.applied: apply effect has no result", r.pos)
            elif r.pos < rp:
                err("E_STRUCTURE",
                    "commit.applied before the result of its apply effect",
                    r.pos)

    # decision before apply: each effect.http{purpose: apply} must follow a
    # commit.decision for the commit whose request contains its `for` entry.
    reqs = [r for r in recs if r.rtype == "commit.requested"]
    decisions = [r for r in recs if r.rtype == "commit.decision"]
    for r in recs:
        if not (r.rtype == "effect.http" and r.body.get("purpose") == "apply"
                and r.body.get("for") is not None):
            continue
        entry = r.body["for"]
        cands = [q for q in reqs if entry in q.body["entries"]
                 and q.pos < r.pos]
        if not cands:
            err("E_STRUCTURE",
                f"apply effect {r.body['effect_id']}: no commit.requested "
                f"for entry {entry!r} precedes it", r.pos)
            continue
        req = cands[-1]
        ok = any(d.pos > req.pos and d.pos < r.pos and
                 d.body["decision"] == "commit"
                 for d in decisions if d.body["commit_id"] ==
                 req.body["commit_id"])
        if not ok:
            err("E_STRUCTURE",
                f"apply effect {r.body['effect_id']}: no commit.decision "
                "before it", r.pos)


def _warnings(recs, seal, warn):
    """V15 warning conditions."""
    results = {r.body["effect_id"] for r in recs
               if r.rtype in ("effect.http.result", "effect.tunnel.result")}
    for r in recs:
        if r.rtype in EFFECT_TYPES and r.body["effect_id"] not in results:
            warn("W_DANGLING", f"effect {r.body['effect_id']} has no result",
                 r.pos)
        elif r.rtype == "observer.gap":
            warn("W_OBSERVER_GAP", "observer.gap present", r.pos)
        elif r.rtype == "intent.unparsed":
            warn("W_UNPARSED", "intent.unparsed present", r.pos)
        elif r.rtype == "commit.closed" and r.body["outcome"] == "partial":
            warn("W_PARTIAL_COMMIT", "commit closed partial", r.pos)
        elif r.rtype == "commit.applied" and r.body["outcome"] == "unknown":
            warn("W_APPLY_UNKNOWN", "apply outcome unknown", r.pos)
        elif r.rtype == "undo.applied" and r.body["outcome"] == "conflict":
            warn("W_UNDO_CONFLICT", "undo applied with conflict", r.pos)
    if seal:
        for e in seal.body["emitters"]:
            if not e["clean"]:
                warn("W_UNCLEAN_EMITTER",
                     f"emitter {e['emitter']} sealed unclean")


def run(bundle_path, keys_path):
    """Verify a bundle file against a trusted manifest file → output dict.
    Raises UsageError for unreadable inputs."""
    try:
        members = bund.read(bundle_path)
    except VerifyError as e:
        return {"verdict": "INVALID", "world": None,
                "errors": [e.obj()], "warnings": [], "findings": [],
                "stats": {"records": 0, "emitters": 0, "denials": 0,
                          "tree_size": None}}
    try:
        with open(keys_path, "rb") as f:
            kobj = strict.loads(f.read(), "trusted keys", code="E_KEY")
        trusted = keysmod.parse_manifest(kobj, "trusted keys")
    except VerifyError as e:
        return {"verdict": "INVALID", "world": None,
                "errors": [e.obj()], "warnings": [], "findings": [],
                "stats": {"records": 0, "emitters": 0, "denials": 0,
                          "tree_size": None}}
    try:
        return verify(members, trusted)
    except VerifyError as e:
        return {"verdict": "INVALID", "world": None,
                "errors": [e.obj()], "warnings": [], "findings": [],
                "stats": {"records": 0, "emitters": 0, "denials": 0,
                          "tree_size": None}}
