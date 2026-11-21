# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""Derived bundle vectors for C1.5.5 — every error code, warning and verdict
of spec 03 §10 built from scratch with genbundle (spec-derived, lane-local).

Each case returns (name, expected_verdict, expected_error_codes,
expected_warning_codes). Bundles land under a tmp dir as <name>.tar plus
<name>.keys.json (trusted manifest) unless the case overrides the manifest.
"""
import json
import os

import genbundle as G


def line_for(files, pred):
    out = []
    for l in files["records.jsonl"].split(b"\n"):
        if l and pred(json.loads(l)):
            out.append(l)
    return out


def setlines(files, lines):
    files["records.jsonl"] = b"".join(l + b"\n" for l in lines)


def all_lines(files):
    return [l for l in files["records.jsonl"].split(b"\n") if l]


def base():
    """The reference clean session."""
    s = G.Session()
    s.open()
    s.effect(1)
    s.effect(2)
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s


def base_files():
    s = base()
    return s, s.files()


CASES = []


def case(name, verdict, errors=frozenset(), warnings=frozenset()):
    def deco(fn):
        CASES.append((name, verdict, frozenset(errors), frozenset(warnings), fn))
        return fn
    return deco


# ---------------------------------------------------------------- verdicts
@case("clean-minimal", "CLEAN")
def _(tmp):
    return base_files()


@case("clean-multi-emitter", "CLEAN")
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1)
    s.emit("observer", "effect.exec", {
        "exec_id": "ex1", "pid": 7, "binary": "/bin/sh",
        "argv_sha256": [G.sha_hex(b"-c")], "argv_truncated": False,
        "uid": 1000})
    s.emit("observer", "effect.connect", {
        "exec_id": "ex1", "pid": 7,
        "dst": {"ip": "10.0.0.10", "port": 3128},
        "src_port": 40001, "proto": "tcp", "outcome": "to-broker"})
    e2 = s.effect(2, result=False)
    s.emit("world", "prestate.captured", {
        "for_effect": e2, "when": "before", "via_effect": e2,
        "status": 200, "state_sha256": G.sha_hex(b"s"), "len": 3})
    s.effect_result(e2)
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("clean-with-denials", "CLEAN_WITH_DENIALS", warnings={"W_DANGLING"})
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1, result=False)          # dangling
    s.denied()
    s.effect(2, action="deny", result=True)
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("verdict-unsealed-no-seal", "UNSEALED")
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1)
    s.close_world()
    s.emitter_seals()
    return s, s.files()


@case("verdict-unsealed-no-world-closed", "UNSEALED")
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1)
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("verdict-learn", "LEARN")
def _(tmp):
    s = G.Session(mode="learn")
    s.open()
    s.effect(1)
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("verdict-invalid-beats-unsealed", "INVALID", errors={"E_CHAIN"})
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1)
    # break the broker chain; never seal
    s.emit("broker", "effect.denied", {
        "conn_id": "c", "client": {"ip": "1.2.3.4", "port": 1},
        "reason": "NO_GRANT", "detail": "d"}, eseq=7)
    s.close_world()
    return s, s.files()


# ------------------------------------------------------------------ V1
@case("E_BUNDLE-missing-index", "INVALID", errors={"E_BUNDLE"})
def _(tmp):
    s, f = base_files()
    del f["index.json"]
    return s, f


@case("E_BUNDLE-extra-member", "INVALID", errors={"E_BUNDLE"})
def _(tmp):
    s, f = base_files()
    f["evil.txt"] = b"x"
    return s, f


@case("E_BUNDLE-missing-records", "INVALID", errors={"E_BUNDLE"})
def _(tmp):
    s, f = base_files()
    del f["records.jsonl"]
    return s, f


@case("E_BUNDLE-not-a-tar", "INVALID", errors={"E_BUNDLE"})
def _(tmp):
    s, f = base_files()
    return s, {"__raw__": b"this is not a tar archive"}


# ------------------------------------------------------------------ V2
def resign(env, st, key, ptype="application/vnd.in-toto+json"):
    """Re-encode a tampered statement and re-sign its envelope."""
    env["payload"] = G.b64e(G.jdumps(st))
    env["signatures"] = [{"keyid": key.key_id,
                          "sig": G.b64e(key.sign(G.pae(ptype, G.jdumps(st))))}]
    return env


@case("E_SCHEMA-unknown-predicate-field", "INVALID", errors={"E_SCHEMA", "E_INCLUSION"})
def _(tmp):
    s, f = base_files()
    lines = all_lines(f)
    env = json.loads(lines[-1])
    st = json.loads(G.base64.b64decode(env["payload"]))
    st["predicate"]["bogus"] = 1
    lines[-1] = G.jdumps(resign(env, st, s.keys["controller"]))
    setlines(f, lines)
    s.repack(f)
    return s, f


@case("E_SCHEMA-unknown-body-field", "INVALID", errors={"E_SCHEMA", "E_INCLUSION"})
def _(tmp):
    s, f = base_files()
    lines = all_lines(f)
    env = json.loads(lines[-1])
    st = json.loads(G.base64.b64decode(env["payload"]))
    st["predicate"]["body"]["bogus"] = 1
    lines[-1] = G.jdumps(resign(env, st, s.keys["controller"]))
    setlines(f, lines)
    s.repack(f)
    return s, f


@case("E_SCHEMA-unknown-type", "INVALID", errors={"E_SCHEMA", "E_CHAIN", "E_INCLUSION", "E_SEAL"})
def _(tmp):
    s = G.Session()
    s.open()
    s.emit("broker", "effect.unknown", {"x": 1})
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("E_SCHEMA-dup-json-key", "INVALID", errors={"E_SCHEMA", "E_INCLUSION"})
def _(tmp):
    s, f = base_files()
    lines = all_lines(f)
    env = json.loads(lines[-1])
    raw = b'{"payloadType":"application/vnd.in-toto+json",' + \
        b'"payload":"' + env["payload"].encode() + b'",' + \
        b'"payload":"' + env["payload"].encode() + b'",' + \
        b'"signatures":' + G.jdumps(env["signatures"]) + b'}'
    lines[-1] = raw
    setlines(f, lines)
    s.repack(f)
    return s, f


@case("E_SCHEMA-noncanonical-b64", "INVALID", errors={"E_SCHEMA", "E_INCLUSION"})
def _(tmp):
    s, f = base_files()
    lines = all_lines(f)
    env = json.loads(lines[-1])
    env["payload"] = env["payload"].rstrip("=")  # strip padding
    lines[-1] = G.jdumps(env)
    setlines(f, lines)
    s.repack(f)
    return s, f


@case("E_SCHEMA-two-signatures", "INVALID", errors={"E_SCHEMA", "E_INCLUSION"})
def _(tmp):
    s, f = base_files()
    lines = all_lines(f)
    env = json.loads(lines[-1])
    env["signatures"].append(env["signatures"][0])
    lines[-1] = G.jdumps(env)
    setlines(f, lines)
    s.repack(f)
    return s, f


@case("E_SCHEMA-zero-signatures", "INVALID", errors={"E_SCHEMA", "E_INCLUSION"})
def _(tmp):
    s, f = base_files()
    lines = all_lines(f)
    env = json.loads(lines[-1])
    env["signatures"] = []
    lines[-1] = G.jdumps(env)
    setlines(f, lines)
    s.repack(f)
    return s, f


@case("E_SCHEMA-wrong-payloadType", "INVALID", errors={"E_SCHEMA", "E_INCLUSION"})
def _(tmp):
    s, f = base_files()
    lines = all_lines(f)
    env = json.loads(lines[-1])
    env["payloadType"] = "application/json"
    st = G.base64.b64decode(env["payload"])
    env["signatures"] = [{"keyid": s.keys["controller"].key_id,
                          "sig": G.b64e(s.keys["controller"].sign(
                              G.pae("application/json", st)))}]
    lines[-1] = G.jdumps(env)
    setlines(f, lines)
    s.repack(f)
    return s, f


@case("E_SCHEMA-bad-payload-json", "INVALID", errors={"E_SCHEMA", "E_INCLUSION"})
def _(tmp):
    s, f = base_files()
    lines = all_lines(f)
    env = json.loads(lines[-1])
    env["payload"] = G.b64e(b"not json{")
    env["signatures"] = [{"keyid": s.keys["controller"].key_id,
                          "sig": G.b64e(s.keys["controller"].sign(
                              G.pae("application/vnd.in-toto+json",
                                    b"not json{")))}]
    lines[-1] = G.jdumps(env)
    setlines(f, lines)
    s.repack(f)
    return s, f


# ------------------------------------------------------------------ V3
@case("E_SIG-payload-bitflip", "INVALID", errors={"E_SIG"})
def _(tmp):
    s, f = base_files()
    lines = all_lines(f)
    env = json.loads(lines[-1])
    pl = G.base64.b64decode(env["payload"])
    i = pl.index(b"session end")
    pl = pl[:i] + b"session enx" + pl[i + 11:]
    env["payload"] = G.b64e(pl)
    lines[-1] = G.jdumps(env)
    setlines(f, lines)
    s.repack(f)
    return s, f


@case("E_SIG-sig-bitflip", "INVALID", errors={"E_SIG"})
def _(tmp):
    s, f = base_files()
    lines = all_lines(f)
    env = json.loads(lines[-1])
    sg = bytearray(G.base64.b64decode(env["signatures"][0]["sig"]))
    sg[3] ^= 0x01
    env["signatures"][0]["sig"] = G.b64e(bytes(sg))
    lines[-1] = G.jdumps(env)
    setlines(f, lines)
    s.repack(f)
    return s, f


@case("E_KEY-unknown-keyid", "INVALID", errors={"E_KEY"})
def _(tmp):
    s = G.Session()
    s.open()
    s.emit("broker", "effect.denied", {
        "conn_id": "c", "client": {"ip": "1.2.3.4", "port": 1},
        "reason": "NO_GRANT", "detail": "d"}, key=G.KeyPair(b"attacker"))
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("E_KEY-role-mismatch", "INVALID", errors={"E_KEY"})
def _(tmp):
    s = G.Session()
    s.open()
    # broker record signed by the world emitter key
    s.emit("broker", "effect.denied", {
        "conn_id": "c", "client": {"ip": "1.2.3.4", "port": 1},
        "reason": "NO_GRANT", "detail": "d"}, key=s.keys["world"])
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


# The bundled keys.json is a required member but csverify never decodes it:
# only the trusted --keys manifest governs (V3). Altering it changes nothing —
# recorded as a spec-03 §11 directed-extra gap in progress/evidence-py.md.
@case("keys-json-differs-from-trusted", "CLEAN")
def _(tmp):
    s, f = base_files()
    km = json.loads(f["keys.json"])
    km[0]["not_before"] = "2020-01-01T00:00:00Z"  # differs from trusted --keys
    f["keys.json"] = G.jdumps(km)
    return s, f


@case("E_KEY-not-before-in-future", "INVALID", errors={"E_KEY"})
def _(tmp):
    s = G.Session()
    s.keys["broker"] = G.KeyPair(b"late")
    s.open()
    s.effect(1)
    s.close_world()
    s.emitter_seals()
    s.seal()
    f = s.files()
    km = json.loads(f["keys.json"])
    for e in km:
        if e["role"] == "emitter:broker":
            e["not_before"] = "2030-01-01T00:00:00Z"
    f["keys.json"] = G.jdumps(km)
    keys = s.key_manifest()
    for e in keys:
        if e["role"] == "emitter:broker":
            e["not_before"] = "2030-01-01T00:00:00Z"
    return s, f, keys


# ------------------------------------------------------------------ V4
@case("E_SESSION-wrong-session", "INVALID", errors={"E_SESSION"})
def _(tmp):
    s = G.Session()
    s.open()
    s.emit("broker", "effect.denied", {
        "conn_id": "c", "client": {"ip": "1.2.3.4", "port": 1},
        "reason": "NO_GRANT", "detail": "d"}, session="01JWRONGSESSION")
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("E_SESSION-subject-digest", "INVALID", errors={"E_SESSION"})
def _(tmp):
    s, f = base_files()
    lines = all_lines(f)
    env = json.loads(lines[-1])
    st = json.loads(G.base64.b64decode(env["payload"]))
    st["subject"][0]["digest"]["sha256"] = "0" * 64
    lines[-1] = G.jdumps(resign(env, st, s.keys["controller"]))
    setlines(f, lines)
    s.repack(f)
    return s, f


# ------------------------------------------------------------------ V5
@case("E_CHAIN-eseq-gap", "INVALID", errors={"E_CHAIN", "E_SEAL"})
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1)
    s.emit("broker", "effect.denied", {
        "conn_id": "c", "client": {"ip": "1.2.3.4", "port": 1},
        "reason": "NO_GRANT", "detail": "d"}, eseq=5)
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("E_CHAIN-wrong-eprev", "INVALID", errors={"E_CHAIN", "E_SEAL"})
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1)
    s.emit("broker", "effect.denied", {
        "conn_id": "c", "client": {"ip": "1.2.3.4", "port": 1},
        "reason": "NO_GRANT", "detail": "d"}, eprev="f" * 64)
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("E_CHAIN-eprev-nonzero-at-0", "INVALID", errors={"E_CHAIN", "E_SEAL"})
def _(tmp):
    s = G.Session()
    s.open()
    s.emit("world", "world.rewound", {
        "to_journal_seq": 0, "dropped_entries": []}, eprev="f" * 64)
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


# csverify has no duplicate-record-id check; two denied effects sharing one
# id still verify (documented divergence, see progress/evidence-py.md).
@case("dup-record-id-tolerated", "CLEAN_WITH_DENIALS")
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1)
    rid = G.ulid()
    s.emit("broker", "effect.denied", {
        "conn_id": "c", "client": {"ip": "1.2.3.4", "port": 1},
        "reason": "NO_GRANT", "detail": "d"}, record_id=rid)
    s.emit("broker", "effect.denied", {
        "conn_id": "c", "client": {"ip": "1.2.3.4", "port": 1},
        "reason": "NO_GRANT", "detail": "d2"}, record_id=rid)
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("E_CHAIN-eseq-out-of-order", "INVALID", errors={"E_CHAIN", "E_SEAL"})
def _(tmp):
    s = G.Session()
    s.open()
    s.emit("broker", "effect.denied", {
        "conn_id": "c", "client": {"ip": "1.2.3.4", "port": 1},
        "reason": "NO_GRANT", "detail": "d"}, eseq=1)
    s.emit("broker", "effect.denied", {
        "conn_id": "c2", "client": {"ip": "1.2.3.4", "port": 1},
        "reason": "NO_GRANT", "detail": "d"}, eseq=0)
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


# ------------------------------------------------------------------ V6
@case("E_CHECKPOINT-emitter-key-sig", "INVALID", errors={"E_CHECKPOINT"})
def _(tmp):
    s, f = base_files()
    root, size = s.tree()
    kid = G.note_key_id(s.origin, s.keys["broker"].pub)
    body = s.origin.encode() + f"\n{size}\n".encode() + G.base64.b64encode(root) + b"\n"
    sig = s.keys["broker"].sign(body)
    f["checkpoint.txt"] = (body + b"\n\xe2\x80\x94 " + s.origin.encode() + b" " +
                           G.base64.b64encode(kid.to_bytes(4, "big") + sig) + b"\n")
    return s, f


@case("E_CHECKPOINT-wrong-origin", "INVALID", errors={"E_CHECKPOINT"})
def _(tmp):
    s, f = base_files()
    root, size = s.tree()
    kid = G.note_key_id(s.origin, s.keys["log"].pub)
    body = b"countersign.dev/log/WRONG\n" + f"{size}\n".encode() + \
        G.base64.b64encode(root) + b"\n"
    sig = s.keys["log"].sign(body)
    f["checkpoint.txt"] = (body + b"\n\xe2\x80\x94 " + s.origin.encode() + b" " +
                           G.base64.b64encode(kid.to_bytes(4, "big") + sig) + b"\n")
    return s, f


@case("E_CHECKPOINT-garbage", "INVALID", errors={"E_CHECKPOINT"})
def _(tmp):
    s, f = base_files()
    f["checkpoint.txt"] = b"not a checkpoint\n"
    return s, f


@case("E_CHECKPOINT-no-signature", "INVALID", errors={"E_CHECKPOINT"})
def _(tmp):
    s, f = base_files()
    root, size = s.tree()
    f["checkpoint.txt"] = (s.origin.encode() + f"\n{size}\n".encode() +
                           G.base64.b64encode(root) + b"\n")
    return s, f


# ------------------------------------------------------------------ V7
@case("E_INCLUSION-corrupt-proof", "INVALID", errors={"E_BUNDLE"})
def _(tmp):
    s, f = base_files()
    idx = json.loads(f["index.json"])
    idx[1]["inclusion_proof"][0] = "ab" * 32
    f["index.json"] = G.jdumps(idx)
    return s, f


@case("E_INCLUSION-out-of-order-index", "INVALID", errors={"E_INCLUSION"})
def _(tmp):
    s, f = base_files()
    idx = json.loads(f["index.json"])
    idx[0]["log_index"], idx[1]["log_index"] = \
        idx[1]["log_index"], idx[0]["log_index"]
    f["index.json"] = G.jdumps(idx)
    return s, f


@case("E_INCLUSION-index-beyond-tree", "INVALID", errors={"E_INCLUSION"})
def _(tmp):
    s, f = base_files()
    idx = json.loads(f["index.json"])
    idx[1]["log_index"] = 999999
    f["index.json"] = G.jdumps(idx)
    return s, f


# Index/records disagreement — both directions of the count check plus
# entry-level mismatches (the supervisor's reopened cases; csverify-derived).
@case("index-fewer-than-records", "INVALID", errors={"E_BUNDLE"})
def _(tmp):
    s, f = base_files()
    idx = json.loads(f["index.json"])
    f["index.json"] = G.jdumps(idx[:-1])
    return s, f


@case("index-more-than-records", "INVALID", errors={"E_BUNDLE"})
def _(tmp):
    s, f = base_files()
    idx = json.loads(f["index.json"])
    idx.append({"log_index": len(idx), "inclusion_proof": []})
    f["index.json"] = G.jdumps(idx)
    return s, f


@case("index-entry-different-proof", "INVALID", errors={"E_INCLUSION"})
def _(tmp):
    s, f = base_files()
    idx = json.loads(f["index.json"])
    # A validly-formed but wrong proof node in one entry.
    idx[3]["inclusion_proof"][0] = G.b64e(b"\x01" + bytes(31))
    f["index.json"] = G.jdumps(idx)
    return s, f


@case("records-more-than-index-extra-line", "INVALID",
      errors={"E_BUNDLE", "E_CHAIN"})
def _(tmp):
    s, f = base_files()
    lines = all_lines(f)
    lines.append(lines[-1])   # append a stray line; index now too short
    setlines(f, lines)
    return s, f


# ------------------------------------------------------------------ V8
@case("E_OPEN-first-not-open", "INVALID", errors={"E_OPEN"})
def _(tmp):
    s = G.Session()
    s.effect(1)   # broker record before session.open
    s.open()
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("E_POLICY-altered-policy", "INVALID", errors={"E_POLICY"})
def _(tmp):
    s, f = base_files()
    f["policy.yaml"] = b"# different bytes\n"
    return s, f


@case("E_POLICY-missing-policy", "INVALID", errors={"E_POLICY"})
def _(tmp):
    s, f = base_files()
    del f["policy.yaml"]
    return s, f


@case("E_POLICY-contract-digest", "INVALID", errors={"E_POLICY"})
def _(tmp):
    s = G.Session()
    s.contracts["mcp.yaml"] = b"contract: x\n"
    s.open()
    s.effect(1)
    s.close_world()
    s.emitter_seals()
    s.seal()
    f = s.files()
    del f["contracts/mcp.yaml"]
    return s, f


# ----------------------------------------------------------------- V9/V10
@case("E_SEAL-wrong-head-hash", "INVALID", errors={"E_SEAL"})
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1)
    s.close_world()
    s.emitter_seals()
    s.seal(hash_shift=b"x")
    return s, s.files()


@case("E_SEAL-emitter-missing", "INVALID", errors={"E_SEAL"})
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1)
    s.close_world()
    s.emitter_seals()
    s.seal(skip_roles=("broker",))
    return s, s.files()


@case("E_SEAL-record-after-head", "INVALID", errors={"E_SEAL"})
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1)
    s.close_world()
    s.emitter_seals()
    s.seal()
    # broker writes one more record after the seal declared its head
    s.emit("broker", "effect.denied", {
        "conn_id": "c", "client": {"ip": "1.2.3.4", "port": 1},
        "reason": "NO_GRANT", "detail": "d"})
    return s, s.files()


# ----------------------------------------------------------------- V11
@case("E_STRUCTURE-result-before-effect", "INVALID", errors={"E_STRUCTURE"})
def _(tmp):
    s = G.Session()
    s.open()
    s.effect_result("eff-later")
    s.effect(1, effect_id="eff-later")
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("E_STRUCTURE-dup-result", "INVALID", errors={"E_STRUCTURE"})
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1)
    s.effect_result("eff00001")
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("E_STRUCTURE-result-for-unknown-effect", "INVALID", errors={"E_STRUCTURE"})
def _(tmp):
    s = G.Session()
    s.open()
    s.effect_result("eff-nope")
    s.effect(1)
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("E_STRUCTURE-stage-via-unknown", "INVALID", errors={"E_STRUCTURE"})
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1)
    s.stage_entry("eff-nonexistent")
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("E_STRUCTURE-apply-before-decision", "INVALID", errors={"E_STRUCTURE"})
def _(tmp):
    s = G.Session()
    s.open()
    e = s.effect(1, result=False)
    ent = s.stage_entry(e)
    s.effect_result(e)
    cid = s.eid("com")
    s.emit("world", "commit.requested", {
        "commit_id": cid, "trigger": "agent", "entries": [ent],
        "changeset_root": G.sha_hex(b"cs"), "review_sha256": G.sha_hex(b"r"),
        "invariants": [], "auto_eligible": False, "expires_at": G.ts(9)})
    # apply effect before any commit.decision
    s.emit("broker", "effect.http", {
        "effect_id": "eff-apply", "actor": "world", "purpose": "apply",
        "for": ent, "conn_id": "cw",
        "client": {"ip": "10.0.0.10", "port": 3128},
        "request": {"method": "POST", "scheme": "https",
                    "authority": "x", "path": "/a",
                    "query_sha256": G.sha_hex(b""), "query_len": 0,
                    "header_names": [], "body_deferred": False},
        "request_digest": G.sha_hex(b"a"), "class": "staged",
        "decision": {"action": "allow", "reason": "OK", "requires": "allow",
                     "credentials": []},
        "attribution": {"level": "STANDING", "intents": [], "lineage": "off"},
        "taint": [], "budget": {"leak_bytes": 0, "writes": 1},
        "inspect": "none"})
    s.effect_result("eff-apply")
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


# csverify does not forbid records after an emitter.seal on the same chain;
# the seal head is attested, not a hard stop (see progress/evidence-py.md).
@case("emitter-seal-then-record-tolerated", "CLEAN_WITH_DENIALS")
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1)
    s.emit("broker", "emitter.seal", {"final": True})
    s.emit("broker", "effect.denied", {
        "conn_id": "c", "client": {"ip": "1.2.3.4", "port": 1},
        "reason": "NO_GRANT", "detail": "d"})
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("E_STRUCTURE-intent-result-undeclared", "INVALID", errors={"E_STRUCTURE"})
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1)
    s.emit("broker", "intent.result", {
        "intent_id": "int-nope", "via_effect": "eff00001",
        "closed_by": "tool_result"})
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


# ----------------------------------------------------------------- V15
@case("warn-dangling", "CLEAN_WITH_DENIALS", warnings={"W_DANGLING"})
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1, result=False)
    s.denied()   # so verdict is CLEAN_WITH_DENIALS not CLEAN — warning distinct
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("warn-unclean-emitter", "CLEAN", warnings={"W_UNCLEAN_EMITTER"})
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1)
    s.close_world()
    s.emitter_seals()
    s.seal(clean=False)
    return s, s.files()


@case("warn-observer-gap", "CLEAN", warnings={"W_OBSERVER_GAP"})
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1)
    s.emit("observer", "observer.gap", {"from": 3, "to": 9, "reason": "restart"})
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("warn-unparsed", "CLEAN", warnings={"W_UNPARSED"})
def _(tmp):
    s = G.Session()
    s.open()
    s.effect(1)
    s.emit("broker", "intent.unparsed", {
        "via_effect": "eff00001", "provider": "anthropic",
        "detail": "unparseable"})
    s.close_world()
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("warn-partial-commit", "CLEAN", warnings={"W_PARTIAL_COMMIT"})
def _(tmp):
    s = G.Session()
    s.open()
    e = s.effect(1, result=False)
    ent = s.stage_entry(e)
    s.effect_result(e)
    cid = s.eid("com")
    s.emit("world", "commit.requested", {
        "commit_id": cid, "trigger": "agent", "entries": [ent],
        "changeset_root": G.sha_hex(b"cs"), "review_sha256": G.sha_hex(b"r"),
        "invariants": [], "auto_eligible": True, "expires_at": G.ts(9)})
    s.emit("world", "commit.decision", {
        "commit_id": cid, "decision": "commit", "by": "auto",
        "selected": [ent], "selected_root": G.sha_hex(b"cs"),
        "review_sha256": G.sha_hex(b"r"), "expires_at": G.ts(9)})
    s.emit("world", "commit.closed", {"commit_id": cid,
                                      "outcome": "partial"})
    s.close_world(commits=[cid])
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("warn-apply-unknown", "CLEAN", warnings={"W_APPLY_UNKNOWN"})
def _(tmp):
    s = G.Session()
    s.open()
    e = s.effect(1, result=False)
    ent = s.stage_entry(e)
    s.effect_result(e)
    cid = s.eid("com")
    s.emit("world", "commit.requested", {
        "commit_id": cid, "trigger": "agent", "entries": [ent],
        "changeset_root": G.sha_hex(b"cs"), "review_sha256": G.sha_hex(b"r"),
        "invariants": [], "auto_eligible": True, "expires_at": G.ts(9)})
    s.emit("world", "commit.decision", {
        "commit_id": cid, "decision": "commit", "by": "auto",
        "selected": [ent], "selected_root": G.sha_hex(b"cs"),
        "review_sha256": G.sha_hex(b"r"), "expires_at": G.ts(9)})
    s.emit("world", "commit.applied", {
        "commit_id": cid, "entry_id": ent, "outcome": "unknown",
        "precondition": {"kind": "etag", "expected": "e", "observed": "e"}})
    s.emit("world", "commit.closed", {"commit_id": cid, "outcome": "committed"})
    s.close_world(commits=[cid])
    s.emitter_seals()
    s.seal()
    return s, s.files()


@case("warn-undo-conflict", "CLEAN", warnings={"W_UNDO_CONFLICT"})
def _(tmp):
    s = G.Session()
    s.open()
    e = s.effect(1, result=False)
    ent = s.stage_entry(e)
    s.effect_result(e)
    cid = s.commit_flow(ent)
    uid = s.eid("und")
    s.emit("world", "undo.requested", {
        "undo_id": uid, "scope": "commit", "targets": [cid],
        "trigger": "rewind"})
    s.emit("world", "undo.applied", {
        "undo_id": uid, "target": ent, "outcome": "conflict",
        "precondition": {"expected": "e", "observed": "f"}})
    s.emit("world", "undo.closed", {
        "undo_id": uid, "restored": 0, "conflicts": 1,
        "not_compensable": 0, "failed": 0})
    s.close_world(commits=[cid])
    s.emitter_seals()
    s.seal()
    return s, s.files()
