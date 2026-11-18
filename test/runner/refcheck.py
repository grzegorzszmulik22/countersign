#!/usr/bin/env python3
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""Independent bundle verifier for M2.7 — a second implementation of the
core evidence checks of spec/03 §10, distinct from cmd/csverify.

Usage: refcheck.py <bundle.tar> <keys.json>

Verifies, for the session bundle:
  * required tar members present
  * every record is a DSSE v1 envelope with one ed25519 signature that
    verifies against keys.json under a manifest key with role
    emitter:<role> and not_before <= record ts
  * every record carries the bundle's session id (in-toto subject too)
  * first record is session.open; session.seal exists
  * per-emitter eseq/eprev chains are exact (eprev[0]=0*64, then
    eprev[i]=sha256(PAE(record i-1)))
  * checkpoint.txt parses, origin matches manifest, its single signature
    verifies under the manifest's role=log key
  * every index.json inclusion proof verifies (RFC 6962) against the
    checkpoint root
Exits 0 only when all of it holds; prints a verdict JSON.
"""
import base64
import hashlib
import json
import re
import sys
import tarfile
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ZERO = "0" * 64

RFC3339 = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?Z$")


def parse_ts(s: str) -> datetime:
    m = RFC3339.match(s)
    if not m:
        fail(f"bad RFC3339 timestamp {s!r}")
    frac = (m.group(7) or ".0")[1:]
    micro = int((frac + "000000")[:6])
    return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                    int(m.group(4)), int(m.group(5)), int(m.group(6)),
                    micro, tzinfo=timezone.utc)


def pae(payload_type: str, payload: bytes) -> bytes:
    pt = payload_type.encode()
    return (b"DSSEv1 " + str(len(pt)).encode() + b" " + pt
            + b" " + str(len(payload)).encode() + b" " + payload)


def fail(msg):
    print(json.dumps({"verdict": "INVALID", "error": msg}))
    sys.exit(1)


def hash_leaf(line: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + line).digest()


def hash_node(l: bytes, r: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + l + r).digest()


def verify_inclusion(index, size, leaf, proof, root):
    if size == 0 or index >= size:
        fail("inclusion index out of range")
    inner = (index ^ (size - 1)).bit_length()
    border = bin(index >> inner).count("1")
    if len(proof) != inner + border:
        fail("inclusion proof wrong size")
    r = leaf
    for i in range(inner):
        if (index >> i) & 1 == 0:
            r = hash_node(r, proof[i])
        else:
            r = hash_node(proof[i], r)
    for h in proof[inner:]:
        r = hash_node(h, r)
    if r != root:
        fail("inclusion proof root mismatch")


def main():
    bundle, keys_path = sys.argv[1], sys.argv[2]
    manifest = {e["key_id"]: e for e in json.load(open(keys_path))}

    members = {}
    with tarfile.open(bundle) as tf:
        for m in tf.getmembers():
            members[m.name] = tf.extractfile(m).read()
    for req in ("manifest.json", "keys.json", "records.jsonl",
                    "index.json", "checkpoint.txt"):
        if req not in members:
            fail(f"missing member {req}")

    man = json.loads(members["manifest.json"])
    session = man["session"]
    origin = man["log_origin"]

    lines = [l for l in members["records.jsonl"].split(b"\n") if l.strip()]
    index = json.loads(members["index.json"])
    if len(index) != len(lines):
        fail("index/records length mismatch")

    heads = {}
    saw_open = saw_seal = False
    for i, line in enumerate(lines):
        env = json.loads(line)
        if env.get("payloadType") != "application/vnd.in-toto+json":
            fail(f"line {i}: bad payloadType")
        payload = base64.b64decode(env["payload"])
        st = json.loads(payload)
        rec = st["predicate"]
        if rec["session"] != session:
            fail(f"line {i}: session {rec['session']} != {session}")
        subj = st["subject"]
        want_subj = hashlib.sha256(session.encode()).hexdigest()
        if len(subj) != 1 or subj[0]["digest"]["sha256"] != want_subj \
                or subj[0]["name"] != "countersign:session:" + session:
            fail(f"line {i}: subject does not bind the session")
        sigs = env.get("signatures", [])
        if len(sigs) != 1:
            fail(f"line {i}: want exactly one signature")
        sig = sigs[0]
        ent = manifest.get(sig["keyid"])
        if ent is None:
            fail(f"line {i}: unknown key {sig['keyid']}")
        role = rec["emitter"].split("/")[0]
        if ent["role"] != "emitter:" + role:
            fail(f"line {i}: key role {ent['role']} != emitter:{role}")
        if ent.get("not_before") and \
                parse_ts(ent["not_before"]) > parse_ts(rec["ts"]):
            fail(f"line {i}: record predates key not_before")
        pub = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(ent["public_key"]))
        try:
            pub.verify(base64.b64decode(sig["sig"]), pae(env["payloadType"], payload))
        except Exception:
            fail(f"line {i}: signature invalid")
        # chain
        em = rec["emitter"]
        want_eseq, want_eprev = heads.get(em, (0, ZERO))
        if rec["eseq"] != want_eseq or rec["eprev"] != want_eprev:
            fail(f"line {i}: chain break at {em} eseq {rec['eseq']}")
        heads[em] = (want_eseq + 1,
                     hashlib.sha256(pae(env["payloadType"], payload)).hexdigest())
        if i == 0 and rec["type"] == "session.open":
            saw_open = True
        if rec["type"] == "session.seal":
            saw_seal = True
        # log_index must be strictly increasing
        if i > 0 and index[i]["log_index"] <= index[i - 1]["log_index"]:
            fail(f"line {i}: log_index not strictly increasing")
    if not saw_open:
        fail("first record is not session.open")
    if not saw_seal:
        fail("no session.seal")

    # checkpoint: <origin>\n<size>\n<b64root>\n\n— <origin> <b64(kh|sig)>
    cp_raw = members["checkpoint.txt"].decode()
    text, rest = cp_raw.split("\n\n", 1)
    clines = text.split("\n")
    cp_origin, cp_size, cp_root_b64 = clines[0], int(clines[1]), clines[2]
    if cp_origin != origin:
        fail("checkpoint origin mismatch")
    cp_root = base64.b64decode(cp_root_b64)
    sigline = rest.strip()
    assert sigline.startswith("— ")
    name, b64s = sigline[2:].split(" ")
    if name != cp_origin:
        fail("checkpoint signer name != origin")
    raw = base64.b64decode(b64s)
    kh, sig = raw[:4], raw[4:]
    msg = (text + "\n").encode()
    # noteKeyHash: sha256(origin ‖ "\n" ‖ 0x01 ‖ pubkey)[:4]
    ok = False
    for e in manifest.values():
        if e["role"] != "log":
            continue
        pub = base64.b64decode(e["public_key"])
        khexp = hashlib.sha256(
            cp_origin.encode() + b"\n\x01" + pub).digest()[:4]
        if khexp != kh:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
            ok = True
        except Exception:
            pass
    if not ok:
        fail("checkpoint signature invalid")

    # inclusion proofs (RFC 6962)
    for i, e in enumerate(index):
        proof = [base64.b64decode(p) for p in e["inclusion_proof"]]
        verify_inclusion(e["log_index"], cp_size,
                         hash_leaf(lines[i]), proof, cp_root)

    print(json.dumps({"verdict": "CLEAN", "records": len(lines),
                      "emitters": len(heads), "tree_size": cp_size}))
    sys.exit(0)


if __name__ == "__main__":
    main()
