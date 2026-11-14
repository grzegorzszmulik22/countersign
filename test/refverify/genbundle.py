# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""Spec-derived bundle fabricator for refverify checks (lane-local test code).

Builds bundles exactly per spec 03 §7: DSSE envelopes over in-toto statements,
RFC 6962 leaf/node hashing, inclusion proofs, a C2SP tlog-checkpoint signed by
a dedicated log key, and a deterministic tar. Hashing and proof generation are
transcribed directly from RFC 6962 here — refverify is never imported — so a
shared bug cannot hide.
"""
import base64
import hashlib
import io
import json
import tarfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

H = hashlib.sha256


def sha(b):
    return H(b).digest()


def sha_hex(b):
    return H(b).hexdigest()


# --- ULID (Crockford base32, 26 chars) -------------------------------------
_CROCK = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid(seed=None):
    n = int.from_bytes(sha((seed or str(time.time_ns()) + str(id(object()))).encode())[:16], "big")
    ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    v = (ts_ms << 80) | n
    s = ""
    for i in range(26):
        s = _CROCK[(v >> ((25 - i) * 5)) & 31] + s
    return s


def ts(offset_ns=0):
    ns = 1_763_000_000_000_000_000 + offset_ns
    s, f = divmod(ns, 1_000_000_000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(s)) + f".{f:09d}Z"


def b64e(b):
    return base64.b64encode(b).decode()


def jdumps(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def pae(payload_type, payload):
    return (b"DSSEv1 " + str(len(payload_type.encode())).encode() + b" " +
            payload_type.encode() + b" " + str(len(payload)).encode() +
            b" " + payload)


class KeyPair:
    def __init__(self, seed):
        self.priv = Ed25519PrivateKey.from_private_bytes(sha(b"key:" + seed))
        self.pub = self.priv.public_key().public_bytes_raw()
        self.key_id = sha(self.pub)[:16].hex()

    def sign(self, msg):
        return self.priv.sign(msg)

    def pub_obj(self):
        return Ed25519PublicKey.from_public_bytes(self.pub)


ROLES = ["broker", "controller", "world", "observer"]


def leaf_hash(data):
    return sha(b"\x00" + data)


def node_hash(l, r):
    return sha(b"\x01" + l + r)


def mth(datas):
    n = len(datas)
    if n == 0:
        return sha(b"")
    if n == 1:
        return leaf_hash(datas[0])
    k = 1 << (n.bit_length() - 1)
    if k == n:
        k >>= 1
    return node_hash(mth(datas[:k]), mth(datas[k:]))


def ipath(m, datas):
    n = len(datas)
    if n == 1:
        return []
    k = 1 << (n.bit_length() - 1)
    if k == n:
        k >>= 1
    if m < k:
        return ipath(m, datas[:k]) + [mth(datas[k:])]
    return ipath(m - k, datas[k:]) + [mth(datas[:k])]


def note_key_id(name, pubkey):
    return int.from_bytes(sha(name.encode() + b"\x0a" + b"\x01" + pubkey)[:4], "big")


class Session:
    """A fabricated session: records, log, checkpoint, key manifest."""

    def __init__(self, sid=None, log_base=0, mode="enforce"):
        self.sid = sid or ulid()
        self.origin = "countersign.dev/log/" + ulid()[:12].lower()
        self.log_base = log_base
        self.keys = {r: KeyPair(b"emitter:" + r.encode()) for r in ROLES}
        self.keys["log"] = KeyPair(b"other:log")
        self.keys["attestor"] = KeyPair(b"other:attestor")
        self.instances = {r: ulid() for r in ROLES}
        self.chains = {r: [] for r in ROLES}      # record hashes per emitter
        self.lines = []                            # stored line bytes, no \n
        self.rec_meta = []                         # (emitter, eseq) per line
        self.mode = mode
        self.policy = b"# session policy\nallow: []\n"
        self.contracts = {}
        self.closed_world = False
        self.sealed = False
        self._idc = 0

    def eid(self, p):
        self._idc += 1
        return f"{p}{self._idc:05d}"

    def emitter(self, role):
        return f"{role}/{self.instances[role]}"

    def emit(self, role, rtype, body, key=None, session=None, eseq=None,
             eprev=None, record_id=None, ts_off=None):
        """Append one signed record; returns (line_bytes, record_hash)."""
        ch = self.chains[role]
        seq = len(ch) if eseq is None else eseq
        if eprev is None:
            eprev = ch[-1] if ch else "0" * 64
        rid = record_id or ulid()
        sess = session or self.sid
        pred = {"v": 1, "type": rtype, "id": rid, "session": sess,
                "emitter": self.emitter(role), "eseq": seq, "eprev": eprev,
                "ts": ts(self._idc if ts_off is None else ts_off), "body": body}
        stmt = {"_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": f"countersign:session:{sess}",
                             "digest": {"sha256": sha_hex(sess.encode())}}],
                "predicateType": "https://countersign.dev/record/v1",
                "predicate": pred}
        payload = jdumps(stmt)
        sig = (key or self.keys[role]).sign(
            pae("application/vnd.in-toto+json", payload))
        env = {"payloadType": "application/vnd.in-toto+json",
               "payload": b64e(payload),
               "signatures": [{"keyid": (key or self.keys[role]).key_id,
                               "sig": b64e(sig)}]}
        line = jdumps(env)
        self.lines.append(line)
        self.rec_meta.append((role, seq))
        ch.append(sha(pae("application/vnd.in-toto+json", payload)).hex())
        return line, ch[-1]

    # --- convenience emitters ---------------------------------------------
    def open(self, **over):
        body = {"kind": "agent",
                "principal": {"subject": "user@example.com",
                              "issuer": "corp-idp", "method": "oidc"},
                "sandbox": {"namespace": "sandboxes", "pod": "agent-1",
                            "pod_uid": "abc", "node": "w1",
                            "image_digest": sha_hex(b"img")},
                "mode": self.mode,
                "policy_digest": sha_hex(self.policy),
                "contract_digests": sorted(sha_hex(c) for c in self.contracts.values()),
                "ca_cert_sha256": sha_hex(b"ca"),
                "log_origin": self.origin,
                "world": {"id": ulid()},
                "start": {},
                "tape": {"enabled": False}}
        body.update(over)
        return self.emit("controller", "session.open", body)

    def effect(self, i=1, action="allow", cls="safe", actor="sandbox",
               result=True, effect_id=None, purpose=None, for_=None,
               actor_ip="10.0.0.9"):
        eid = effect_id or self.eid("eff")
        body = {"effect_id": eid, "actor": actor, "conn_id": f"c{i}",
                "client": {"ip": actor_ip, "port": 40000 + i},
                "request": {"method": "GET", "scheme": "https",
                            "authority": "example.com", "path": f"/r{i}",
                            "query_sha256": sha_hex(b""), "query_len": 0,
                            "header_names": ["host"],
                            "body_sha256": sha_hex(b""), "body_len": 0,
                            "body_deferred": False},
                "request_digest": sha_hex(f"req{i}".encode()),
                "class": cls,
                "decision": {"action": action, "reason": "OK",
                             "requires": "allow",
                             "credentials": [], "would_deny": False},
                "attribution": {"level": "STANDING", "intents": [],
                                "lineage": "off"},
                "taint": [], "budget": {"leak_bytes": 0, "writes": 0},
                "inspect": "none"}
        if purpose is not None:
            body["purpose"] = purpose
        if for_ is not None:
            body["for"] = for_
        self.emit("broker", "effect.http", body)
        if result:
            self.effect_result(eid)
        return eid

    def effect_result(self, eid):
        self.emit("broker", "effect.http.result", {
            "effect_id": eid, "served_by": "upstream", "status": 200,
            "response": {"header_names": ["content-type"],
                         "body_sha256": sha_hex(b"resp"), "body_len": 4},
            "request_body": {"sha256": sha_hex(b""), "len": 0},
            "timing": {"total_ms": 12, "ttfb_ms": 8},
            "scrubbed": False})

    def denied(self):
        self.emit("broker", "effect.denied", {
            "conn_id": "cx", "client": {"ip": "10.0.0.9", "port": 40099},
            "authority": "evil.example", "reason": "DENY_GRANT",
            "detail": "no grant for authority"})

    def stage_entry(self, via, entry_id=None, seq=1):
        eid = entry_id or self.eid("ent")
        entry = {"op": "git-push", "ref": "refs/heads/w"}
        self.emit("world", "stage.entry", {
            "entry_id": eid, "journal_seq": seq, "via_effect": via,
            "entry": entry, "entry_sha256": sha_hex(jdumps(entry))})
        return eid

    def commit_flow(self, entry, apply_eff=True):
        cid = self.eid("com")
        self.emit("world", "commit.requested", {
            "commit_id": cid, "trigger": "agent", "entries": [entry],
            "changeset_root": sha_hex(b"cs"),
            "review_sha256": sha_hex(b"rev"),
            "invariants": [{"name": "i1", "pass": True, "detail": ""}],
            "auto_eligible": True, "expires_at": ts(999999)})
        self.emit("world", "commit.decision", {
            "commit_id": cid, "decision": "commit", "by": "auto",
            "selected": [entry], "selected_root": sha_hex(b"cs"),
            "review_sha256": sha_hex(b"rev"), "expires_at": ts(999999)})
        if apply_eff:
            eff = self.eid("eff")
            self.emit("broker", "effect.http", {
                "effect_id": eff, "actor": "world", "purpose": "apply",
                "for": entry, "conn_id": "cw",
                "client": {"ip": "10.0.0.10", "port": 3128},
                "request": {"method": "POST", "scheme": "https",
                            "authority": "example.com", "path": "/apply",
                            "query_sha256": sha_hex(b""), "query_len": 0,
                            "header_names": ["host"], "body_deferred": False},
                "request_digest": sha_hex(b"apply"),
                "class": "compensable",
                "decision": {"action": "allow", "reason": "OK",
                             "requires": "allow", "credentials": [],
                             "would_deny": False},
                "attribution": {"level": "STANDING", "intents": [],
                                "lineage": "off"},
                "taint": [], "budget": {"leak_bytes": 0, "writes": 1},
                "inspect": "none"})
            self.effect_result(eff)
            self.emit("world", "commit.applied", {
                "commit_id": cid, "entry_id": entry, "outcome": "applied",
                "via_effect": eff,
                "precondition": {"kind": "etag", "expected": "e",
                                 "observed": "e"}})
        self.emit("world", "commit.closed", {"commit_id": cid,
                                             "outcome": "committed"})
        return cid

    def close_world(self, outcome="committed", commits=None):
        self.closed_world = True
        return self.emit("world", "world.closed",
                         {"outcome": outcome, "commits": commits or []})

    def seal(self, clean=True, skip_roles=(), final_shift=0, hash_shift=b""):
        emitters = []
        for r in ROLES:
            if r in skip_roles or not self.chains[r]:
                continue
            emitters.append({"emitter": self.emitter(r),
                             "final_eseq": len(self.chains[r]) - 1 + final_shift,
                             "head_hash": (sha(bytes.fromhex(self.chains[r][-1]) +
                                              hash_shift).hex() if hash_shift
                                          else self.chains[r][-1]),
                             "clean": clean})
        self.sealed = True
        return self.emit("controller", "session.seal", {
            "reason": "session end", "emitters": emitters,
            "counts": {"effects": 0, "intents": 0, "denials": 0,
                       "entries": 0, "commits": 0}})

    def emitter_seals(self):
        # emitter.seal is the last record an emitter writes; the sealer
        # (controller) finishes with session.seal instead, so it never
        # writes emitter.seal.
        for r in ROLES:
            if r != "controller" and self.chains[r]:
                self.emit(r, "emitter.seal", {"final": True})

    # --- bundle -----------------------------------------------------------
    def key_manifest(self):
        out = []
        for role, kp in self.keys.items():
            out.append({"key_id": kp.key_id,
                        "role": role if role in ("log", "attestor") else f"emitter:{role}",
                        "public_key": b64e(kp.pub),
                        "not_before": "2025-01-01T00:00:00Z"})
        return out

    def index(self):
        return [{"log_index": self.log_base + i,
                 "inclusion_proof": [p.hex() for p in ipath(self.log_base + i, self.lines)]}
                for i in range(len(self.lines))]

    def tree(self):
        return mth(self.lines), self.log_base + len(self.lines)

    def checkpoint(self):
        root, size = self.tree()
        kid = note_key_id(self.origin, self.keys["log"].pub)
        body = (self.origin.encode() + f"\n{size}\n".encode() +
                base64.b64encode(root) + b"\n")
        sig = self.keys["log"].sign(body)
        return (body + b"\n\xe2\x80\x94 " + self.origin.encode() + b" " +
                base64.b64encode(kid.to_bytes(4, "big") + sig) + b"\n")

    def manifest(self):
        return {"bundle_version": 1, "session": self.sid,
                "log_origin": self.origin, "created": ts(0)}

    def files(self):
        f = {"manifest.json": jdumps(self.manifest()),
             "keys.json": jdumps(self.key_manifest()),
             "records.jsonl": b"".join(l + b"\n" for l in self.lines),
             "index.json": jdumps(self.index()),
             "checkpoint.txt": self.checkpoint(),
             "policy.yaml": self.policy}
        for name, data in self.contracts.items():
            f[f"contracts/{name}"] = data
        return f

    def repack(self, files):
        """Recompute index.json + checkpoint.txt after records.jsonl edits."""
        lines = [l for l in files["records.jsonl"].split(b"\n") if l]
        self.lines = lines
        files["index.json"] = jdumps(self.index())
        files["checkpoint.txt"] = self.checkpoint()
        return files


def write_tar(files, path):
    """Deterministic tar: sorted names, zeroed mtime/uid/gid."""
    with tarfile.open(path, "w") as tf:
        for name in sorted(files):
            data = files[name]
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = 0
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(data))


def write_keys(keys, path):
    with open(path, "wb") as f:
        f.write(jdumps(keys))
