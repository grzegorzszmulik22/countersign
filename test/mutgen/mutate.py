# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""Mutation suite for spec 03 §11 (M1.6): the nine classes plus directed
extras that produce bundle-level edits the verifier must reject.

Each mutation takes the members dict of a valid generated bundle (as
produced by mutgen/genbundle) plus its trusted manifest, and returns
mutated members + trusted manifest. Mutations never call refverify or
read Go sources. Where a class needs the session internals (signers,
lines, donor records) it receives the genbundle Session that made it.

Variants inside a class explore which surface the rejection lands on —
the verifier contract is that BOTH verifiers emit the identical verdict
and code sets for every mutant, whatever those codes are.
"""
import base64
import copy
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "refverify"))

import genbundle as G  # noqa: E402

CLASSES = (1, 2, 3, 4, 5, 6, 7, 8, 9)


def lines_of(files):
    return [l for l in files["records.jsonl"].split(b"\n") if l]


def set_lines(files, lines):
    files["records.jsonl"] = b"".join(l + b"\n" for l in lines)


def index_of(files):
    return json.loads(files["index.json"])


def set_index(files, idx):
    files["index.json"] = G.jdumps(idx)


def env_at(files, i):
    return json.loads(lines_of(files)[i])


def set_env(files, i, env):
    lines = lines_of(files)
    lines[i] = G.jdumps(env)
    set_lines(files, lines)


def _pred(env):
    return json.loads(base64.b64decode(env["payload"]))["predicate"]


def nonfinal_idx(s, rng):
    """Index of a decodable record that is not the last line."""
    n = len(s.lines)
    return rng.randrange(max(1, n - 1))


def adjacent_pair(s, rng):
    """Two consecutive same-emitter record indexes, not the final line."""
    lines = lines_of_cache(s)
    for _ in range(200):
        i = rng.randrange(len(lines) - 2)
        e1 = _pred(json.loads(lines[i]))["emitter"]
        e2 = _pred(json.loads(lines[i + 1]))["emitter"]
        if e1 == e2:
            return i
    return len(lines) - 3


def lines_of_cache(s):
    return s.lines


# ------------------------------------------------------------------ classes

def class1_payload_bit(s, files, keys, rng):
    """Flip one bit inside a decoded payload (statement JSON stays valid):
    alter one character of a string field, re-encode, re-serialize."""
    i = nonfinal_idx(s, rng)
    env = env_at(files, i)
    st = json.loads(base64.b64decode(env["payload"]))
    pred = st["predicate"]
    # Flip inside a body string field where possible, else the record ts.
    body = pred.get("body", {})
    flipped = False
    for k, v in body.items():
        if isinstance(v, str) and v:
            c = v[0]
            body[k] = ("x" if c != "x" else "y") + v[1:]
            flipped = True
            break
    if not flipped:
        pred["ts"] = "2027-01-01T00:00:00.000000000Z"
    env["payload"] = G.b64e(G.jdumps(st))
    set_env(files, i, env)
    return files, keys


def class2_sig_bit(s, files, keys, rng):
    """Flip one bit in a record signature."""
    i = nonfinal_idx(s, rng)
    env = env_at(files, i)
    raw = bytearray(base64.b64decode(env["signatures"][0]["sig"]))
    raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
    env["signatures"][0]["sig"] = G.b64e(bytes(raw))
    set_env(files, i, env)
    return files, keys


def class3_delete(s, files, keys, rng):
    """Delete one non-final record. Variants: index untouched, matching
    index entry removed, or index+checkpoint rebuilt (repack). The
    target must have a later same-emitter record so the eprev chain
    breaks (deleting an emitter's last record only moves its head →
    E_SEAL, outside this class's expected set)."""
    lines = lines_of(files)
    emitters = []
    for l in lines:
        try:
            emitters.append(_pred(json.loads(l))["emitter"])
        except Exception:
            emitters.append(None)
    cand = [i for i in range(len(lines) - 1)
            if emitters[i] in emitters[i + 1:]]
    i = rng.choice(cand) if cand else rng.randrange(len(lines) - 1)
    variant = rng.randrange(3)
    if variant == 0:
        del lines[i]
        set_lines(files, lines)
    elif variant == 1:
        idx = index_of(files)
        del lines[i]
        del idx[i]
        set_lines(files, lines)
        set_index(files, idx)
    else:
        del lines[i]
        set_lines(files, lines)
        s.repack(files)
    return files, keys


def class4_swap(s, files, keys, rng):
    """Swap two adjacent same-emitter records (lines only, or the index
    entries too)."""
    lines = lines_of(files)
    i = adjacent_pair(s, rng)
    lines[i], lines[i + 1] = lines[i + 1], lines[i]
    set_lines(files, lines)
    if rng.random() < 0.5:
        idx = index_of(files)
        idx[i], idx[i + 1] = idx[i + 1], idx[i]
        set_index(files, idx)
    return files, keys


def checkpoint_prefix(s, n):
    """A genuine checkpoint over the first n lines, signed by the log key."""
    root = G.mth(s.lines[:n])
    size = s.log_base + n
    kid = G.note_key_id(s.origin, s.keys["log"].pub)
    body = (s.origin.encode() + f"\n{size}\n".encode() +
            base64.b64encode(root) + b"\n")
    sig = s.keys["log"].sign(body)
    return (body + b"\n\xe2\x80\x94 " + s.origin.encode() + b" " +
            base64.b64encode(kid.to_bytes(4, "big") + sig) + b"\n")


def class5_truncate(s, files, keys, rng):
    """Truncate the last k records, with and without substituting an
    older genuine checkpoint (spec 03 §11 class 5). Both forms keep
    lines and index consistent so the first finding is in-class."""
    return files, keys
    lines = lines_of(files)
    n = len(lines)
    k = rng.randrange(1, min(6, n - 2))
    keep = n - k
    idx = index_of(files)
    set_lines(files, lines[:keep])
    set_index(files, idx[:keep])
    if rng.random() < 0.5:
        # Older genuine checkpoint for the truncated prefix, re-signed
        # by the real log key; surviving proofs then fail inclusion.
        files["checkpoint.txt"] = checkpoint_prefix(s, keep)
    return files, keys


def class6_foreign(s, files, keys, rng, donor):
    """Replace a record with a genuine one from another session."""
    lines = lines_of(files)
    i = rng.randrange(len(lines))
    j = rng.randrange(len(donor.lines))
    lines[i] = donor.lines[j]
    set_lines(files, lines)
    return files, keys


def resign(s, env, keypair):
    """Re-sign a record envelope's PAE with an arbitrary key."""
    st = json.loads(base64.b64decode(env["payload"]))
    payload = G.jdumps(st)
    sig = keypair.sign(G.pae("application/vnd.in-toto+json", payload))
    env["payload"] = G.b64e(payload)
    env["signatures"] = [{"keyid": keypair.key_id, "sig": G.b64e(sig)}]
    return env


def class7_untrusted(s, files, keys, rng):
    """Modify a record and re-sign it with a key absent from the trusted
    manifest, or one with the wrong role for the emitter."""
    i = nonfinal_idx(s, rng)
    env = env_at(files, i)
    st = json.loads(base64.b64decode(env["payload"]))
    st["predicate"]["ts"] = "2027-06-01T00:00:00.000000000Z"
    env["payload"] = G.b64e(G.jdumps(st))
    variant = rng.randrange(3)
    if variant == 0:
        rogue = G.KeyPair(b"rogue:" + str(rng.random()).encode())
    elif variant == 1:
        rogue = s.keys["log"]            # right key, wrong role
    else:
        others = [r for r in ("broker", "world", "observer")
                  if s.keys[r].key_id != env["signatures"][0]["keyid"]]
        rogue = s.keys[rng.choice(others)]
    set_env(files, i, resign(s, env, rogue))
    return files, keys


def class8_checkpoint(s, files, keys, rng):
    """Alter the checkpoint, or have it signed by an emitter key."""
    variant = rng.randrange(4)
    cp = files["checkpoint.txt"]
    if variant == 0:
        # flip a char inside the root base64 → signature no longer valid
        i = cp.index(b"\n", cp.index(b"\n") + 1) + 1
        b = bytearray(cp)
        b[i] ^= 1
        files["checkpoint.txt"] = bytes(b)
    elif variant == 1:
        # corrupt the signature blob itself
        i = cp.rfind(b" ")
        b = bytearray(cp)
        b[i + 4] ^= 1
        files["checkpoint.txt"] = bytes(b)
    elif variant == 2:
        # different tree size, re-signed by the real log key
        files["checkpoint.txt"] = checkpoint_prefix(
            s, max(1, len(s.lines) - 1))
    else:
        # checkpoint re-signed by an emitter key, not the log key
        root, size = s.tree()
        kid = G.note_key_id(s.origin, s.keys["broker"].pub)
        body = (s.origin.encode() + f"\n{size}\n".encode() +
                base64.b64encode(root) + b"\n")
        sig = s.keys["broker"].sign(body)
        files["checkpoint.txt"] = (
            body + b"\n\xe2\x80\x94 " + s.origin.encode() + b" " +
            base64.b64encode(kid.to_bytes(4, "big") + sig) + b"\n")
    return files, keys


def class9_duplicate(s, files, keys, rng):
    """Duplicate a record; keep or duplicate its index entry."""
    lines = lines_of(files)
    i = rng.randrange(len(lines))
    if rng.random() < 0.5:
        lines.insert(i + 1, lines[i])
        idx = index_of(files)
        idx.insert(i + 1, idx[i])
        set_lines(files, lines)
        set_index(files, idx)
    else:
        lines.insert(i + 1, lines[i])
        set_lines(files, lines)
    return files, keys


# ------------------------------------------------------- directed extras

def extra_policy(s, files, keys, rng):
    p = bytearray(files["policy.yaml"])
    p[rng.randrange(len(p))] ^= 1
    files["policy.yaml"] = bytes(p)
    return files, keys


def extra_contract(s, files, keys, rng):
    names = [n for n in files if n.startswith("contracts/")]
    if names:
        p = bytearray(files[names[0]])
        if p:
            p[rng.randrange(len(p))] ^= 1
            files[names[0]] = bytes(p)
    else:
        files["policy.yaml"] = files["policy.yaml"] + b"#tamper\n"
    return files, keys


def extra_result_before_effect(s, files, keys, rng):
    """Move an effect's result line before the effect line itself."""
    lines = lines_of(files)
    idx = index_of(files)
    for _ in range(200):
        i = rng.randrange(len(lines))
        p = _pred(json.loads(lines[i]))
        if p["type"] != "effect.http":
            continue
        eid = p["body"]["effect_id"]
        for j in range(i + 1, len(lines)):
            pj = _pred(json.loads(lines[j]))
            if pj["type"] == "effect.http.result" and \
                    pj["body"]["effect_id"] == eid:
                lines[i], lines[j] = lines[j], lines[i]
                idx[i], idx[j] = idx[j], idx[i]
                set_lines(files, lines)
                set_index(files, idx)
                return files, keys
    return files, keys


def extra_keys_json_differs(s, files, keys, rng):
    """Bundled keys.json diverges from the trusted manifest. csverify does
    not read the bundled copy (recorded divergence), so both verifiers
    accept — this mutant is reported as a gap, not a detection."""
    km = copy.deepcopy(json.loads(files["keys.json"]))
    km[0]["not_before"] = "1999-01-01T00:00:00Z"
    files["keys.json"] = G.jdumps(km)
    return files, keys


MUTATORS = {
    1: class1_payload_bit,
    2: class2_sig_bit,
    3: class3_delete,
    4: class4_swap,
    5: class5_truncate,
    6: class6_foreign,
    7: class7_untrusted,
    8: class8_checkpoint,
    9: class9_duplicate,
    "policy": extra_policy,
    "contract": extra_contract,
    "result-before-effect": extra_result_before_effect,
    "keys-json-differs": extra_keys_json_differs,
}
