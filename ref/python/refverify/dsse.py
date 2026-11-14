# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""DSSE v1 envelope and in-toto Statement v1 parsing (spec 03 §1–§2)."""
import hashlib

from .errors import VerifyError
from . import strict

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://countersign.dev/record/v1"


def pae(payload_type, payload):
    """DSSEv1 <len(type)> <type> <len(payload)> <payload> — lengths ASCII
    decimal, payload = the decoded statement bytes."""
    t = payload_type.encode("utf-8")
    return (b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " +
            str(len(payload)).encode() + b" " + payload)


def record_hash(payload_type, payload):
    """Record hash per spec 03 §3: SHA-256(PAE)."""
    return hashlib.sha256(pae(payload_type, payload)).hexdigest()


def parse_envelope(line, record=None):
    """One stored line (no newline) → (payload: bytes, keyid: str,
    sig: bytes). Envelope is exactly {payloadType, payload, signatures:[1]}."""
    env = strict.loads(line, "envelope", record=record)
    if not isinstance(env, dict):
        raise VerifyError("E_SCHEMA", "envelope: not an object", record)
    if set(env) != {"payloadType", "payload", "signatures"}:
        raise VerifyError("E_SCHEMA",
                          f"envelope: keys must be exactly "
                          f"payloadType/payload/signatures, got {sorted(env)}",
                          record)
    if env["payloadType"] != PAYLOAD_TYPE:
        raise VerifyError("E_SCHEMA",
                          f"payloadType {env['payloadType']!r} != {PAYLOAD_TYPE!r}",
                          record)
    payload = strict.b64d(env["payload"], "payload", record=record)
    sigs = env["signatures"]
    if not isinstance(sigs, list):
        raise VerifyError("E_SCHEMA", "signatures: not a list", record)
    if len(sigs) != 1:
        raise VerifyError("E_SCHEMA",
                          f"signatures: exactly 1 required, got {len(sigs)}",
                          record)
    s = sigs[0]
    if not isinstance(s, dict) or set(s) != {"keyid", "sig"}:
        raise VerifyError("E_SCHEMA", "signature entry: keys must be keyid+sig",
                          record)
    kid = strict.check_hex(s["keyid"], 32, "signature keyid", record)
    sig = strict.b64d(s["sig"], "signature sig", record=record)
    if len(sig) != 64:
        raise VerifyError("E_SCHEMA", f"signature not 64 bytes: {len(sig)}",
                          record)
    return payload, kid, sig


def parse_statement(payload, record=None):
    """Statement bytes → statement dict. Validates the in-toto v1 shape and
    the countersign predicateType; the predicate's per-type body schema is
    checked separately (records.schema)."""
    st = strict.loads(payload, "statement", record=record)
    if not isinstance(st, dict):
        raise VerifyError("E_SCHEMA", "statement: not an object", record)
    if set(st) != {"_type", "subject", "predicateType", "predicate"}:
        raise VerifyError("E_SCHEMA",
                          f"statement: keys must be exactly "
                          f"_type/subject/predicateType/predicate, got {sorted(st)}",
                          record)
    if st["_type"] != STATEMENT_TYPE:
        raise VerifyError("E_SCHEMA", f"_type {st['_type']!r}", record)
    if st["predicateType"] != PREDICATE_TYPE:
        raise VerifyError("E_SCHEMA",
                          f"predicateType {st['predicateType']!r}", record)
    subj = st["subject"]
    if (not isinstance(subj, list) or len(subj) != 1 or
            not isinstance(subj[0], dict) or
            set(subj[0]) != {"name", "digest"}):
        raise VerifyError("E_SCHEMA",
                          "subject: exactly one {name, digest} entry", record)
    d = subj[0]["digest"]
    if not isinstance(d, dict) or set(d) != {"sha256"} or \
            not strict.is_hex(d["sha256"], 64):
        raise VerifyError("E_SCHEMA", "subject.digest: needs {sha256: hex64}",
                          record)
    if not isinstance(subj[0]["name"], str):
        raise VerifyError("E_SCHEMA", "subject.name: not a string", record)
    if not isinstance(st["predicate"], dict):
        raise VerifyError("E_SCHEMA", "predicate: not an object", record)
    return st
