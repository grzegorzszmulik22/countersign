# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""DSSE v1 envelope, in-toto Statement v1 and record predicate decoding
(spec 03 §1–§4). Every rejection carries the reference verifier's detail."""
import hashlib

from . import schema
from .strict import SchemaError, _quote, go_typed, parse_node

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://countersign.dev/record/v1"

ZERO_HASH = "0" * 64


def pae(payload_type, payload):
    """DSSEv1 <len(type)> <type> <len(payload)> <payload>."""
    t = payload_type.encode("utf-8")
    return (b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " +
            str(len(payload)).encode() + b" " + payload)


def record_hash(env):
    """Record hash of 03 §3: hex SHA-256(PAE(payloadType, payload))."""
    return hashlib.sha256(
        pae(env["payload_type"], env["payload"])).hexdigest()


def session_subject_digest(session):
    """sha256 of the UTF-8 session ID — the statement subject digest."""
    return hashlib.sha256(session.encode("utf-8")).hexdigest()


def emitter_role(emitter):
    """'<role>/<ULID instance>' → (role, instance); raises ValueError with
    the reference diagnostics 'malformed emitter %q' / 'unknown role %q'."""
    role, sep, instance = emitter.partition("/")
    if not sep or role == "" or not _valid_ulid(instance):
        raise ValueError("malformed emitter %s" % _quote(emitter))
    if role not in ("broker", "controller", "world", "observer"):
        raise ValueError("unknown emitter role %s" % _quote(role))
    return role, instance


def _valid_ulid(s):
    if len(s) != 26:
        return False
    # valid set: 0-9 A-H J-M N-P Q-T V-Z  (no I, no U)
    ok = ("0123456789" + "ABCDEFGH" + "JKLM" + "NOP" + "QRST" + "VWXYZ")
    return all(c in ok for c in s)


def _valid_keyid(s):
    return len(s) == 32 and all(c in "0123456789abcdef" for c in s)


def decode_envelope(line):
    """One stored line → dict {payloadType, payload(bytes), sig_keyid, sig}."""
    if b"\n" in line:
        raise SchemaError("record line contains a newline")
    env = go_typed(parse_node(line), schema.ENVELOPE)
    if env["payloadType"] != PAYLOAD_TYPE:
        raise SchemaError(
            "unsupported payloadType %s" % _quote(env["payloadType"]))
    sigs = env["signatures"] or []
    if len(sigs) != 1:
        raise SchemaError(
            "envelope must carry exactly one signature, got %d" % len(sigs))
    sig = sigs[0]["sig"]
    if len(sig) != 64:
        raise SchemaError("signature is %d bytes, want 64" % len(sig))
    if not _valid_keyid(sigs[0]["keyid"]):
        raise SchemaError("malformed keyid %s" % _quote(sigs[0]["keyid"]))
    return {
        "payload_type": env["payloadType"],
        "payload": env["payload"],
        "keyid": sigs[0]["keyid"],
        "sig": sig,
    }


def decode_statement(payload):
    """Statement bytes → dict {_type, subject[], predicateType, predicate}."""
    st = go_typed(parse_node(payload), schema.STATEMENT)
    if st["_type"] != STATEMENT_TYPE:
        raise SchemaError("wrong _type %s" % _quote(st["_type"]))
    if st["predicateType"] != PREDICATE_TYPE:
        raise SchemaError(
            "wrong predicateType %s" % _quote(st["predicateType"]))
    if len(st["subject"] or []) != 1:
        raise SchemaError(
            "statement must have exactly one subject, got %d"
            % len(st["subject"] or []))
    if not st["predicate"]:
        raise SchemaError("empty predicate")
    return st


def decode_predicate(pred_bytes):
    """Predicate bytes → record dict incl. decoded body."""
    p = go_typed(parse_node(pred_bytes), schema.PREDICATE)
    if p["v"] != 1:
        raise SchemaError("unsupported record version %d" % p["v"])
    body_spec = schema.BODIES.get(p["type"])
    if body_spec is None:
        raise SchemaError("unknown record type %s" % _quote(p["type"]))
    if p["body"] is None or len(p["body"]) == 0:
        raise SchemaError("missing body for %s" % _quote(p["type"]))
    # The body decodes into a struct pointer: JSON null → nil body.
    body_node = parse_node(p["body"])
    if body_node[0] == "null":
        raise SchemaError("body of %s is null" % _quote(p["type"]))
    try:
        body = go_typed(body_node, body_spec)
    except SchemaError as e:
        raise SchemaError("body of %s: %s" % (_quote(p["type"]), e)) from e
    return {
        "v": p["v"], "type": p["type"], "id": p["id"],
        "session": p["session"], "emitter": p["emitter"],
        "eseq": p["eseq"], "eprev": p["eprev"], "ts": p["ts"],
        "body": body,
    }


def decode_record_line(line):
    """Envelope → statement → predicate; returns (env, st, rec)."""
    env = decode_envelope(line)
    st = decode_statement(env["payload"])
    rec = decode_predicate(st["predicate"])
    return env, st, rec
