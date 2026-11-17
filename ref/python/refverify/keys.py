# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""Trusted key manifest (--keys) and per-record signature verification."""
import base64
import binascii
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import dsse, schema
from .strict import SchemaError, _quote, go_parse_first, go_typed


class KeysError(Exception):
    """Trusted-manifest load failure (exit-2 class)."""


def unmarshal_manifest(data):
    """keys.json bytes → list of manifest entries (dicts)."""
    try:
        node, _end = go_parse_first(data)
    except SchemaError as e:
        raise KeysError(str(e)) from e
    try:
        m = go_typed(node, schema.KEYS_MANIFEST)
    except SchemaError as e:
        raise KeysError(str(e)) from e
    return m or []


def find(manifest, keyid):
    for e in manifest:
        if e["key_id"] == keyid:
            return e
    return None


def _public(entry):
    try:
        b = base64.b64decode(entry["public_key"].encode("ascii"),
                             validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None
    if len(b) != 32:
        return None
    return b


_TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$")


def _parse_ts(s):
    """RFC 3339 (nano) → epoch nanoseconds, or None if unparseable."""
    m = _TS_RE.match(s)
    if not m:
        return None
    y, mo, d, hh, mm, ss, frac, off = m.groups()
    import datetime
    try:
        dt = datetime.datetime(int(y), int(mo), int(d), int(hh), int(mm),
                               int(ss), tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    nanos = int(frac.ljust(9, "0")) if frac else 0
    if off != "Z":
        sign = 1 if off[0] == "+" else -1
        ohh, omm = int(off[1:3]), int(off[4:6])
        if ohh > 23 or omm > 59:
            return None
        dt -= datetime.timedelta(minutes=sign * (ohh * 60 + omm))
    return int(dt.timestamp()) * 10**9 + nanos


def covers_ts(entry, ts):
    t = _parse_ts(ts)
    if t is None:
        return False
    nb = _parse_ts(entry["not_before"])
    if nb is None or t < nb:
        return False
    if entry["not_after"] is not None:
        na = _parse_ts(entry["not_after"])
        if na is None or t > na:
            return False
    return True


def verify_record(env, rec, manifest):
    """V3 of §10 → None, or the error string starting E_KEY/E_SIG."""
    keyid = env["keyid"]
    entry = find(manifest, keyid)
    if entry is None:
        return "E_KEY: unknown key %s" % keyid
    try:
        role, _inst = dsse.emitter_role(rec["emitter"])
    except ValueError as e:
        return "E_KEY: %s" % e
    if entry["role"] != "emitter:" + role:
        return ("E_KEY: key %s role %s cannot sign %s"
                % (keyid, _quote(entry["role"]), rec["emitter"]))
    if not covers_ts(entry, rec["ts"]):
        return "E_KEY: key %s not valid at %s" % (keyid, rec["ts"])
    pub = _public(entry)
    if pub is None:
        return "E_KEY: bad public_key for %s" % keyid
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(
            env["sig"], dsse.pae(env["payload_type"], env["payload"]))
    except (InvalidSignature, ValueError):
        return "E_SIG: signature on %s invalid" % rec["id"]
    return None
