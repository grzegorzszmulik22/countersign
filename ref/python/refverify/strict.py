# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""Strict decoders per spec 03 §1–§2: duplicate keys, non-UTF-8, non-canonical
base64, bare NaN/Infinity and non-32-byte signatures are all rejected."""
import base64
import binascii
import json
import re

from .errors import VerifyError

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_TS = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


def _no_dup(pairs):
    seen = set()
    out = {}
    for k, v in pairs:
        if k in seen:
            raise ValueError(f"duplicate key {k!r}")
        seen.add(k)
        out[k] = v
    return out


def _no_const(x):
    raise ValueError(f"non-JSON constant {x}")


def loads(data, what, code="E_SCHEMA", record=None):
    """Strict JSON: UTF-8, no duplicate keys, no NaN/Infinity."""
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as e:
            raise VerifyError(code, f"{what}: non-UTF-8 input", record) from e
    else:
        text = data
    try:
        return json.loads(text, object_pairs_hook=_no_dup,
                          parse_constant=_no_const)
    except (json.JSONDecodeError, ValueError) as e:
        raise VerifyError(code, f"{what}: invalid JSON ({e})", record) from e


def b64d(s, what, code="E_SCHEMA", record=None):
    """Standard base64, canonical per RFC 4648 §3.5 (rejects unpadded,
    URL-safe alphabets, whitespace and non-canonical trailing bits)."""
    if not isinstance(s, str):
        raise VerifyError(code, f"{what}: base64 value is not a string", record)
    try:
        raw = base64.b64decode(s.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as e:
        raise VerifyError(code, f"{what}: invalid base64", record) from e
    if base64.b64encode(raw).decode() != s:
        raise VerifyError(code, f"{what}: non-canonical base64", record)
    return raw


def is_hex(s, n):
    return isinstance(s, str) and bool(
        re.fullmatch(r"[0-9a-f]{%d}" % n, s))


def check_hex(s, n, what, record=None):
    if not is_hex(s, n):
        raise VerifyError("E_SCHEMA", f"{what}: not {n} lowercase hex chars",
                          record)
    return s


def parse_ts(s, what="ts", record=None):
    """RFC 3339 timestamp → (seconds:int, nanos:int). Accepts Z and offsets."""
    if not isinstance(s, str):
        raise VerifyError("E_SCHEMA", f"{what}: not a string", record)
    m = _TS.match(s)
    if not m:
        raise VerifyError("E_SCHEMA", f"{what}: not RFC 3339: {s!r}", record)
    import datetime
    y, mo, d, hh, mm, ss, frac, off = m.groups()
    try:
        dt = datetime.datetime(int(y), int(mo), int(d), int(hh), int(mm),
                               int(ss), tzinfo=datetime.timezone.utc)
    except ValueError as e:
        raise VerifyError("E_SCHEMA", f"{what}: bad date {s!r}", record) from e
    nanos = int((frac[1:] if frac else "0").ljust(9, "0")[:9])
    if off != "Z":
        sign = 1 if off[0] == "+" else -1
        ohh, omm = map(int, off[1:].split(":"))
        dt -= datetime.timedelta(minutes=sign * (ohh * 60 + omm))
    return int(dt.timestamp()), nanos


def ts_le(a, b):
    return a <= b
