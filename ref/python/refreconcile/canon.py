#!/usr/bin/env python3
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# RFC 8785 JSON Canonicalization Scheme (JCS), needed by spec/04 §6.3:
# SHA-256(canonical(intent.input)) == SHA-256(canonical(call.arguments)).


def _esc(s):
    out = []
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _num(n):
    if isinstance(n, bool):  # bool is an int subclass; never reached via canon()
        raise TypeError("bool is not a number")
    if isinstance(n, int):
        return str(n)
    if n != n or n in (float("inf"), float("-inf")):
        raise ValueError("non-finite number cannot be canonicalized")
    if n == 0:
        return "0"  # ECMAScript String(-0) is "0"
    # ECMAScript Number::toString: shortest round-trip digits; fixed notation
    # for a decimal exponent in [-6, 20], exponential ("1e+21") outside it.
    # repr() yields the same shortest digits as the ECMAScript algorithm.
    from decimal import Decimal
    d = Decimal(repr(n))
    if d == d.to_integral_value() and d.adjusted() < 21:
        return str(int(d))
    if -6 <= d.adjusted() < 21:
        return format(d, "f")
    mant, exp = repr(n).lower().split("e")
    return "%se%+d" % (mant, int(exp))


def canon(obj):
    """Return the RFC 8785 canonical form of a JSON value as a str."""
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, str):
        return _esc(obj)
    if isinstance(obj, (int, float)):
        return _num(obj)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(canon(v) for v in obj) + "]"
    if isinstance(obj, dict):
        keys = sorted(obj.keys(), key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_esc(k) + ":" + canon(obj[k]) for k in keys) + "}"
    raise TypeError("cannot canonicalize %r" % type(obj))


def canon_sha256(obj):
    """hex SHA-256 of the canonical form — the digest §6.3 compares."""
    import hashlib
    return hashlib.sha256(canon(obj).encode("utf-8")).hexdigest()
