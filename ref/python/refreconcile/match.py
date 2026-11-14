#!/usr/bin/env python3
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Reference matcher for spec/04-policy-and-reconciliation.md §2 steps 1-2,
# written from the spec (M3.1). Reads {"cases": [{"policy": <spec object>,
# "request": {...}}]} on stdin and prints a JSON array of
# {"grant": id|null, "reason": null|DENY_GRANT|NO_GRANT|SMUGGLING_SUSPECT}.
import ipaddress
import json
import re
import sys

UNRES = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
HEX = set("0123456789abcdefABCDEF")
BAD = re.compile(r"%(2e|2f|5c|00)", re.I)


def is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def norm(h):  # grant-side normalization: lowercase, brackets, one root dot
    h = h.lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h[:-1] if h.endswith(".") else h


def host_ok(pat, h):
    if is_ip(h):            # 04 §2.1: IP literal matches only its own listing
        return pat == h
    if pat == "*":
        return True
    if pat.startswith("*."):
        return h.endswith(pat[1:])          # one or more labels, never apex
    return h == pat


def smuggle(p):             # 04 §2.1 path rejects
    return ("\\" in p or BAD.search(p) is not None
            or any(ord(c) < 32 or c == "\x7f" for c in p)
            or any(s in (".", "..") for s in p.split("/")))


def decode(p):              # percent-decode unreserved characters only
    out, i = [], 0
    while i < len(p):
        esc = p[i + 1:i + 3]
        if p[i] == "%" and len(esc) == 2 and esc[0] in HEX and esc[1] in HEX:
            c = chr(int(esc, 16))
            out.append(c if c in UNRES else p[i:i + 3])
            i += 3
        else:
            out.append(p[i])
            i += 1
    return "".join(out)


def seg_ok(pat, seg):
    rx = "".join("[^/]*" if c == "*" else re.escape(c) for c in pat)
    return re.fullmatch(rx, seg) is not None


def path_ok(glob, path):    # "*" inside a segment; "**" any number of segments
    gs, ps = glob.split("/"), path.split("/")

    def m(gi, pi):
        if gi == len(gs):
            return pi == len(ps)
        if gs[gi] == "**":
            return any(m(gi + 1, pi + k) for k in range(len(ps) - pi + 1))
        return pi < len(ps) and seg_ok(gs[gi], ps[pi]) and m(gi + 1, pi + 1)
    return m(0, 0)


def match(pol, r):
    h = (r.get("host") or "").lower()
    if any((r.get(k) or h).lower() != h for k in ("sni", "connect")):
        return {"grant": None, "reason": "SMUGGLING_SUSPECT"}
    raw = r.get("path") or "/"
    if smuggle(raw):
        return {"grant": None, "reason": "SMUGGLING_SUSPECT"}
    p, scheme = decode(raw), r.get("scheme") or "https"
    port = r.get("port") or (80 if scheme == "http" else 443)
    host = norm(r.get("host") or "")
    for g in pol.get("grants") or []:
        m = g.get("match") or {}
        if m.get("matcher") or (r.get("scheme") or "https") != (m.get("scheme") or "https"):
            continue
        ports = m.get("ports")
        ports = [80 if (m.get("scheme") or "https") == "http" else 443] if ports is None else ports
        if port not in ports or not any(host_ok(norm(x), host) for x in m.get("hosts") or []):
            continue
        methods = m.get("methods")
        if methods is not None and r.get("method") not in methods:
            continue
        paths = m.get("paths")
        if paths is None:
            paths = ["/**"]
        if not any(path_ok(x, p) for x in paths):
            continue
        return {"grant": g.get("id"),
                "reason": "DENY_GRANT" if g.get("action") == "deny" else None}
    return {"grant": None, "reason": "NO_GRANT"}


cases = json.load(sys.stdin)["cases"]
print(json.dumps([match(c["policy"], c["request"]) for c in cases]))
