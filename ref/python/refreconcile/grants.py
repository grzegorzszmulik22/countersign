#!/usr/bin/env python3
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Grant selection (spec/04 §2), reversibility class (spec/05 §1) and the
# autonomy condition (spec/05 §2), written from the specs for M9.1.
#
# The abstract trace's request object:
#   {method, scheme, authority, path, query, port?, sni?, connect?,
#    websocket?, mcp?: {method, server, tool, arguments}}
# authority is the lowercase host[:port]; query is the raw query without "?".
import ipaddress
import re

UNRES = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_HEXD = frozenset("0123456789abcdefABCDEF")
_BADPCT = re.compile(r"%(2e|2f|5c|00)", re.I)

READ_METHODS = frozenset(("GET", "HEAD", "OPTIONS"))
BOUNDARY_HOST = "countersign.internal"

COND_ORDER = {"allow": 0, "intent": 1, "review": 2, "deny": 3}


def is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def split_authority(authority, default_port):
    """'host[:port]' -> (host, port); brackets kept out of host."""
    a = (authority or "").lower()
    if a.startswith("["):
        end = a.find("]")
        if end != -1:
            host, rest = a[1:end], a[end + 1:]
            return host, int(rest[1:]) if rest.startswith(":") else default_port
    if ":" in a:
        host, _, p = a.rpartition(":")
        if p.isdigit():
            return host, int(p)
    return a, default_port


def norm_host(h):
    h = h.lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h[:-1] if h.endswith(".") else h


def host_ok(pat, h):
    if is_ip(h):                     # 04 §2.1: IP literal matches its listing only
        return pat == h
    if pat == "*":
        return True
    if pat.startswith("*."):
        return h.endswith(pat[1:])   # one or more labels, never the apex
    return h == pat


def smuggle_path(p):
    return ("\\" in p or _BADPCT.search(p) is not None
            or any(ord(c) < 32 or c == "\x7f" for c in p)
            or any(s in (".", "..") for s in p.split("/")))


def pct_decode_unres(p):
    """Percent-decode unreserved characters only (canonical path compare)."""
    out, i = [], 0
    while i < len(p):
        esc = p[i + 1:i + 3]
        if p[i] == "%" and len(esc) == 2 and esc[0] in _HEXD and esc[1] in _HEXD:
            c = chr(int(esc, 16))
            out.append(c if c in UNRES else "%" + esc.upper())
            i += 3
        else:
            out.append(p[i])
            i += 1
    return "".join(out)


def _seg_ok(pat, seg):
    rx = "".join("[^/]*" if c == "*" else re.escape(c) for c in pat)
    return re.fullmatch(rx, seg) is not None


def path_ok(glob, path):
    """'*' inside a segment; '**' any number of segments (04 §1 match.paths)."""
    gs, ps = glob.split("/"), path.split("/")

    def m(gi, pi):
        if gi == len(gs):
            return pi == len(ps)
        if gs[gi] == "**":
            return any(m(gi + 1, pi + k) for k in range(len(ps) - pi + 1))
        return pi < len(ps) and _seg_ok(gs[gi], ps[pi]) and m(gi + 1, pi + 1)
    return m(0, 0)


def _git_seg(seg):                   # one optional ".git" suffix is transport syntax
    return seg[:-4] if seg.endswith(".git") else seg


def git_op(request):
    """Classify a request as a git smart-HTTP op per 04 §2.

    Returns {"access": "read"|"write", "owner": str, "repo": str} or None.
    Scheme is not constrained here; grant matching handles it.
    """
    p = request.get("path") or "/"
    q = request.get("query") or ""
    segs = p[1:].split("/") if p.startswith("/") else p.split("/")
    if len(segs) == 4 and segs[2] == "info" and segs[3] == "refs":
        if request.get("method") != "GET":
            return None
        if q == "service=git-upload-pack":
            need = "read"
        elif q == "service=git-receive-pack":
            need = "write"
        else:
            return None
    elif len(segs) == 3 and segs[2] in ("git-upload-pack", "git-receive-pack"):
        if request.get("method") != "POST" or q != "":
            return None
        need = "read" if segs[2] == "git-upload-pack" else "write"
    else:
        return None
    owner, name = segs[0], _git_seg(segs[1])
    if not owner or not name:
        return None
    return {"access": need, "owner": owner, "repo": name}


def _git_grant_ok(matcher, op):
    git = (matcher or {}).get("git-smart-http")
    if git is None:
        return False
    if op["access"] == "write" and git.get("access") != "write":
        return False
    return any(
        len(e.split("/")) == 2 and e.split("/")[0] == op["owner"]
        and _git_seg(e.split("/")[1]) == op["repo"]
        for e in git.get("repos") or [])


def grant_match(grant, request):
    """Does this grant's `match` select the request? (04 §2 step 2.)"""
    m = grant.get("match") or {}
    scheme = request.get("scheme") or "https"
    if scheme != (m.get("scheme") or "https"):
        return False
    host, port = split_authority(request.get("authority"), 80 if scheme == "http" else 443)
    host = norm_host(host)
    ports = m.get("ports")
    if ports is None:
        ports = [80 if (m.get("scheme") or "https") == "http" else 443]
    if port not in ports:
        return False
    if not any(host_ok(norm_host(x), host) for x in m.get("hosts") or []):
        return False
    if m.get("matcher"):
        op = git_op(request)
        return op is not None and _git_grant_ok(m.get("matcher"), op)
    methods = m.get("methods")
    if methods is not None and request.get("method") not in methods:
        return False
    paths = m.get("paths")
    if paths is None:
        paths = ["/**"]
    path = pct_decode_unres(request.get("path") or "/")
    return any(path_ok(x, path) for x in paths)


def select_grant(policy, request):
    """04 §2 steps 1-2: pre-checks, then first matching grant in document order.

    Returns (grant, reason): grant is the selected object or None; reason is
    None on success else SMUGGLING_SUSPECT | NO_GRANT | DENY_GRANT.
    """
    host, _ = split_authority(request.get("authority"),
                              80 if (request.get("scheme") or "https") == "http" else 443)
    for k in ("sni", "connect"):
        v = request.get(k)
        if v is not None and norm_host(v) != norm_host(host):
            return None, "SMUGGLING_SUSPECT"
    raw = request.get("path") or "/"
    if smuggle_path(raw):
        return None, "SMUGGLING_SUSPECT"
    if is_ip(host) and not any(
            is_ip(norm_host(x)) and norm_host(x) == norm_host(host)
            for g in policy.get("grants") or []
            for x in (g.get("match") or {}).get("hosts") or []):
        return None, "NO_GRANT"
    for g in policy.get("grants") or []:
        if grant_match(g, request):
            if g.get("action") == "deny":
                return g, "DENY_GRANT"
            return g, None
    return None, "NO_GRANT"


def _stager_stages(grant, request):
    """05 §1 rule 4: is this request one the grant's stager stages?"""
    st = grant.get("stager") or {}
    if not st:
        return False
    if "git" in st:
        op = git_op(request)
        return op is not None and op["access"] == "write" and \
            _git_grant_ok((grant.get("match") or {}).get("matcher"), op)
    if "outbox" in st:
        # A deferred-send outbox stores requests that are not reads.
        return request.get("method") not in READ_METHODS
    return False


def _mcp_call(request):
    mcp = (request or {}).get("mcp")
    if mcp and mcp.get("method") == "tools/call":
        return mcp
    return None


def classify(grant, request, boundary_host=BOUNDARY_HOST):
    """05 §1: the reversibility class — first rule that applies wins."""
    mcp = (request or {}).get("mcp")
    if (grant.get("inspect") == "inference"
            or norm_host(split_authority(request.get("authority"), 443)[0]) == boundary_host
            or (grant.get("inspect") == "mcp" and mcp is not None
                and mcp.get("method") != "tools/call")):
        return "control"
    if grant.get("class"):
        return grant["class"]
    if grant.get("mode") == "passthrough" or request.get("websocket"):
        return "irreversible"
    if _stager_stages(grant, request):
        return "staged"
    if (grant.get("match") or {}).get("matcher"):
        op = git_op(request)
        if op is not None and op["access"] == "read" and \
                _git_grant_ok((grant.get("match") or {}).get("matcher"), op):
            return "safe"
    if request.get("method") in READ_METHODS:
        return "safe"
    call = _mcp_call(request)
    if call is not None:
        if grant.get("calls") == "serialized":      # brokered server, 05 §12
            return "control"
        if grant.get("inspect") == "mcp":
            return (grant.get("tools") or {}).get(call.get("tool"),
                                                 "irreversible")
    comp = grant.get("compensate") or {}
    for rule in ("restore", "deleteCreated"):
        methods = ((comp.get(rule) or {}).get("methods"))
        if methods and request.get("method") in methods:
            return "compensable"
    return "irreversible"


def condition(policy, grant, cls):
    """05 §2: strictest of autonomy[class] and the grant's requires.

    `requires: none` (a grant allowed to stand without intents, 04 §6.1
    STANDING) ranks as `allow` for strictness but is kept on the grant for
    the level computation.
    """
    cond = ((policy.get("autonomy") or {}).get(cls)) or "allow"
    req = grant.get("requires")
    if req in (None, "none"):
        req = "allow"
    return req if COND_ORDER[req] > COND_ORDER[cond] else cond
