#!/usr/bin/env python3
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Generates test/vectors/policy/matching.yaml for M3.1.
#
# The "expected" column is derived by reasoning from the spec text
# (04-policy-and-reconciliation.md §1 defaults table and §2 steps 1-2):
# - grants are tried in document order, first match wins;
# - "*.dom" matches one or more labels below dom, never the apex;
# - "*" alone matches any host that is not an IP literal; an IP-literal
#   request host matches only a grant listing that literal;
# - request host is lowercased and one trailing root dot is dropped before
#   matching; methods compare case-sensitively;
# - in path globs "*" is a wildcard inside one segment and "**" spans any
#   number of whole segments including zero;
# - percent-encoded unreserved characters are decoded before matching;
# - scheme defaults to https, ports to [443] ([80] for http), methods to all,
#   paths to ["/**"]; an explicit empty list matches nothing;
# - a matched deny grant yields DENY_GRANT, no match yields NO_GRANT;
# - the §2.1 pre-checks yield SMUGGLING_SUSPECT.
#
# M3.6 adds the git-smart-http semantic matcher (04 §2). For repository
# OWNER/REPO, one optional ".git" suffix on the repo segment is ignored on
# both sides; every other byte of owner/repo is case-sensitive. Permitted:
#   read  = GET /<o>/<r>[.git]/info/refs?service=git-upload-pack,
#           POST /<o>/<r>[.git]/git-upload-pack
#   write = the above plus service=git-receive-pack and POST git-receive-pack
# The info/refs query is exactly "service=<svc>"; POST endpoints carry no
# query at all. Any other path, method or service value does not match.
# It is written independently of the Go matcher and of
# ref/python/refreconcile/match.py; the generated file is reviewed by reading.
import ipaddress
import json
import re

UNRES = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
HEX = set("0123456789abcdefABCDEF")
BAD = re.compile(r"%(2e|2f|5c|00)", re.I)


def is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def norm(h):
    h = h.lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h[:-1] if h.endswith(".") else h


def host_ok(pat, h):
    if is_ip(h):
        return pat == h
    if pat == "*":
        return True
    if pat.startswith("*."):
        return h.endswith(pat[1:])
    return h == pat


def smuggle(p):
    return ("\\" in p or BAD.search(p) is not None
            or any(ord(c) < 32 or c == "\x7f" for c in p)
            or any(s in (".", "..") for s in p.split("/")))


def decode(p):
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


def path_ok(glob, path):
    gs, ps = glob.split("/"), path.split("/")

    def m(gi, pi):
        if gi == len(gs):
            return pi == len(ps)
        if gs[gi] == "**":
            return any(m(gi + 1, pi + k) for k in range(len(ps) - pi + 1))
        return pi < len(ps) and seg_ok(gs[gi], ps[pi]) and m(gi + 1, pi + 1)
    return m(0, 0)


def git_seg(seg):
    """One optional ".git" suffix on the repo segment is transport syntax."""
    return seg[:-4] if seg.endswith(".git") else seg


def git_ok(m, r, path):
    """04 §2 git-smart-http: is this request inside the matcher's set?"""
    git = (m.get("matcher") or {}).get("git-smart-http")
    if git is None:
        return False
    query = r.get("query") or ""
    segs = path[1:].split("/") if path.startswith("/") else path.split("/")
    if len(segs) == 4 and segs[2] == "info" and segs[3] == "refs":
        if r.get("method") != "GET":
            return False
        if query == "service=git-upload-pack":
            need = "read"
        elif query == "service=git-receive-pack":
            need = "write"
        else:
            return False
    elif len(segs) == 3 and segs[2] in ("git-upload-pack", "git-receive-pack"):
        if r.get("method") != "POST" or query != "":
            return False
        need = "read" if segs[2] == "git-upload-pack" else "write"
    else:
        return False
    if need == "write" and git.get("access") != "write":
        return False
    owner, name = segs[0], git_seg(segs[1])
    if not owner or not name:
        return False
    for e in git.get("repos") or []:
        es = e.split("/")
        if len(es) == 2 and es[0] == owner and git_seg(es[1]) == name and name:
            return True
    return False


def expected(pol, r):
    """Spec-reasoned decision for one row: (grant_id|None, reason|None)."""
    h = r.get("host", "").lower()
    if any((r.get(k) or h).lower() != h for k in ("sni", "connect")):
        return None, "SMUGGLING_SUSPECT"
    raw = r.get("path") or "/"
    if smuggle(raw):
        return None, "SMUGGLING_SUSPECT"
    p = decode(raw)
    scheme = r.get("scheme") or "https"
    port = r.get("port") or (80 if scheme == "http" else 443)
    host = norm(r.get("host", ""))
    for g in pol["spec"]["grants"]:
        m = g["match"]
        if scheme != m.get("scheme", "https"):
            continue
        if port not in m.get("ports", [80 if m.get("scheme") == "http" else 443]):
            continue
        if not any(host_ok(norm(x), host) for x in m["hosts"]):
            continue
        if m.get("matcher"):
            if not git_ok(m, r, p):
                continue
        else:
            if "methods" in m and r.get("method") not in m["methods"]:
                continue
            if not any(path_ok(x, p) for x in m.get("paths", ["/**"])):
                continue
        return g["id"], "DENY_GRANT" if g.get("action") == "deny" else None
    return None, "NO_GRANT"


def grant(gid, hosts, action=None, methods=None, paths=None, scheme=None,
          ports=None, mode=None, matcher=None, credential=None):
    g, m = {"id": gid}, {"hosts": hosts}
    for k, v in (("scheme", scheme), ("ports", ports), ("methods", methods),
                 ("paths", paths), ("matcher", matcher)):
        if v is not None:
            m[k] = v
    g["match"] = m
    if action:
        g["action"] = action
    if mode:
        g["mode"] = mode
    if credential:
        g["credential"] = credential
    return g


def doc(name, grants, mode="enforce"):
    return {"apiVersion": "countersign.dev/v1alpha1", "kind": "SessionPolicy",
            "metadata": {"name": name},
            "spec": {"mode": mode, "scenario": "agent", "grants": grants}}


POLICIES = {
    "main": doc("main", [
        grant("deny-admin", ["api.example.com"], action="deny", paths=["/admin/**"]),
        grant("api-read", ["api.example.com"], methods=["GET", "HEAD"],
              paths=["/v1/**", "/v*/items"]),
        grant("api-write", ["api.example.com"], methods=["POST", "PUT"],
              paths=["/v1/items", "/v1/items/*/comments"]),
        grant("wild-pub", ["*.example.com"], methods=["GET"], paths=["/pub/**"]),
        grant("api-any", ["api.example.com"]),
    ]),
    "order-a": doc("order-a", [
        grant("broad", ["shop.test"], paths=["/**"]),
        grant("narrow", ["shop.test"], methods=["POST"]),
    ]),
    "order-b": doc("order-b", [
        grant("narrow", ["shop.test"], methods=["POST"]),
        grant("broad", ["shop.test"], paths=["/**"]),
    ]),
    "deny-first": doc("deny-first", [
        grant("deny-x", ["svc.test"], action="deny", paths=["/x/**"]),
        grant("allow-x", ["svc.test"], paths=["/x/**"]),
    ]),
    "deny-last": doc("deny-last", [
        grant("allow-x", ["svc.test"], paths=["/x/**"]),
        grant("deny-x", ["svc.test"], action="deny", paths=["/x/**"]),
    ]),
    "schemes": doc("schemes", [
        grant("secure", ["secure.test"]),
        grant("plain", ["insecure.test"], scheme="http"),
        grant("both-p", ["multi.test"], ports=[443, 8443]),
        grant("p8443", ["alt.test"], ports=[8443]),
        grant("httpx", ["odd.test"], scheme="http", ports=[8080]),
    ]),
    "ip": doc("ip", [
        grant("ipgrant", ["203.0.113.7"]),
        grant("ipwild", ["*.example.com"]),
        grant("v6", ["::1"]),
    ]),
    "idn": doc("idn", [
        grant("idn", ["xn--nxasmq6b.example", "xn--bcher-kva.test"]),
    ]),
    "pass": doc("pass", [
        grant("tunnel", ["vpn.test"], mode="passthrough"),
    ]),
    "star": doc("star", [
        grant("any", ["*"]),
    ]),
    "learn": doc("learn", [
        grant("any-cred", ["*"], credential={
            "ref": {"secret": "s", "key": "k"},
            "inject": {"header": "x-api-key"}, "placeholderEnv": "X_KEY"}),
    ], mode="learn"),
    "gitlike": doc("gitlike", [
        grant("repo", ["code.test"], methods=["GET"],
              paths=["/repos/acme/widgets", "/repos/acme/*/info/refs"]),
        grant("repog", ["code.test"], methods=["POST"], paths=["/repos/acme/*"]),
    ]),
    "empty-lists": doc("empty-lists", [
        grant("e-methods", ["em.test"], methods=[]),
        grant("e-paths", ["ep.test"], paths=[]),
        grant("e-ports", ["epo.test"], ports=[]),
        grant("e-ok", ["e.test"]),
    ]),
    # --- M3.6 git-smart-http policies ----------------------------------------
    "gitread": doc("gitread", [
        grant("repo-r", ["code.test"],
              matcher={"git-smart-http": {"repos": ["acme/widgets"],
                                          "access": "read"}}),
    ]),
    "gitwrite": doc("gitwrite", [
        grant("repo-w", ["code.test"],
              matcher={"git-smart-http": {"repos": ["acme/widgets"],
                                          "access": "write"}}),
    ]),
    "gitmulti": doc("gitmulti", [
        grant("multi", ["code.test"],
              matcher={"git-smart-http": {"repos": ["acme/widgets",
                                                    "acme/gadgets"],
                                          "access": "write"}}),
    ]),
    "gittwo": doc("gittwo", [
        grant("r-read", ["code.test"],
              matcher={"git-smart-http": {"repos": ["acme/widgets"],
                                          "access": "read"}}),
        grant("r-write", ["code.test"],
              matcher={"git-smart-http": {"repos": ["acme/gadgets"],
                                          "access": "write"}}),
    ]),
    "gitorder": doc("gitorder", [
        grant("broad", ["code.test"], paths=["/**"]),
        grant("repo", ["code.test"],
              matcher={"git-smart-http": {"repos": ["acme/widgets"],
                                          "access": "read"}}),
    ]),
    "gitdeny": doc("gitdeny", [
        grant("deny-git", ["code.test"], action="deny",
              matcher={"git-smart-http": {"repos": ["acme/secret"],
                                          "access": "write"}}),
        grant("repo", ["code.test"],
              matcher={"git-smart-http": {"repos": ["acme/secret",
                                                    "acme/widgets"],
                                          "access": "read"}}),
    ]),
    "gitdeny2": doc("gitdeny2", [
        grant("deny-r", ["code.test"], action="deny",
              matcher={"git-smart-http": {"repos": ["acme/secret"],
                                          "access": "read"}}),
        grant("repo", ["code.test"],
              matcher={"git-smart-http": {"repos": ["acme/secret"],
                                          "access": "write"}}),
    ]),
    "gitdot": doc("gitdot", [
        grant("dot", ["code.test"],
              matcher={"git-smart-http": {"repos": ["acme/widgets.git"],
                                          "access": "read"}}),
    ]),
}

rows = []


def row(name, pol, req):
    g, rsn = expected(POLICIES[pol], req)
    rows.append({"name": name, "policy": pol, "request": req,
                 "expected": {"grant": g, "reason": rsn}})


def req(host, method="GET", path="/", scheme=None, port=None, sni=None,
        connect=None, query=None):
    r = {"method": method, "host": host, "path": path}
    for k, v in (("scheme", scheme), ("port", port), ("sni", sni),
                 ("connect", connect), ("query", query)):
        if v is not None:
            r[k] = v
    return r


# --- cross product on "main": hosts x methods x paths -----------------------
MAIN_HOSTS = ["api.example.com", "API.EXAMPLE.COM", "api.example.com.",
              "a.example.com", "a.b.example.com", "example.com", "other.test",
              "203.0.113.9"]
MAIN_PATHS = ["/v1/messages", "/v1/items", "/v1/items/x/comments",
              "/v1/items/a/b/comments", "/admin/x", "/admin", "/pub/x",
              "/v2/messages", "/v1/", "/x/../y"]
n = 0
for h in MAIN_HOSTS:
    for meth in ["GET", "POST", "get"]:
        for p in MAIN_PATHS:
            n += 1
            row("main-%03d" % n, "main", req(h, meth, p))

# --- scheme x port x host on "schemes" --------------------------------------
n = 0
for h in ["secure.test", "insecure.test", "multi.test", "alt.test", "odd.test"]:
    for scheme in ["https", "http"]:
        for port in [None, 443, 8443, 8080, 80]:
            n += 1
            row("sch-%02d" % n, "schemes",
                req(h, "GET", "/x", scheme=scheme, port=port))

# --- order / deny policies ---------------------------------------------------
for pol in ["order-a", "order-b"]:
    row(pol + "-post", pol, req("shop.test", "POST", "/cart"))
    row(pol + "-get", pol, req("shop.test", "GET", "/cart"))
    row(pol + "-put", pol, req("shop.test", "PUT", "/cart"))
for pol in ["deny-first", "deny-last"]:
    row(pol + "-hit", pol, req("svc.test", "GET", "/x/y"))
    row(pol + "-miss", pol, req("svc.test", "GET", "/z"))

# --- targeted host rows ------------------------------------------------------
row("wild-apex", "star", req("anything.else.test"))
row("star-ip", "star", req("192.0.2.1"))
row("star-v6", "star", req("[::1]"))
row("learn-any", "learn", req("totally.unknown.example"))
row("learn-ip", "learn", req("198.51.100.2"))
row("ip-listed", "ip", req("203.0.113.7"))
row("ip-listed-dot", "ip", req("203.0.113.7."))
row("ip-unlisted", "ip", req("203.0.113.8"))
row("ip-wild-no", "ip", req("8.8.8.8"))
row("ip-v6", "ip", req("[::1]"))
row("ip-v6-nobr", "ip", req("::1"))
row("idn-alabel", "idn", req("xn--nxasmq6b.example"))
row("idn-alabel2", "idn", req("xn--bcher-kva.test"))
row("idn-other", "idn", req("xn--other.example"))
row("pass-any", "pass", req("vpn.test", "POST", "/anything/here"))
row("pass-http", "pass", req("vpn.test", "GET", "/", scheme="http"))

# --- gitlike / path-glob edges ----------------------------------------------
row("git-exact", "gitlike", req("code.test", "GET", "/repos/acme/widgets"))
row("git-evil", "gitlike", req("code.test", "GET", "/repos/acme/widgets-evil"))
row("git-infos", "gitlike", req("code.test", "GET", "/repos/acme/w/info/refs"))
row("git-deep", "gitlike", req("code.test", "GET", "/repos/acme/a/b"))
row("git-star-one", "gitlike", req("code.test", "POST", "/repos/acme/x"))
row("git-star-two", "gitlike", req("code.test", "POST", "/repos/acme/a/b"))
row("git-post-widget", "gitlike", req("code.test", "POST", "/repos/acme/widgets"))

# --- empty lists match nothing ----------------------------------------------
row("empty-methods", "empty-lists", req("em.test", "GET", "/"))
row("empty-paths", "empty-lists", req("ep.test", "GET", "/x"))
row("empty-ports", "empty-lists", req("epo.test", "GET", "/"))
row("empty-ok", "empty-lists", req("e.test", "PUT", "/anything"))

# --- pre-checks (04 §2 step 1) ------------------------------------------------
for i, p in enumerate(["/a/../b", "/x/./y", "/x/%2e/y", "/x%2fy", "/x%2Fy",
                       "/x\\y", "/x%5cy", "/x%00y", "/x%2E%2E/y", "/x\t/y",
                       "/x%2e", "/%2f"]):
    row("precheck-path-%02d" % i, "main", req("api.example.com", "GET", p))
row("precheck-sni", "main", req("api.example.com", "GET", "/v1/messages",
                                sni="evil.test"))
row("precheck-connect", "main", req("api.example.com", "GET", "/v1/messages",
                                    connect="evil.test"))
row("precheck-sni-case-ok", "main", req("api.example.com", "GET", "/v1/messages",
                                        sni="API.EXAMPLE.COM"))
row("precheck-connect-ok", "main", req("api.example.com", "GET", "/v1/messages",
                                       connect="api.example.com"))
row("empty-path", "main", req("api.example.com", "GET", ""))
row("query-ignored", "main", req("api.example.com", "GET", "/v1/messages",
                                 query="a=%2f&b=.."))
row("unreserved-decode", "main", req("api.example.com", "GET", "/v1/mess%61ges"))
row("unreserved-decode2", "main", req("api.example.com", "GET", "/%7e1/messages"))
row("reserved-raw", "main", req("api.example.com", "GET", "/v1/mess%20ages"))

# --- git-smart-http matcher (M3.6, 04 §2): every endpoint x access ------------
U = "service=git-upload-pack"
R = "service=git-receive-pack"
IR = "/acme/widgets.git/info/refs"          # info/refs URL for the repo
IRN = "/acme/widgets/info/refs"             # same, no .git suffix
UP = "/acme/widgets.git/git-upload-pack"
UPN = "/acme/widgets/git-upload-pack"
RP = "/acme/widgets.git/git-receive-pack"
RPN = "/acme/widgets/git-receive-pack"

# read access: the two read endpoints match, both write endpoints do not.
row("gitm-r-001", "gitread", req("code.test", "GET", IR, query=U))
row("gitm-r-002", "gitread", req("code.test", "GET", IRN, query=U))
row("gitm-r-003", "gitread", req("code.test", "GET", IR, query=R))
row("gitm-r-004", "gitread", req("code.test", "POST", UP))
row("gitm-r-005", "gitread", req("code.test", "POST", UPN))
row("gitm-r-006", "gitread", req("code.test", "POST", RP))
row("gitm-r-007", "gitread", req("code.test", "POST", RPN))
# write access covers all four.
row("gitm-w-001", "gitwrite", req("code.test", "GET", IR, query=U))
row("gitm-w-002", "gitwrite", req("code.test", "GET", IR, query=R))
row("gitm-w-003", "gitwrite", req("code.test", "POST", UP))
row("gitm-w-004", "gitwrite", req("code.test", "POST", RP))
# endpoint shapes and the service parameter, byte-exact.
row("gitm-s-001", "gitread", req("code.test", "GET", IR))              # no query
row("gitm-s-002", "gitread", req("code.test", "GET", IR, query="service="))
row("gitm-s-003", "gitread", req("code.test", "GET", IR, query="service=git-dumb"))
row("gitm-s-004", "gitread", req("code.test", "GET", IR, query="Service=git-upload-pack"))
row("gitm-s-005", "gitread", req("code.test", "GET", IR, query="service=GIT-UPLOAD-PACK"))
row("gitm-s-006", "gitread", req("code.test", "GET", IR, query="service=git%2dupload%2dpack"))
row("gitm-s-007", "gitread", req("code.test", "GET", IR, query="service=git-upload-pack&x=1"))
row("gitm-s-008", "gitread", req("code.test", "GET", IR, query="x=1&service=git-upload-pack"))
row("gitm-s-009", "gitread", req("code.test", "GET", IR,
                               query="service=git-upload-pack&service=git-receive-pack"))
row("gitm-s-010", "gitread", req("code.test", "GET", IR, query="service=git-upload-pack%00"))
row("gitm-s-011", "gitread", req("code.test", "POST", UP, query="service=git-upload-pack"))
row("gitm-s-012", "gitread", req("code.test", "POST", UP, query="x=1"))
row("gitm-s-013", "gitwrite", req("code.test", "POST", RP, query="service=git-receive-pack"))
# wrong method on each endpoint shape.
row("gitm-m-001", "gitread", req("code.test", "POST", IR, query=U))
row("gitm-m-002", "gitread", req("code.test", "PUT", IR, query=U))
row("gitm-m-003", "gitread", req("code.test", "GET", UP))
row("gitm-m-004", "gitread", req("code.test", "PUT", UP))
row("gitm-m-005", "gitread", req("code.test", "HEAD", IR, query=U))
row("gitm-m-006", "gitwrite", req("code.test", "GET", RP))
row("gitm-m-007", "gitread", req("code.test", "DELETE", IR, query=U))
# repository scoping: prefix/suffix names, case, nesting, extra segments.
row("gitm-p-001", "gitread", req("code.test", "GET",
                                 "/acme/widgets-evil.git/info/refs", query=U))
row("gitm-p-002", "gitread", req("code.test", "GET",
                                 "/acme/widget.git/info/refs", query=U))
row("gitm-p-003", "gitread", req("code.test", "GET",
                                 "/acme/widgetsx.git/info/refs", query=U))
row("gitm-p-004", "gitread", req("code.test", "GET",
                                 "/acme/widgets.gitx/info/refs", query=U))
row("gitm-p-005", "gitread", req("code.test", "GET",
                                 "/acme/widgets.git.git/info/refs", query=U))
row("gitm-p-006", "gitread", req("code.test", "GET",
                                 "/ACME/widgets.git/info/refs", query=U))
row("gitm-p-007", "gitread", req("code.test", "GET",
                                 "/acme/Widgets.git/info/refs", query=U))
row("gitm-p-008", "gitread", req("code.test", "GET",
                                 "/ACME/WIDGETS.git/info/refs", query=U))
row("gitm-p-009", "gitread", req("code.test", "GET",
                                 "/org/acme/widgets.git/info/refs", query=U))
row("gitm-p-010", "gitread", req("code.test", "GET",
                                 "/acme/widgets.git/extra/info/refs", query=U))
row("gitm-p-011", "gitread", req("code.test", "POST",
                                 "/acme/widgets.git/x/git-upload-pack"))
row("gitm-p-012", "gitread", req("code.test", "GET", "/acme/widgets.git/"))
row("gitm-p-013", "gitread", req("code.test", "GET", "/acme/widgets.git"))
row("gitm-p-014", "gitread", req("code.test", "GET", "/acme/widgets/info/refs/x",
                               query=U))
row("gitm-p-015", "gitread", req("code.test", "GET", "//widgets.git/git-upload-pack"))
row("gitm-p-016", "gitread", req("code.test", "GET", "/acme//info/refs", query=U))
row("gitm-p-017", "gitread", req("code.test", "GET", "/acme/.git/info/refs", query=U))
# endpoint letter case is significant.
row("gitm-c-001", "gitread", req("code.test", "GET",
                                 "/acme/widgets.git/INFO/refs", query=U))
row("gitm-c-002", "gitread", req("code.test", "GET",
                                 "/acme/widgets.git/info/REFS", query=U))
row("gitm-c-003", "gitread", req("code.test", "POST",
                                 "/acme/widgets.git/Git-Upload-Pack"))
# traversal and smuggling pre-checks fire before the matcher is consulted.
row("gitm-t-001", "gitread", req("code.test", "GET",
                                 "/acme/widgets/../widgets.git/info/refs", query=U))
row("gitm-t-002", "gitread", req("code.test", "GET",
                                 "/acme/%2e%2e/widgets.git/info/refs", query=U))
row("gitm-t-003", "gitread", req("code.test", "GET",
                                 "/acme/widgets%2egit/info/refs", query=U))
row("gitm-t-004", "gitread", req("code.test", "GET",
                                 "/acme%2fwidgets.git/info/refs", query=U))
# percent-encoded unreserved bytes decode before the matcher sees the path.
row("gitm-e-001", "gitread", req("code.test", "GET",
                                 "/acme/%77idgets.git/info/refs", query=U))
row("gitm-e-002", "gitread", req("code.test", "GET",
                                 "/acme/widgets.git/info/%72efs", query=U))
# host / scheme / port still gate a matcher grant.
row("gitm-h-001", "gitread", req("other.test", "GET", IR, query=U))
row("gitm-h-002", "gitread", req("code.test", "GET", IR, query=U, port=8443))
row("gitm-h-003", "gitread", req("code.test", "GET", IR, query=U, scheme="http"))
row("gitm-h-004", "gitread", req("CODE.TEST", "GET", IR, query=U))
# grant order and mixed policies.
row("gitm-o-001", "gitorder", req("code.test", "GET", IR, query=U))   # broad first
row("gitm-o-002", "gittwo", req("code.test", "POST", "/acme/gadgets.git/git-receive-pack"))
row("gitm-o-003", "gittwo", req("code.test", "POST", RP))             # widgets write: no fall-through
row("gitm-o-004", "gittwo", req("code.test", "GET", "/acme/gadgets.git/info/refs",
                                query=U))
row("gitm-o-005", "gitmulti", req("code.test", "GET", "/acme/gadgets.git/info/refs",
                                  query=R))
row("gitm-o-006", "gitdeny", req("code.test", "GET", "/acme/secret.git/info/refs",
                                 query=U))                            # write deny covers read
row("gitm-o-007", "gitdeny", req("code.test", "POST", "/acme/secret.git/git-receive-pack"))
row("gitm-o-008", "gitdeny", req("code.test", "POST", UP))
row("gitm-o-009", "gitdeny2", req("code.test", "GET", "/acme/secret.git/info/refs",
                                  query=U))
row("gitm-o-010", "gitdeny2", req("code.test", "POST", "/acme/secret.git/git-receive-pack"))
# a repos entry carrying ".git" names the same repository.
row("gitm-d-001", "gitdot", req("code.test", "GET", IRN, query=U))
row("gitm-d-002", "gitdot", req("code.test", "GET", IR, query=U))
row("gitm-d-003", "gitdot", req("code.test", "GET",
                                "/acme/widgets.git.git/info/refs", query=U))

# --- emit --------------------------------------------------------------------
def scalar(s):
    if isinstance(s, bool):
        return "true" if s else "false"
    if isinstance(s, (int, float)):
        return repr(s)
    if s is None:
        return "null"
    return json.dumps(s)


def flow(v):
    if isinstance(v, dict):
        return "{" + ", ".join(k + ": " + flow(x) for k, x in v.items()) + "}"
    if isinstance(v, list):
        return "[" + ", ".join(flow(x) for x in v) + "]"
    return scalar(v)


def simple(v):
    if isinstance(v, dict):
        return all(simple(x) for x in v.values())
    if isinstance(v, list):
        return all(not isinstance(x, (dict, list)) for x in v)
    return True


def block(v, ind):
    pad = "  " * ind
    out = []
    for k, x in v.items():
        if simple(x):
            out.append(pad + k + ": " + flow(x))
        elif isinstance(x, dict):
            out.append(pad + k + ":")
            out += block(x, ind + 1)
        else:
            out.append(pad + k + ":")
            out += blocklist(x, ind + 1)
    return out


def blocklist(v, ind):
    pad = "  " * ind
    out = []
    for x in v:
        if simple(x):
            out.append(pad + "- " + flow(x))
        else:
            first = True
            for k, y in x.items():
                pre = pad + "- " if first else pad + "  "
                if simple(y):
                    out.append(pre + k + ": " + flow(y))
                elif isinstance(y, dict):
                    out.append(pre + k + ":")
                    out += block(y, ind + 2)
                else:
                    out.append(pre + k + ":")
                    out += blocklist(y, ind + 2)
                first = False
    return out


out = ["# test/vectors/policy/matching.yaml — decision table for spec/04 §2",
       "# steps 1-2 (M3.1). At least 200 rows: the cross product of the",
       "# dimensions in spec/milestones/M3 (hosts, paths, methods, order,",
       "# scheme/ports) plus hand-written rows.",
       "#",
       "# The expected column was derived by reasoning from the spec text",
       "# (04 §1 defaults, §2 steps 1-2), never by running the Go matcher:",
       "# test/gen/matching_table.py contains an independent expression of",
       "# the rules and this file was reviewed by reading after generation.",
       "#",
       "# Row format: {name, policy, request, expected:{grant|null,reason}}.",
       "# reason is null (allow) | DENY_GRANT | NO_GRANT | SMUGGLING_SUSPECT.",
       "policies:"]
for name, pol in POLICIES.items():
    out.append("  %s: |" % name)
    out += ["    " + line for line in block(pol, 0)]
out.append("rows:")
for r in rows:
    q = flow({"name": r["name"], "policy": r["policy"],
              "request": r["request"], "expected": r["expected"]})
    out.append("  - " + q)
with open("test/vectors/policy/matching.yaml", "w") as fh:
    fh.write("\n".join(out) + "\n")
print("wrote %d rows, %d policies" % (len(rows), len(POLICIES)))
