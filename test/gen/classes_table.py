#!/usr/bin/env python3
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Generates test/vectors/policy/classes.yaml for M5.2.
#
# The "expected" column is derived by reasoning from the spec text
# (05-transactions.md §1 ordered class rules and §2 strictest condition),
# never by running internal/classify or ref/python/refclassify: this file
# contains an independent expression of the rules and the generated output
# is reviewed by reading.
#
# §1 rules, in order (first match wins):
#   1 inspect:inference | host == countersign.internal | MCP protocol
#     message != tools/call on inspect:mcp            -> control
#   2 grant class: declared                            -> that class
#     (declared safe on non-GET / tunnel / websocket -> declared_safe)
#   3 mode:passthrough | websocket upgrade            -> irreversible
#   4 grant stager stages the request (git write in matcher scope;
#     outbox for non-reads)                           -> staged
#   5 smart-HTTP read (upload-pack, its info/refs) in matcher -> safe
#   6 GET | HEAD | OPTIONS                            -> safe
#   7 tools/call on brokered (calls:serialized)       -> control
#   8 tools/call else: grant tools map, default irreversible
#   9 compensate rule listing this method             -> compensable
#  10 otherwise                                       -> irreversible
#
# §2: condition = strictest of autonomy[class] (default allow), grant
# requires, and for compensable/irreversible the whenTainted outcome for
# the labels present (04 §8). allow < intent < review < deny.
import json
import sys

READ = {"GET", "HEAD", "OPTIONS"}
ORDER = {"allow": 0, "intent": 1, "review": 2, "deny": 3}
NAME = ["allow", "intent", "review", "deny"]
ROWS = []


def git_op(r):
    segs = r["path"].split("/")
    if segs and segs[0] == "":
        segs = segs[1:]
    if len(segs) == 4 and segs[2] == "info" and segs[3] == "refs":
        if r["method"] != "GET":
            return None
        q = r.get("query", "")
        if q == "service=git-upload-pack":
            acc = "read"
        elif q == "service=git-receive-pack":
            acc = "write"
        else:
            return None
    elif len(segs) == 3 and segs[2] in ("git-upload-pack", "git-receive-pack"):
        if r["method"] != "POST" or r.get("query", ""):
            return None
        acc = "read" if segs[2] == "git-upload-pack" else "write"
    else:
        return None
    repo = segs[1][:-4] if segs[1].endswith(".git") else segs[1]
    return (acc, segs[0], repo) if segs[0] and repo else None


def covers(matcher, op):
    git = (matcher or {}).get("git-smart-http") or {}
    if op[0] == "write" and git.get("access") != "write":
        return False
    for e in git.get("repos") or []:
        p = e.split("/")
        if len(p) == 2:
            n = p[1][:-4] if p[1].endswith(".git") else p[1]
            if p[0] == op[1] and n == op[2]:
                return True
    return False


def classify(grant, r):
    mcp = r.get("mcp")
    # 1
    if (grant.get("inspect") == "inference"
            or r["host"].split(":")[0].rstrip(".").lower() == "countersign.internal"
            or (grant.get("inspect") == "mcp" and mcp
                and mcp.get("method") != "tools/call")):
        return "control"
    # 2
    if grant.get("class"):
        return grant["class"]
    # 3
    if grant.get("mode") == "passthrough" or r.get("websocket"):
        return "irreversible"
    # 4
    stager = grant.get("stager") or {}
    if "git" in stager:
        op = git_op(r)
        if op and op[0] == "write" and covers(
                (grant.get("match") or {}).get("matcher"), op):
            return "staged"
    elif "outbox" in stager and r["method"] not in READ:
        return "staged"
    # 5
    matcher = (grant.get("match") or {}).get("matcher")
    if matcher and matcher.get("git-smart-http") is not None:
        op = git_op(r)
        if op and op[0] == "read" and covers(matcher, op):
            return "safe"
    # 6
    if r["method"] in READ:
        return "safe"
    # 7-8
    if mcp and mcp.get("method") == "tools/call":
        if grant.get("calls") == "serialized":
            return "control"
        if grant.get("inspect") == "mcp":
            cls = (grant.get("tools") or {}).get(mcp.get("tool"))
            return cls if cls else "irreversible"
    # 9
    comp = grant.get("compensate") or {}
    for rule in ("restore", "deleteCreated"):
        if r["method"] in ((comp.get(rule) or {}).get("methods") or []):
            return "compensable"
    # 10
    return "irreversible"


def taint_cond(grant, labels):
    wt = grant.get("whenTainted")
    if wt is None or not labels:
        return "allow"
    default = wt.get("default")
    if not default:
        methods = (grant.get("match") or {}).get("methods")
        default = ("review" if (grant.get("credential") or not methods
                                or any(m not in ("GET", "HEAD") for m in methods))
                   else "allow")
    best = 0
    for lb in labels:
        c = (wt.get("labels") or {}).get(lb) or default
        best = max(best, ORDER[c])
    return NAME[best]


def condition(policy_spec, grant, cls, taint):
    cands = [(policy_spec.get("autonomy") or {}).get(cls) or "allow",
             grant.get("requires") or "allow"]
    if cls in ("compensable", "irreversible"):
        cands.append(taint_cond(grant, taint or []))
    return NAME[max(ORDER[c if c != "none" else "allow"] for c in cands)]


def declared_safe(grant, r, cls):
    return (cls == "safe" and grant.get("class") == "safe"
            and (r["method"] != "GET" or bool(r.get("tunnel"))
                 or bool(r.get("websocket"))))


# --- policy library ---------------------------------------------------------
POLICIES = {}  # name -> {"spec": spec-dict, "grants": {id: grant-dict}}


def define(name, spec):
    POLICIES[name] = {"spec": spec,
                      "grants": {g["id"]: g for g in spec.get("grants") or []}}


def row(name, policy, grant, request, taint=None, c523=False):
    P = POLICIES[policy]
    g = P["grants"][grant]
    cls = classify(g, request)
    r = {"name": name, "policy": policy, "grant": grant, "request": request}
    if taint:
        r["taint"] = taint
    if c523:
        r["c523"] = True
    r["expected"] = {
        "class": cls,
        "requires": condition(P["spec"], g, cls, taint),
        "declared_safe": declared_safe(g, request, cls),
    }
    ROWS.append(r)


def grant(i, hosts=None, matcher=None, methods=None, paths=None,
          ports=None, **kw):
    m = {"hosts": hosts} if hosts else {}
    if matcher:
        m["matcher"] = {"git-smart-http": matcher}
    if methods:
        m["methods"] = methods
    if paths:
        m["paths"] = paths
    if ports:
        m["ports"] = ports
    g = {"id": i, "match": m}
    g.update(kw)
    return g


OUTBOX = {"outbox": {"respond": {"status": 200, "contentType": "application/json",
                                "body": '{"ok": true, "id": "{provisional}"}'},
                     "idMap": {"provisional": "/id", "real": "/id"},
                     "idempotencyHeader": "Idempotency-Key"}}
GIT_STAGER = {"git": {"refs": ["refs/heads/agent/*"], "allowDelete": False,
                      "allowNonFastForward": False, "maxPackBytes": "512Mi"}}
REPO_W = {"repos": ["acme/widgets", "acme/lib"], "access": "write"}
REPO_R = {"repos": ["acme/widgets"], "access": "read"}

BASE_GRANTS = [
    grant("llm", ["api.anthropic.test"], methods=["POST"], inspect="inference"),
    # boundary-decl must precede boundary: /decl/** would otherwise select
    # the catch-all boundary grant first.
    grant("boundary-decl", ["countersign.internal"], paths=["/decl/**"],
          **{"class": "safe"}),
    grant("boundary", ["countersign.internal"], ports=[443, 8443]),
    grant("repo", ["code.test"], matcher=REPO_W, stager=GIT_STAGER),
    grant("repo-ro", ["ro.test"], matcher=REPO_R),
    grant("repo-nows", ["ws.test"], matcher=REPO_W),
    grant("api", ["api.test"]),
    grant("api-meth", ["m.test"], methods=["GET", "HEAD", "OPTIONS", "POST",
          "PUT", "DELETE", "PATCH", "TRACE", "PURGE"]),
    grant("ws", ["rt.test"], methods=["GET"], paths=["/feed"],
          upgrade=["websocket"]),
    grant("pt", ["vpn.test"], mode="passthrough"),
    grant("mcp-map", ["mcp.map.test"], methods=["POST", "GET"], inspect="mcp",
          tools={"search": "safe", "issue": "irreversible",
                 "note": "compensable", "halt": "control"}),
    grant("mcp-ser", ["mcp.ser.test"], methods=["POST", "GET"], inspect="mcp",
          calls="serialized"),
    grant("mcp-bare", ["mcp.bare.test"], methods=["POST"], inspect="mcp"),
    grant("notify", ["chat.test"], methods=["POST", "PUT", "DELETE"],
          paths=["/api/messages"], stager=OUTBOX),
    grant("ob-read", ["chat.test"], methods=["GET", "HEAD"],
          paths=["/api/messages"], stager=OUTBOX),
    grant("comp-put", ["c.test"], methods=["GET", "PUT", "PATCH", "POST",
          "DELETE"], paths=["/things/**"],
          compensate={"restore": {"methods": ["PUT", "PATCH"]},
                      "stateDigest": {"ignore": ["/updated_at"]}}),
    grant("comp-del", ["c.test"], methods=["POST"], paths=["/items"],
          compensate={"deleteCreated": {"methods": ["POST"],
                                        "from": "location"}}),
    grant("comp-del2", ["c.test"], methods=["GET", "DELETE"], paths=["/old"],
          compensate={"restore": {"methods": ["DELETE"]}}),
    grant("notify-comp", ["chat.test"], methods=["POST", "PUT"], paths=["/nc"],
          stager=OUTBOX, compensate={"restore": {"methods": ["PUT"]}}),
    grant("repo-ros", ["ros.test"], matcher=REPO_R, stager=GIT_STAGER),
    grant("inf-stager", ["infs.test"], methods=["POST"], inspect="inference",
          stager=OUTBOX),
    grant("mcp-sertools", ["mcp.st.test"], methods=["POST"], inspect="mcp",
          calls="serialized", tools={"x": "safe"}),
    grant("ws2", ["rt3.test"], methods=["POST"], paths=["/u"],
          upgrade=["websocket"]),
    grant("ws-decl2", ["rt4.test"], methods=["GET", "POST"], paths=["/g"],
          upgrade=["websocket"], **{"class": "safe"}),
    grant("pt-ctl", ["vpn4.test"], mode="passthrough", **{"class": "control"}),
    grant("notify-opt", ["chat.test"], methods=["OPTIONS", "HEAD"],
          paths=["/api/messages"], stager=OUTBOX),
    grant("notify-all", ["chat.test"], methods=["TRACE", "PURGE", "FOO",
          "PATCH"], paths=["/t"], stager=OUTBOX),
    grant("decl-req", ["dr.test"], methods=["GET", "POST"], paths=["/r/**"],
          **{"class": "safe"}, requires="review"),
    grant("decl-safe", ["d.test"], methods=["GET", "HEAD", "OPTIONS", "POST",
          "PUT", "DELETE", "PATCH"], paths=["/s/**"], **{"class": "safe"}),
    grant("decl-staged", ["d.test"], methods=["GET", "POST"], paths=["/st/**"],
          **{"class": "staged"}, stager=OUTBOX),
    grant("decl-comp", ["d.test"], methods=["GET", "POST"], paths=["/c/**"],
          **{"class": "compensable"}),
    grant("decl-irr", ["d.test"], methods=["GET", "POST"], paths=["/i/**"],
          **{"class": "irreversible"}),
    grant("decl-ctl", ["d.test"], methods=["GET", "POST"], paths=["/x/**"],
          **{"class": "control"}),
    grant("inf-decl", ["inf.test"], methods=["POST", "GET"],
          inspect="inference", **{"class": "safe"}),
    grant("pt-decl", ["vpn2.test"], mode="passthrough", **{"class": "safe"}),
    grant("pt-comp", ["vpn3.test"], mode="passthrough",
          **{"class": "compensable"}),
    grant("ws-decl", ["rt2.test"], methods=["GET"], paths=["/f"],
          upgrade=["websocket"], **{"class": "safe"}),
    grant("ob-irr", ["chat.test"], methods=["POST"], paths=["/irr"],
          **{"class": "irreversible"}, stager=OUTBOX),
    grant("mcp-decl", ["mcp.d.test"], methods=["POST"], inspect="mcp",
          **{"class": "safe"}),
]


def spec(autonomy=None, grants=None, **kw):
    s = {"mode": "enforce", "scenario": "agent"}
    if autonomy:
        s["autonomy"] = autonomy
    s.update(kw)
    s["grants"] = grants if grants is not None else BASE_GRANTS
    return s


define("base", spec())
define("autoA", spec(autonomy={"safe": "allow", "control": "allow",
                             "staged": "review", "compensable": "review",
                             "irreversible": "review"}))
define("autoB", spec(autonomy={"safe": "deny", "control": "deny",
                             "staged": "allow", "compensable": "deny",
                             "irreversible": "deny"}))
define("autoC", spec(autonomy={"safe": "review", "control": "allow",
                             "staged": "deny", "compensable": "allow",
                             "irreversible": "review"}))

# strict: autonomy everywhere review/deny; rq-* grants carry a looser or
# unset requires so the autonomy value must win (C5.2.3 rows).
define("strict", spec(
    autonomy={"safe": "review", "control": "deny", "staged": "deny",
              "compensable": "review", "irreversible": "deny"},
    grants=BASE_GRANTS + [
        grant("rq-allow", ["r.test"], methods=["GET", "POST", "PUT"],
              requires="allow"),
        grant("rq-none", ["r2.test"], methods=["GET", "POST", "PUT"]),
        grant("rq-review", ["r3.test"], methods=["GET", "POST", "PUT"],
              requires="review"),
        grant("rq-deny", ["r4.test"], methods=["GET", "POST", "PUT"],
              requires="deny"),
        grant("rq-repo", ["rcode.test"], matcher=REPO_W, stager=GIT_STAGER,
              requires="allow"),
        grant("rq-comp", ["rc.test"], methods=["GET", "PUT"], paths=["/t/**"],
              compensate={"restore": {"methods": ["PUT"]}}, requires="allow"),
        grant("rq-llm", ["rinf.test"], methods=["POST"], inspect="inference",
              requires="allow"),
    ]))

# lax: autonomy all-allow; grant requires drives the condition upward.
define("lax", spec(
    autonomy={"safe": "allow", "control": "allow", "staged": "allow",
              "compensable": "allow", "irreversible": "allow"},
    grants=BASE_GRANTS + [
        grant("rq-review", ["r3.test"], methods=["GET", "POST", "PUT"],
              requires="review"),
        grant("rq-deny", ["r4.test"], methods=["GET", "POST", "PUT"],
              requires="deny"),
        grant("rq-repo", ["rcode.test"], matcher=REPO_W, stager=GIT_STAGER,
              requires="review"),
        grant("rq-comp", ["rc.test"], methods=["GET", "PUT"], paths=["/t/**"],
              compensate={"restore": {"methods": ["PUT"]}}, requires="deny"),
    ]))

# taint: whenTainted variants for the 04 §8 third operand.
define("taint", spec(
    grants=BASE_GRANTS + [
        grant("tw-web", ["tw.test"], methods=["GET", "POST", "PUT"],
              whenTainted={"default": "review",
                           "labels": {"web": "deny", "packages": "allow"}}),
        grant("tw-nodef", ["tw2.test"], methods=["GET", "POST", "PUT"],
              whenTainted={"labels": {"web": "deny"}}),
        # tw-ro admits only GET/HEAD; a declared class keeps whenTainted
        # reachable so the derived default (allow, read-only) is exercised.
        grant("tw-ro", ["tw3.test"], methods=["GET", "HEAD"],
              **{"class": "irreversible"},
              whenTainted={"labels": {"web": "deny"}}),
        grant("tw-comp", ["tw4.test"], methods=["PUT", "POST"],
              compensate={"restore": {"methods": ["PUT"]}},
              whenTainted={"default": "deny",
                           "labels": {"packages": "allow"}}),
        # staged effects record taint but whenTainted never interrupts
        # them (05 §2): requires must stay the autonomy value.
        grant("tw-staged", ["tw5.test"], methods=["POST", "PUT"],
              stager=OUTBOX, whenTainted={"default": "deny"}),
    ]))


def req(method, host, path="/", query="", port=0, **kw):
    r = {"method": method, "host": host, "path": path}
    if query:
        r["query"] = query
    if port:
        r["port"] = port
    r.update(kw)
    return r


def mcp(method, tool=None):
    m = {"method": method}
    if tool is not None:
        m["tool"] = tool
    return m


GIT_R = "/acme/widgets/info/refs"
GIT_UP = "/acme/widgets/git-upload-pack"
GIT_RECV = "/acme/widgets/git-receive-pack"
GIT_DOTGIT = "/acme/widgets.git/git-receive-pack"

# --- section A: rule order and shadowing ------------------------------------
# rule 1 shadows every later rule.
row("a-ctl-inference", "base", "llm", req("POST", "api.anthropic.test", "/v1/messages"))
row("a-ctl-inference-get", "base", "inf-decl", req("GET", "inf.test", "/m"))
row("a-ctl-inference-decl", "base", "inf-decl", req("POST", "inf.test", "/m"))
row("a-ctl-boundary-get", "base", "boundary", req("GET", "countersign.internal", "/self"))
row("a-ctl-boundary-post", "base", "boundary", req("POST", "countersign.internal", "/w"))
row("a-ctl-boundary-port", "base", "boundary", req("POST", "countersign.internal", "/w", port=8443))
row("a-ctl-boundary-case", "base", "boundary", req("POST", "Countersign.Internal", "/w"))
row("a-ctl-boundary-dot", "base", "boundary", req("POST", "countersign.internal.", "/w"))
row("a-ctl-mcpproto-list", "base", "mcp-map", req("POST", "mcp.map.test", "/", mcp=mcp("tools/list")))
row("a-ctl-mcpproto-decl", "base", "mcp-decl", req("POST", "mcp.d.test", "/", mcp=mcp("notifications/x")))
row("a-ctl-mcpproto-ser", "base", "mcp-ser", req("POST", "mcp.ser.test", "/", mcp=mcp("tools/list")))
# rule 2 shadows rules 3-9.
row("a-decl-vs-ws", "base", "ws-decl", req("GET", "rt2.test", "/f", websocket=True))
row("a-decl-vs-pt", "base", "pt-decl", req("POST", "vpn2.test", "/x", tunnel=True))
row("a-decl-vs-pt-comp", "base", "pt-comp", req("POST", "vpn3.test", "/x", tunnel=True))
row("a-decl-vs-stager", "base", "ob-irr", req("POST", "chat.test", "/irr"))
row("a-decl-staged-vs-m6", "base", "decl-staged", req("GET", "d.test", "/st/x"))
# rule 3 shadows rules 4+.
row("a-pt-any", "base", "pt", req("GET", "vpn.test", "/deep/path", tunnel=True))
row("a-pt-post", "base", "pt", req("POST", "vpn.test", "/x", tunnel=True))
row("a-ws-irr", "base", "ws", req("GET", "rt.test", "/feed", websocket=True))
# rule 4 (stager) shadows rules 5-9.
row("a-stager-vs-get", "base", "repo", req("GET", "code.test", GIT_R, "service=git-receive-pack"))
row("a-stager-vs-del", "base", "notify", req("DELETE", "chat.test", "/api/messages"))
# rule 5 shadows 6+.
row("a-read-shadow", "base", "repo", req("GET", "code.test", GIT_R, "service=git-upload-pack"))
row("a-read-post", "base", "repo", req("POST", "code.test", GIT_UP))
# rule 6 shadows 7-10.
row("a-get-vs-mcp", "base", "mcp-map", req("GET", "mcp.map.test", "/", mcp=mcp("tools/call", "issue")))
row("a-get-vs-comp", "base", "comp-put", req("GET", "c.test", "/things/1"))
# rules 7-8 shadow 9-10 on MCP grants.
row("a-mcpcall-ser", "base", "mcp-ser", req("POST", "mcp.ser.test", "/", mcp=mcp("tools/call", "anything")))
row("a-mcpcall-tool", "base", "mcp-map", req("POST", "mcp.map.test", "/", mcp=mcp("tools/call", "search")))
# rule 9 shadows 10.
row("a-comp-vs-irr", "base", "comp-put", req("PUT", "c.test", "/things/1"))

# --- section B: every method on a plain grant --------------------------------
for meth in ("GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH",
             "TRACE", "PURGE"):
    row("b-method-" + meth.lower(), "base", "api-meth", req(meth, "m.test", "/p"))

# --- section C: git read vs write ---------------------------------------------
row("c-repo-info-r", "base", "repo", req("GET", "code.test", GIT_R, "service=git-upload-pack"))
row("c-repo-info-w", "base", "repo", req("GET", "code.test", GIT_R, "service=git-receive-pack"))
row("c-repo-post-up", "base", "repo", req("POST", "code.test", GIT_UP))
row("c-repo-post-recv", "base", "repo", req("POST", "code.test", GIT_RECV))
row("c-repo-dotgit", "base", "repo", req("POST", "code.test", GIT_DOTGIT))
row("c-repo-owner-repo", "base", "repo", req("POST", "code.test", "/acme/lib/git-receive-pack"))
row("c-repo-lib-info-r", "base", "repo", req("GET", "code.test", "/acme/lib/info/refs", "service=git-upload-pack"))
row("c-repo-lib-post-up", "base", "repo", req("POST", "code.test", "/acme/lib/git-upload-pack"))
row("c-ro-info-r", "base", "repo-ro", req("GET", "ro.test", GIT_R, "service=git-upload-pack"))
row("c-ro-post-up", "base", "repo-ro", req("POST", "ro.test", GIT_UP))
row("c-nows-info-r", "base", "repo-nows", req("GET", "ws.test", GIT_R, "service=git-upload-pack"))
row("c-nows-info-w", "base", "repo-nows", req("GET", "ws.test", GIT_R, "service=git-receive-pack"))
row("c-nows-post-up", "base", "repo-nows", req("POST", "ws.test", GIT_UP))
row("c-nows-post-recv", "base", "repo-nows", req("POST", "ws.test", GIT_RECV))
row("c-nows-lib-recv", "base", "repo-nows", req("POST", "ws.test", "/acme/lib/git-receive-pack"))

# --- section D: stagers --------------------------------------------------------
row("d-outbox-post", "base", "notify", req("POST", "chat.test", "/api/messages"))
row("d-outbox-put", "base", "notify", req("PUT", "chat.test", "/api/messages"))
row("d-outbox-delete", "base", "notify", req("DELETE", "chat.test", "/api/messages"))
row("d-outbox-get", "base", "ob-read", req("GET", "chat.test", "/api/messages"))
row("d-outbox-head", "base", "ob-read", req("HEAD", "chat.test", "/api/messages"))
row("d-git-staged-post", "base", "repo", req("POST", "code.test", GIT_RECV))
row("d-git-read", "base", "repo", req("POST", "code.test", GIT_UP))
# rule 3 (websocket) beats rule 4 (stager): an upgrade on an outbox grant is
# irreversible, not staged.
row("d-outbox-ws-post", "base", "notify",
    req("POST", "chat.test", "/api/messages", websocket=True))
row("d-outbox-ws-del", "base", "notify",
    req("DELETE", "chat.test", "/api/messages", websocket=True))

# --- section E: MCP -------------------------------------------------------------
row("e-call-ser", "base", "mcp-ser", req("POST", "mcp.ser.test", "/", mcp=mcp("tools/call", "x")))
row("e-list-ser", "base", "mcp-ser", req("POST", "mcp.ser.test", "/", mcp=mcp("tools/list")))
row("e-call-map-safe", "base", "mcp-map", req("POST", "mcp.map.test", "/", mcp=mcp("tools/call", "search")))
row("e-call-map-irr", "base", "mcp-map", req("POST", "mcp.map.test", "/", mcp=mcp("tools/call", "issue")))
row("e-call-map-comp", "base", "mcp-map", req("POST", "mcp.map.test", "/", mcp=mcp("tools/call", "note")))
row("e-call-map-ctl", "base", "mcp-map", req("POST", "mcp.map.test", "/", mcp=mcp("tools/call", "halt")))
row("e-call-map-miss", "base", "mcp-map", req("POST", "mcp.map.test", "/", mcp=mcp("tools/call", "unknown")))
row("e-call-bare", "base", "mcp-bare", req("POST", "mcp.bare.test", "/", mcp=mcp("tools/call", "x")))
row("e-notify-mcp", "base", "mcp-map", req("POST", "mcp.map.test", "/", mcp=mcp("notifications/progress")))
row("e-list-bare", "base", "mcp-bare", req("POST", "mcp.bare.test", "/", mcp=mcp("tools/list")))
row("e-call-noinspect", "base", "api", req("POST", "api.test", "/rpc", mcp=mcp("tools/call", "x")))
row("e-call-get-noinspect", "base", "api", req("GET", "api.test", "/rpc", mcp=mcp("tools/call", "x")))
row("e-resp-msg", "base", "mcp-map", req("POST", "mcp.map.test", "/", mcp=mcp("")))
row("e-call-decl", "base", "mcp-decl", req("POST", "mcp.d.test", "/", mcp=mcp("tools/call", "y")))

# --- section F: passthrough, websocket, tunnel ------------------------------------
row("f-pt-get", "base", "pt", req("GET", "vpn.test", "/a", tunnel=True))
row("f-pt-delete", "base", "pt", req("DELETE", "vpn.test", "/a", tunnel=True))
row("f-ws-get", "base", "ws", req("GET", "rt.test", "/feed", websocket=True))
row("f-no-ws-get", "base", "ws", req("GET", "rt.test", "/feed"))
row("f-tunnel-intercept", "base", "api", req("POST", "api.test", "/a", tunnel=True))
row("f-ws-decl", "base", "ws-decl", req("GET", "rt2.test", "/f", websocket=True))
row("f-pt-decl-post", "base", "pt-decl", req("POST", "vpn2.test", "/x", tunnel=True))
row("f-pt-decl-get", "base", "pt-decl", req("GET", "vpn2.test", "/x", tunnel=True))

# --- section G: declared classes + declared_safe flag ------------------------------
for meth in ("GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH"):
    row("g-declsafe-" + meth.lower(), "base", "decl-safe", req(meth, "d.test", "/s/x"))
row("g-decl-staged", "base", "decl-staged", req("POST", "d.test", "/st/x"))
row("g-decl-staged-get", "base", "decl-staged", req("GET", "d.test", "/st/x"))
row("g-decl-comp", "base", "decl-comp", req("POST", "d.test", "/c/x"))
row("g-decl-comp-get", "base", "decl-comp", req("GET", "d.test", "/c/x"))
row("g-decl-irr", "base", "decl-irr", req("POST", "d.test", "/i/x"))
row("g-decl-irr-get", "base", "decl-irr", req("GET", "d.test", "/i/x"))
row("g-decl-ctl", "base", "decl-ctl", req("POST", "d.test", "/x/y"))
row("g-decl-ctl-get", "base", "decl-ctl", req("GET", "d.test", "/x/y"))
row("g-decl-ws", "base", "ws-decl", req("GET", "rt2.test", "/f", websocket=True))
row("g-decl-tunnel", "base", "pt-decl", req("POST", "vpn2.test", "/x", tunnel=True))
row("g-decl-tunnel-get", "base", "pt-decl", req("GET", "vpn2.test", "/x", tunnel=True))
# declared safe on POST is the canonical flagged case called out in M5.2.
row("g-decl-safe-post-flag", "base", "decl-safe", req("POST", "d.test", "/s/new"))

# --- section H: compensate ----------------------------------------------------------
row("h-comp-put", "base", "comp-put", req("PUT", "c.test", "/things/1"))
row("h-comp-patch", "base", "comp-put", req("PATCH", "c.test", "/things/1"))
row("h-comp-post-nocov", "base", "comp-put", req("POST", "c.test", "/things/1"))
row("h-comp-del-nocov", "base", "comp-put", req("DELETE", "c.test", "/things/1"))
row("h-comp-del-created", "base", "comp-del", req("POST", "c.test", "/items"))
row("h-comp-get", "base", "comp-put", req("GET", "c.test", "/things/1"))
row("h-comp-shadow", "base", "notify-comp", req("PUT", "chat.test", "/nc"))
row("h-comp-shadow2", "base", "notify-comp", req("POST", "chat.test", "/nc"))
row("h-comp-delmeth", "base", "comp-del2", req("DELETE", "c.test", "/old"))
row("h-comp-delmeth-get", "base", "comp-del2", req("GET", "c.test", "/old"))

# --- section I: boundary -------------------------------------------------------------
for meth in ("GET", "POST", "DELETE"):
    row("i-boundary-" + meth.lower(), "base", "boundary",
        req(meth, "countersign.internal", "/p"))

# --- section J: rule 10 fallback --------------------------------------------------------
row("j-irr-post", "base", "api", req("POST", "api.test", "/x"))
row("j-irr-delete", "base", "api", req("DELETE", "api.test", "/x"))
row("j-irr-put", "base", "api", req("PUT", "api.test", "/x"))
row("j-irr-post-q", "base", "api", req("POST", "api.test", "/x", "a=b"))
row("j-irr-nogit", "base", "api", req("POST", "api.test", GIT_RECV))

# --- section K: each class under each autonomy condition ---------------------------------
# autoA: safe allow / staged review / compensable review / irreversible
# review / control allow.
row("k-a-safe", "autoA", "api", req("GET", "api.test", "/x"))
row("k-a-staged", "autoA", "repo", req("POST", "code.test", GIT_RECV))
row("k-a-comp", "autoA", "comp-put", req("PUT", "c.test", "/things/1"))
row("k-a-irr", "autoA", "api", req("POST", "api.test", "/x"))
row("k-a-ctl", "autoA", "llm", req("POST", "api.anthropic.test", "/v1/messages"))
row("k-a-boundary", "autoA", "boundary", req("GET", "countersign.internal", "/s"))
# autoB: safe deny / staged allow / compensable deny / irreversible deny /
# control deny.
row("k-b-safe", "autoB", "api", req("GET", "api.test", "/x"))
row("k-b-staged", "autoB", "repo", req("POST", "code.test", GIT_RECV))
row("k-b-comp", "autoB", "comp-put", req("PUT", "c.test", "/things/1"))
row("k-b-irr", "autoB", "api", req("POST", "api.test", "/x"))
row("k-b-ctl", "autoB", "llm", req("POST", "api.anthropic.test", "/v1/messages"))
row("k-b-mcp-tool", "autoB", "mcp-map", req("POST", "mcp.map.test", "/", mcp=mcp("tools/call", "search")))
row("k-b-decl", "autoB", "decl-irr", req("POST", "d.test", "/i/x"))

# --- section L: strictest-wins requires vs autonomy ----------------------------------------
for i, (meth, host) in enumerate((("GET", "r.test"), ("POST", "r.test"),
                                  ("PUT", "r.test"), ("GET", "r2.test"),
                                  ("POST", "r2.test"), ("PUT", "r2.test"))):
    row(f"l-c523-{i}", "strict",
        "rq-allow" if host == "r.test" else "rq-none",
        req(meth, host, "/a"), c523=True)
for i, (gid, ops) in enumerate((
        ("rq-repo", ("POST", "rcode.test", GIT_RECV)),
        ("rq-comp", ("PUT", "rc.test", "/t/1")),
        ("rq-llm", ("POST", "rinf.test", "/m")),
        ("rq-allow", ("POST", "r.test", "/a")),
        ("rq-none", ("GET", "r2.test", "/b")),
        ("rq-allow", ("PUT", "r.test", "/a")))):
    row(f"l-c523-{6 + i}", "strict", gid, req(*ops), c523=True)
# strict policy on base grants (requires unset -> autonomy wins outright).
for i, (g, r_) in enumerate((
        ("api", req("GET", "api.test", "/x")),
        ("api", req("POST", "api.test", "/x")),
        ("repo", req("POST", "code.test", GIT_RECV)),
        ("comp-put", req("PUT", "c.test", "/things/1")),
        ("llm", req("POST", "api.anthropic.test", "/v1/messages")),
        ("boundary", req("POST", "countersign.internal", "/w")),
        ("notify", req("POST", "chat.test", "/api/messages")),
        ("decl-irr", req("POST", "d.test", "/i/x")))):
    row(f"l-strict-base-{i}", "strict", g, r_, c523=True)
# requires stricter than autonomy.
row("l-lax-rev-post", "lax", "rq-review", req("POST", "r3.test", "/a"))
row("l-lax-rev-get", "lax", "rq-review", req("GET", "r3.test", "/a"))
row("l-lax-deny-post", "lax", "rq-deny", req("POST", "r4.test", "/a"))
row("l-lax-deny-get", "lax", "rq-deny", req("GET", "r4.test", "/a"))
row("l-lax-repo", "lax", "rq-repo", req("POST", "rcode.test", GIT_RECV))
row("l-lax-comp", "lax", "rq-comp", req("PUT", "rc.test", "/t/1"))
# requires equal to autonomy.
row("l-eq-review", "strict", "rq-review", req("POST", "r3.test", "/a"))
row("l-eq-deny", "strict", "rq-deny", req("POST", "r4.test", "/a"))

# --- section M: whenTainted (compensable/irreversible only) ----------------------------
row("m-taint-web-irr", "taint", "tw-web", req("POST", "tw.test", "/a"), taint=["web"])
row("m-taint-pkg-irr", "taint", "tw-web", req("POST", "tw.test", "/a"), taint=["packages"])
row("m-taint-none-irr", "taint", "tw-web", req("POST", "tw.test", "/a"))
row("m-taint-miss-irr", "taint", "tw-web", req("POST", "tw.test", "/a"), taint=["other"])
row("m-taint-two-irr", "taint", "tw-web", req("POST", "tw.test", "/a"), taint=["web", "packages"])
row("m-taint-safe-ignored", "taint", "tw-web", req("GET", "tw.test", "/a"), taint=["web"])
row("m-nodef-web", "taint", "tw-nodef", req("POST", "tw2.test", "/a"), taint=["web"])
row("m-nodef-miss", "taint", "tw-nodef", req("POST", "tw2.test", "/a"), taint=["other"])
row("m-nodef-get-miss", "taint", "tw-nodef", req("GET", "tw2.test", "/a"), taint=["other"])
row("m-ro-miss", "taint", "tw-ro", req("GET", "tw3.test", "/a"), taint=["other"])
row("m-ro-web", "taint", "tw-ro", req("GET", "tw3.test", "/a"), taint=["web"])
row("m-comp-web", "taint", "tw-comp", req("PUT", "tw4.test", "/a"), taint=["web"])
row("m-comp-pkg", "taint", "tw-comp", req("PUT", "tw4.test", "/a"), taint=["packages"])
row("m-comp-none", "taint", "tw-comp", req("PUT", "tw4.test", "/a"))
row("m-comp-post", "taint", "tw-comp", req("POST", "tw4.test", "/a"), taint=["packages"])
row("m-taint-staged", "taint", "tw-staged", req("POST", "tw5.test", "/a"), taint=["web"])
row("m-taint-staged-none", "taint", "tw-staged", req("PUT", "tw5.test", "/a"))

# --- section N: more rule-order / control sources ----------------------------------
row("n-boundary-decl", "base", "boundary-decl", req("POST", "countersign.internal", "/decl/x"))
row("n-inf-stager", "base", "inf-stager", req("POST", "infs.test", "/m"))
row("n-inf-stager-get", "base", "inf-stager", req("POST", "infs.test", "/m"))
row("n-mcp-sertools", "base", "mcp-sertools", req("POST", "mcp.st.test", "/", mcp=mcp("tools/call", "x")))
row("n-mcp-sertools-miss", "base", "mcp-sertools", req("POST", "mcp.st.test", "/", mcp=mcp("tools/call", "y")))
row("n-mcp-notool", "base", "mcp-map", req("POST", "mcp.map.test", "/", mcp=mcp("tools/call")))
row("n-ws2-post", "base", "ws2", req("POST", "rt3.test", "/u", websocket=True))
row("n-ws2-no", "base", "ws2", req("POST", "rt3.test", "/u"))
row("n-ros-read", "base", "repo-ros", req("GET", "ros.test", GIT_R, "service=git-upload-pack"))
row("n-ros-up", "base", "repo-ros", req("POST", "ros.test", GIT_UP))
# (a receive-pack on a read-only matcher is refused at grant selection,
# 04 §2, so no classifier row can name the grant)
# rule 3 beats rule 7: a websocket upgrade carrying tools/call on a
# serialized brokered grant is irreversible, not control.
row("n-mcp-ws-ser", "base", "mcp-ser",
    req("POST", "mcp.ser.test", "/", websocket=True, mcp=mcp("tools/call", "x")))

# --- section O: third autonomy mix ----------------------------------------------------
# autoC: {safe:review, control:allow, staged:deny, compensable:allow,
# irreversible:review}
row("o-c-safe", "autoC", "api", req("GET", "api.test", "/x"))
row("o-c-staged", "autoC", "repo", req("POST", "code.test", GIT_RECV))
row("o-c-comp", "autoC", "comp-put", req("PUT", "c.test", "/things/1"))
row("o-c-irr", "autoC", "api", req("POST", "api.test", "/x"))
row("o-c-ctl", "autoC", "llm", req("POST", "api.anthropic.test", "/v1/messages"))
row("o-c-ws", "autoC", "ws", req("GET", "rt.test", "/feed", websocket=True))
row("o-c-pt", "autoC", "pt", req("POST", "vpn.test", "/a", tunnel=True))
row("o-c-decl-ctl", "autoC", "decl-ctl", req("POST", "d.test", "/x/y"))
row("o-c-decl-irr", "autoC", "decl-irr", req("POST", "d.test", "/i/x"))
row("o-c-mcp-tool", "autoC", "mcp-map", req("POST", "mcp.map.test", "/", mcp=mcp("tools/call", "issue")))
row("o-c-boundary", "autoC", "boundary", req("GET", "countersign.internal", "/s"))
row("o-c-outbox", "autoC", "notify", req("POST", "chat.test", "/api/messages"))

# --- section P: requires on declared classes and remaining combos ----------------------
row("p-decl-req-safe", "base", "decl-req", req("POST", "dr.test", "/r/x"))
row("p-decl-req-get", "base", "decl-req", req("GET", "dr.test", "/r/x"))
row("p-decl-req-strict", "strict", "decl-req", req("POST", "dr.test", "/r/x"))
row("p-lax-decl", "lax", "decl-irr", req("POST", "d.test", "/i/x"))
row("p-lax-decl-safe", "lax", "decl-safe", req("POST", "d.test", "/s/x"))
row("p-lax-mcp", "lax", "mcp-map", req("POST", "mcp.map.test", "/", mcp=mcp("tools/call", "note")))
row("p-strict-ws", "strict", "ws", req("GET", "rt.test", "/feed", websocket=True))
row("p-strict-pt", "strict", "pt", req("POST", "vpn.test", "/a", tunnel=True))
row("p-strict-declsafe", "strict", "decl-safe", req("POST", "d.test", "/s/x"), c523=True)
row("p-strict-mcp", "strict", "mcp-map", req("POST", "mcp.map.test", "/", mcp=mcp("tools/call", "issue")), c523=True)
row("p-strict-outbox", "strict", "ob-read", req("GET", "chat.test", "/api/messages"), c523=True)
row("p-strict-mcp-decl", "strict", "mcp-decl", req("POST", "mcp.d.test", "/", mcp=mcp("tools/call", "y")))

# --- section Q: more MCP coverage -----------------------------------------------------
row("q-call-notool-ser", "base", "mcp-ser", req("POST", "mcp.ser.test", "/", mcp=mcp("tools/call")))
row("q-ping-map", "base", "mcp-map", req("POST", "mcp.map.test", "/", mcp=mcp("ping")))
row("q-initialize", "base", "mcp-map", req("POST", "mcp.map.test", "/", mcp=mcp("initialize")))
row("q-get-call-ser", "base", "mcp-ser", req("GET", "mcp.ser.test", "/", mcp=mcp("tools/call", "x")))
row("q-delete-call", "base", "api", req("DELETE", "api.test", "/rpc", mcp=mcp("tools/call", "issue")))
row("q-call-ctl2", "base", "mcp-map", req("POST", "mcp.map.test", "/", mcp=mcp("tools/call", "halt")))
row("q-inf-call", "base", "inf-decl", req("POST", "inf.test", "/m", mcp=mcp("tools/call", "z")))

# --- section R: outbox edge methods ----------------------------------------------------
row("r-outbox-options", "base", "notify-opt", req("OPTIONS", "chat.test", "/api/messages"))
row("r-outbox-trace", "base", "notify-all", req("TRACE", "chat.test", "/t"))
row("r-outbox-purge", "base", "notify-all", req("PURGE", "chat.test", "/t"))
row("r-outbox-connect", "base", "notify-all", req("FOO", "chat.test", "/t"))
row("r-outbox-head", "base", "ob-read", req("HEAD", "chat.test", "/api/messages"))
row("r-outbox-patch", "base", "notify-all", req("PATCH", "chat.test", "/t"))

# --- section S: additional declared/flag coverage --------------------------------------
row("s-declsafe-tunnel-get", "base", "pt-decl", req("GET", "vpn2.test", "/x", tunnel=True))
row("s-declsafe-tunnel-nopost", "base", "pt-decl", req("CONNECT", "vpn2.test", "/x", tunnel=True))
row("s-declsafe-ws-post", "base", "ws-decl2", req("POST", "rt4.test", "/g", websocket=True))
row("s-declctl-tunnel", "base", "pt-ctl", req("POST", "vpn4.test", "/x", tunnel=True))
row("s-decl-staged-get2", "base", "decl-staged", req("GET", "d.test", "/st/y"))
row("s-decl-safe-opt", "base", "decl-safe", req("OPTIONS", "d.test", "/s/x"))
row("s-ctl-mcp-on-api", "base", "api", req("POST", "api.test", "/x", mcp=mcp("tools/call", "t")))
row("s-inf-everything", "base", "llm", req("POST", "api.anthropic.test", "/v1/anything", mcp=mcp("tools/call", "t")))
row("s-decl-staged-lax", "lax", "decl-staged", req("POST", "d.test", "/st/x"))
row("s-decl-comp-autoB", "autoB", "decl-comp", req("POST", "d.test", "/c/x"))

# --- section T: extra c523 margin -------------------------------------------------------
row("t-c523-21", "strict", "mcp-ser", req("POST", "mcp.ser.test", "/", mcp=mcp("tools/call", "x")), c523=True)
row("t-c523-22", "strict", "repo-ro", req("POST", "ro.test", GIT_UP), c523=True)
row("t-c523-23", "strict", "comp-del", req("POST", "c.test", "/items"), c523=True)
row("t-c523-24", "strict", "ws2", req("POST", "rt3.test", "/u", websocket=True), c523=True)

# --- section U: second-repo and .git coverage ---------------------------------------------
row("u-lib-info-w", "base", "repo", req("GET", "code.test", "/acme/lib/info/refs", "service=git-receive-pack"))
row("u-lib-dotgit", "base", "repo", req("POST", "code.test", "/acme/lib.git/git-upload-pack"))
row("u-nows-dotgit-info", "base", "repo-nows", req("GET", "ws.test", "/acme/widgets.git/info/refs", "service=git-upload-pack"))
row("u-ros-dotgit", "base", "repo-ros", req("POST", "ros.test", "/acme/widgets.git/git-upload-pack"))

# --- section V: remaining autonomy/class combos ----------------------------------------------
# Every class value reachable via each rule under deny autonomy (autoB has
# safe:deny / staged:allow / compensable:deny / irreversible:deny /
# control:deny): confirm requires unset + autonomy deny across more rules.
row("v-b-outbox", "autoB", "notify", req("POST", "chat.test", "/api/messages"))
row("v-b-ws", "autoB", "ws", req("GET", "rt.test", "/feed", websocket=True))
row("v-b-pt", "autoB", "pt", req("POST", "vpn.test", "/a", tunnel=True))
row("v-b-decl-safe", "autoB", "decl-safe", req("POST", "d.test", "/s/x"))
row("v-b-decl-staged", "autoB", "decl-staged", req("POST", "d.test", "/st/x"))
row("v-b-git-read", "autoB", "repo", req("POST", "code.test", GIT_UP))
row("v-b-mcp-ser", "autoB", "mcp-ser", req("POST", "mcp.ser.test", "/", mcp=mcp("tools/call", "x")))
row("v-a-outbox", "autoA", "notify", req("POST", "chat.test", "/api/messages"))
row("v-a-ws", "autoA", "ws", req("GET", "rt.test", "/feed", websocket=True))
row("v-a-pt", "autoA", "pt", req("POST", "vpn.test", "/a", tunnel=True))
row("v-a-decl-safe", "autoA", "decl-safe", req("POST", "d.test", "/s/x"))
row("v-a-decl-staged", "autoA", "decl-staged", req("POST", "d.test", "/st/x"))
row("v-a-mcp-ser", "autoA", "mcp-ser", req("POST", "mcp.ser.test", "/", mcp=mcp("tools/call", "x")))

# --- emit ------------------------------------------------------------------------------
INVALID = [
    ("v-stager-empty", "stager",
     {"grants": [grant("g", ["x.test"], stager={})]}),
    ("v-stager-both", "stager",
     {"grants": [grant("g", ["x.test"], stager={"git": GIT_STAGER["git"],
                                              "outbox": OUTBOX["outbox"]})]}),
    ("v-stager-unknown", "svn",
     {"grants": [grant("g", ["x.test"], stager={"svn": {"url": "x"}})]}),
    ("v-class-staged-nostager", "class",
     {"grants": [grant("g", ["x.test"], **{"class": "staged"})]}),
    ("v-class-bad", "class",
     {"grants": [grant("g", ["x.test"], **{"class": "fuzzy"})]}),
    ("v-autonomy-intent", "autonomy",
     {"autonomy": {"safe": "intent"},
      "grants": [grant("g", ["x.test"])]}),
    ("v-autonomy-key", "autonomy",
     {"autonomy": {"magic": "allow"},
      "grants": [grant("g", ["x.test"])]}),
    ("v-requires-intent", "requires",
     {"grants": [grant("g", ["x.test"], requires="intent")]}),
    ("v-tools-notmcp", "tools",
     {"grants": [grant("g", ["x.test"], tools={"a": "safe"})]}),
    ("v-tools-badclass", "tools",
     {"grants": [grant("g", ["x.test"], inspect="mcp",
                       tools={"a": "fuzzy"})]}),
    ("v-calls-bad", "calls",
     {"grants": [grant("g", ["x.test"], inspect="mcp", calls="parallel")]}),
    ("v-calls-notmcp", "calls",
     {"grants": [grant("g", ["x.test"], calls="serialized")]}),
    ("v-stager-pt", "stager",
     {"grants": [grant("g", ["x.test"], mode="passthrough",
                       stager=GIT_STAGER)]}),
    ("v-comp-empty", "compensate",
     {"grants": [grant("g", ["x.test"],
                       compensate={"stateDigest": {"ignore": ["/a"]}})]}),
    ("v-comp-nofrom", "deleteCreated",
     {"grants": [grant("g", ["x.test"],
                       compensate={"deleteCreated": {"methods": ["POST"]}})]}),
    ("v-stager-outbox-noidmap", "idMap",
     {"grants": [grant("g", ["x.test"],
                       stager={"outbox": {"respond": OUTBOX["outbox"]["respond"]}})]}),
    ("v-tools-staged-nostager", "tools",
     {"grants": [grant("g", ["x.test"], inspect="mcp",
                       tools={"a": "staged"})]}),
    ("v-gitstager-badref", "refs",
     {"grants": [grant("g", ["x.test"], matcher=REPO_W,
                       stager={"git": {"refs": ["heads/*"]}})]}),
]


def flow(v):
    if isinstance(v, dict):
        return "{" + ", ".join(f"{k}: {flow(x)}" for k, x in v.items()) + "}"
    if isinstance(v, list):
        return "[" + ", ".join(flow(x) for x in v) + "]"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return json.dumps(v)


def emit(out):
    w = out.write
    w("""# test/vectors/policy/classes.yaml — decision table for spec/05
# transactions §1 ordered reversibility classes and §2 strictest
# condition (M5.2). At least 250 rows.
#
# The expected column was derived by reasoning from the spec text
# (05 §1 rules 1-10, §2 strictest-wins, the rule-2 declared_safe flag),
# never by running the Go classifier or the Python reference:
# test/gen/classes_table.py contains an independent expression of the
# rules and this file was reviewed by reading after generation.
#
# Row format: {name, policy, grant, request, taint?, c523?,
#   expected:{class, requires, declared_safe}}. The row's request
# additionally passes through 04 §2 grant selection and must select the
# named grant; class is that of the effect, requires the condition
# imposed (allow|intent|review|deny), declared_safe the §1 rule-2 flag.
# Rows with c523 assert the autonomy table wins against a looser grant
# requires (C5.2.3).
# invalid entries: {name, field, policy} — policy.Load must reject with
# an error naming field (C5.2.2).
policies:
""")
    for name, p in POLICIES.items():
        w(f"  {name}: |\n")
        w('    apiVersion: "countersign.dev/v1alpha1"\n')
        w('    kind: "SessionPolicy"\n')
        w('    metadata: {name: "t"}\n')
        w("    spec:\n")
        s = p["spec"]
        for k, v in s.items():
            if k == "grants":
                continue
            w(f"      {k}: {flow(v)}\n")
        w("      grants:\n")
        for g in s["grants"]:
            w(f"        - {flow(g)}\n")
    w("rows:\n")
    for r in ROWS:
        request = r["request"]
        req_parts = [f"method: {json.dumps(request['method'])}",
                     f"host: {json.dumps(request['host'])}",
                     f"path: {json.dumps(request['path'])}"]
        for k in ("query",):
            if k in request:
                req_parts.append(f"{k}: {json.dumps(request[k])}")
        if "port" in request:
            req_parts.append(f"port: {request['port']}")
        for k in ("websocket", "tunnel"):
            if k in request:
                req_parts.append(f"{k}: {str(request[k]).lower()}")
        if "mcp" in request:
            m = request["mcp"]
            inner = f"method: {json.dumps(m['method'])}"
            if "tool" in m:
                inner += f", tool: {json.dumps(m['tool'])}"
            req_parts.append("mcp: {" + inner + "}")
        w(f'  - {{name: {json.dumps(r["name"])}, policy: {json.dumps(r["policy"])}, '
          f'grant: {json.dumps(r["grant"])}, request: {{{", ".join(req_parts)}}}')
        if r.get("taint"):
            w(", taint: [" + ", ".join(json.dumps(t) for t in r["taint"]) + "]")
        if r.get("c523"):
            w(", c523: true")
        e = r["expected"]
        w(f', expected: {{class: {json.dumps(e["class"])}, '
          f'requires: {json.dumps(e["requires"])}, '
          f'declared_safe: {str(e["declared_safe"]).lower()}}}}}\n')
    w("invalid:\n")
    for name, field, s in INVALID:
        w(f'  - name: {json.dumps(name)}\n')
        w(f'    field: {json.dumps(field)}\n')
        w('    policy: |\n')
        w('        apiVersion: "countersign.dev/v1alpha1"\n')
        w('        kind: "SessionPolicy"\n')
        w('        metadata: {name: "bad"}\n')
        w("        spec:\n")
        w('          mode: "enforce"\n')
        w('          scenario: "agent"\n')
        for k, v in s.items():
            if k == "grants":
                continue
            w(f"          {k}: {flow(v)}\n")
        w("          grants:\n")
        for g in s["grants"]:
            w(f"            - {flow(g)}\n")


if __name__ == "__main__":
    emit(sys.stdout)
    print(f"# {len(ROWS)} rows, {len(INVALID)} invalid", file=sys.stderr)
