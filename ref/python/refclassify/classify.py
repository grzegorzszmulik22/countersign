#!/usr/bin/env python3
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Reference classifier for spec/05-transactions.md §1-§2 (M5.2), written
# from the spec. Reads {"cases": [{"policy": <spec object>, "grant": <id>,
# "request": {...}, "taint": [...]}]} on stdin and prints a JSON array of
# {"class": <class>, "requires": <condition>, "declared_safe": <bool>}.
#
# A request carries {method, host (host[:port]), path (unreserved-decoded),
# query, websocket, tunnel, mcp: {method, tool}}.
import json
import sys

READ_METHODS = {"GET", "HEAD", "OPTIONS"}
BOUNDARY_HOST = "countersign.internal"
COND_ORDER = {"allow": 0, "intent": 1, "review": 2, "deny": 3}
COND_NAME = ["allow", "intent", "review", "deny"]


def norm_host(h):  # 04 §1: lowercase, drop brackets, drop one root dot
    h = h.lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h[:-1] if h.endswith(".") else h


def authority_host(hostport):  # split host[:port]; brackets kept out
    a = hostport.lower()
    if a.startswith("["):
        end = a.find("]")
        if end != -1:
            return a[1:end]
    if ":" in a:
        head, _, tail = a.rpartition(":")
        if tail.isdigit():
            return head
    return a


def git_op(request):  # 04 §2 smart-HTTP wire shapes -> (access, owner, repo)
    segs = request.get("path", "/").split("/")
    if segs and segs[0] == "":
        segs = segs[1:]
    method, query = request.get("method"), request.get("query", "")
    if len(segs) == 4 and segs[2] == "info" and segs[3] == "refs":
        if method != "GET":
            return None
        if query == "service=git-upload-pack":
            access = "read"
        elif query == "service=git-receive-pack":
            access = "write"
        else:
            return None
    elif len(segs) == 3 and segs[2] in ("git-upload-pack", "git-receive-pack"):
        if method != "POST" or query != "":
            return None
        access = "read" if segs[2] == "git-upload-pack" else "write"
    else:
        return None
    owner, repo = segs[0], segs[1][:-4] if segs[1].endswith(".git") else segs[1]
    return (access, owner, repo) if owner and repo else None


def git_covers(matcher, op):  # repos membership + access level (04 §2)
    git = (matcher or {}).get("git-smart-http") or {}
    if op[0] == "write" and git.get("access") != "write":
        return False
    for e in git.get("repos") or []:
        parts = e.split("/")
        if len(parts) == 2:
            name = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
            if parts[0] == op[1] and name == op[2]:
                return True
    return False


def stager_stages(grant, request):  # 05 §4 git writes; §5 outbox non-reads
    stager = grant.get("stager") or {}
    if "git" in stager:
        op = git_op(request)
        return (op is not None and op[0] == "write"
                and git_covers((grant.get("match") or {}).get("matcher"), op))
    if "outbox" in stager:
        return request.get("method") not in READ_METHODS
    return False


def classify(grant, request):
    """05 §1's ordered class rules; the first rule that applies wins."""
    mcp = request.get("mcp")
    # 1. The agent talking to its model or its own boundary.
    if (grant.get("inspect") == "inference"
            or norm_host(authority_host(request.get("host", ""))) == BOUNDARY_HOST
            or (grant.get("inspect") == "mcp" and mcp
                and mcp.get("method") != "tools/call")):
        return "control"
    # 2. An explicit grant class wins next.
    if grant.get("class"):
        return grant["class"]
    # 3. Passthrough and WebSocket upgrades.
    if grant.get("mode") == "passthrough" or request.get("websocket"):
        return "irreversible"
    # 4. The configured stager stages the request.
    if stager_stages(grant, request):
        return "staged"
    # 5. A smart-HTTP read inside the grant's matcher.
    matcher = (grant.get("match") or {}).get("matcher")
    if matcher and (matcher.get("git-smart-http") is not None):
        op = git_op(request)
        if op and op[0] == "read" and git_covers(matcher, op):
            return "safe"
    # 6. Read methods are safe.
    if request.get("method") in READ_METHODS:
        return "safe"
    # 7-8. tools/call: control on brokered servers; per-tool class on
    #     inspected servers, else irreversible.
    if mcp and mcp.get("method") == "tools/call":
        if grant.get("calls") == "serialized":
            return "control"
        if grant.get("inspect") == "mcp":
            cls = (grant.get("tools") or {}).get(mcp.get("tool"))
            return cls if cls else "irreversible"
    # 9. A compensate rule applying to this method.
    comp = grant.get("compensate") or {}
    for rule in ("restore", "deleteCreated"):
        if request.get("method") in ((comp.get(rule) or {}).get("methods") or []):
            return "compensable"
    # 10. Otherwise irreversible.
    return "irreversible"


def taint_cond(grant, labels):  # 04 §8: whenTainted for the labels present
    wt = grant.get("whenTainted")
    if wt is None or not labels:
        return "allow"
    default = wt.get("default")
    if not default:
        # 04 §1 defaults: review when credentialed or a non-GET/HEAD method
        # is permitted, else allow.
        methods = (grant.get("match") or {}).get("methods")
        if grant.get("credential") or not methods or any(
                m not in ("GET", "HEAD") for m in methods):
            default = "review"
        else:
            default = "allow"
    best = 0
    for label in labels:
        best = max(best, COND_ORDER.get(
            (wt.get("labels") or {}).get(label) or default, 0))
    return COND_NAME[best]


def condition(policy, grant, cls, taint):
    """05 §2: strictest of autonomy[class], grant requires, whenTainted."""
    conds = [(policy.get("autonomy") or {}).get(cls) or "allow",
             grant.get("requires") or "allow"]
    if cls in ("compensable", "irreversible"):
        conds.append(taint_cond(grant, taint or []))
    return COND_NAME[max(COND_ORDER.get(c if c != "none" else "allow", 0)
                         for c in conds)]


def declared_safe(grant, request, cls):  # 05 §1 rule 2 flag
    return (cls == "safe" and grant.get("class") == "safe"
            and (request.get("method") != "GET" or bool(request.get("tunnel"))
                 or bool(request.get("websocket"))))


def decide(policy, grant, request, taint):
    cls = classify(grant, request)
    return {
        "class": cls,
        "requires": condition(policy, grant, cls, taint),
        "declared_safe": declared_safe(grant, request, cls),
    }


def main():
    cases = json.load(sys.stdin)["cases"]
    out = []
    for case in cases:
        spec = case["policy"]
        grant = next(g for g in spec.get("grants", [])
                     if g.get("id") == case["grant"])
        out.append(decide(spec, grant, case["request"], case.get("taint")))
    json.dump(out, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
