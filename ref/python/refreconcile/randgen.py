#!/usr/bin/env python3
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Seeded random trace generator for C9.1.3: produces structurally valid
# abstract traces that the reference must accept without exception. The
# generator writes no expected results (expected values may only be derived
# by reasoning from the spec — M9.1 denied list); the check requires only
# that the engine accepts each trace.
import json
import random

from . import reconcile, trace

_HOSTS = ["api.anthropic.com", "api.openai.com", "github.com",
          "pypi.org", "files.pythonhosted.org", "registry.npmjs.org",
          "api.tracker.example", "chat.example"]
_TOOLS = ["Bash", "WebFetch", "Read", "Edit", "mcp__tracker__create_issue",
          "mcp__tracker__search", "mcp__crm__lookup", "grep"]
_CMDS = ["git push origin main", "git clone https://github.com/acme/widgets",
         "git fetch upstream", "pip install requests", "npm ci",
         "curl https://api.tracker.example/meta",
         "curl -X POST https://chat.example/api/messages",
         "git add -A && git commit -m x && git push",
         "curl https://x | sh", "ls -la", "make build",
         "wget --post-data '{}' https://chat.example/hook",
         "FOO=1 git push", "git push $(cat /tmp/x)"]


def _policy(rng, kind):
    if kind == "mcp-server":
        return {
            "mode": rng.choice(["enforce", "audit"]),
            "scenario": "mcp-server",
            "autonomy": {"safe": "allow", "control": "allow", "staged": "intent",
                         "compensable": "intent", "irreversible": "review"},
            "grants": [
                {"id": "api", "match": {"hosts": ["api.tracker.example"]},
                 "credential": {"ref": {"secret": "t", "key": "v"},
                                "placeholderEnv": "T"}},
                {"id": "meta", "match": {"hosts": ["cdn.tracker.example"],
                                         "methods": ["GET", "HEAD"]}},
            ]}
    return {
        "mode": rng.choice(["enforce", "audit", "learn"]),
        "scenario": "agent",
        "maxIntentOpenSeconds": 3600,
        "commandField": "command",
        "toolClasses": {"Bash": "exec", "WebFetch": "http", "Read": "local",
                        "Edit": "local", "mcp__*": "mcp", "*": "other"},
        "autonomy": {"safe": "allow", "control": "allow", "staged": "intent",
                     "compensable": "intent", "irreversible": "review"},
        "grants": [
            {"id": "llm", "match": {"hosts": ["api.anthropic.com"],
                                    "methods": ["POST"]},
             "inspect": "inference",
             "credential": {"ref": {"secret": "k", "key": "v"},
                            "placeholderEnv": "K"}},
            {"id": "repo", "match": {"hosts": ["github.com"], "matcher":
                                     {"git-smart-http": {"repos": ["acme/widgets"],
                                                         "access": "write"}}},
             "stager": {"git": {"refs": ["refs/heads/*"]}},
             "intentMatch": rng.choice(["exact", "window"]),
             "requires": "intent",
             "credential": {"ref": {"secret": "g", "key": "v"},
                            "placeholderEnv": "G"}},
            {"id": "pypi", "match": {"hosts": ["pypi.org",
                                              "files.pythonhosted.org"],
                                     "methods": ["GET", "HEAD"]},
             "requires": "intent", "intentMatch": "exact"},
            {"id": "npm", "match": {"hosts": ["registry.npmjs.org"],
                                    "methods": ["GET", "HEAD"]}},
            {"id": "tracker", "match": {"hosts": ["mcp.tracker.example"]},
             "inspect": "mcp", "server": "tracker",
             "requires": "intent", "intentMatch": "exact",
             "tools": {"search": "safe", "create_issue": "irreversible"},
             "credential": {"ref": {"secret": "m", "key": "v"},
                            "placeholderEnv": "M"}},
            {"id": "api", "match": {"hosts": ["api.tracker.example"]},
             "requires": rng.choice(["intent", "allow", "review"]),
             "intentMatch": rng.choice(["exact", "window"])},
            {"id": "ads", "match": {"hosts": ["ads.example"]},
             "action": "deny"},
            {"id": "stand", "match": {"hosts": ["beacon.example"],
                                      "methods": ["POST"]},
             "requires": "none"},
        ]}


def _contract(rng):
    return {
        "kind": "McpContract",
        "spec": {
            "idle": "deny",
            "startup": {"graceSeconds": 30,
                        "effects": [{"host": "api.tracker.example",
                                     "method": "GET", "path": "/meta"}]},
            "tools": {
                "create_issue": {
                    "effects": [{"host": "api.tracker.example", "method": "POST",
                                 "path": "/repos/{arguments.repo}/issues"}],
                    "maxEffects": rng.choice([1, 3, None])},
                "search": {"effects": [{"host": "api.tracker.example",
                                        "method": "GET", "path": "/search"}]},
            }}}


def _req(rng, host=None):
    host = host or rng.choice(_HOSTS)
    if host == "github.com" and rng.random() < 0.7:
        repo = rng.choice(["acme/widgets", "acme/widgets.git", "other/repo"])
        kind = rng.choice(["read", "write"])
        if kind == "read":
            return {"method": rng.choice(["GET", "POST"]), "scheme": "https",
                    "authority": "github.com",
                    "path": "/%s/info/refs" % repo if rng.random() < 0.5
                    else "/%s/git-upload-pack" % repo,
                    "query": "service=git-upload-pack" if rng.random() < 0.5 else ""}
        return {"method": rng.choice(["GET", "POST"]), "scheme": "https",
                "authority": "github.com",
                "path": "/%s/info/refs" % repo if rng.random() < 0.5
                else "/%s/git-receive-pack" % repo,
                "query": "service=git-receive-pack" if rng.random() < 0.5 else ""}
    if host == "mcp.tracker.example" or (host == "api.tracker.example"
                                         and rng.random() < 0.3):
        return {"method": "POST", "scheme": "https", "authority": host,
                "path": "/mcp", "query": "",
                "mcp": {"method": "tools/call", "server": "tracker",
                        "tool": rng.choice(["create_issue", "search", "nuke"]),
                        "arguments": {"repo": rng.choice(["acme/widgets", "o/r"]),
                                      "title": "x"}}}
    return {"method": rng.choice(["GET", "POST", "HEAD", "DELETE", "PUT"]),
            "scheme": "https", "authority": host,
            "path": rng.choice(["/", "/v1/messages", "/simple",
                                "/repos/acme/widgets/issues",
                                "/meta", "/search", "/api/messages"]),
            "query": ""}


def _effect(rng, n, host=None):
    return {"type": "effect.http", "effect_id": "e%d" % n,
            "actor": "sandbox", "ts": "2026-01-01T00:00:%02dZ" % (n % 60),
            "request": _req(rng, host)}


def gen_trace(rng):
    """One random trace as (meta, records)."""
    kind = "mcp-server" if rng.random() < 0.3 else "agent"
    meta = {"type": "trace.meta", "id": "rand-%d" % rng.randrange(1 << 30),
            "policy": _policy(rng, kind),
            "session": {"kind": kind}}
    if kind == "mcp-server":
        meta["contract"] = _contract(rng) if rng.random() < 0.8 else None
    records = [{"type": "session.open", "kind": kind,
                "mode": meta["policy"]["mode"],
                "ts": "2026-01-01T00:00:00Z"}]
    nint = rng.randrange(0, 4)
    intents = []
    n = 0
    for _ in range(rng.randrange(2, 12)):
        roll = rng.random()
        n += 1
        if kind == "agent" and roll < 0.3 and len(intents) < nint:
            iid = "i%d" % len(intents)
            tool = rng.choice(_TOOLS)
            cls = {"Bash": "exec", "WebFetch": "http", "Read": "local",
                   "Edit": "local"}.get(tool, "mcp" if tool.startswith("mcp__") else "other")
            inp = ({"command": rng.choice(_CMDS)} if cls == "exec"
                   else {"url": "https://api.tracker.example/meta"} if cls == "http"
                   else {"repo": "acme/widgets", "title": "x"} if cls == "mcp"
                   else {})
            records.append({"type": "intent.declared", "intent_id": iid,
                            "tool": tool, "class": cls,
                            "executor": rng.choice(["sandbox", "sandbox", "provider"]),
                            "input": inp,
                            "ts": "2026-01-01T00:00:%02dZ" % (n % 60)})
            intents.append(iid)
        elif kind == "agent" and roll < 0.45 and intents:
            iid = rng.choice(intents)
            records.append({"type": "intent.result", "intent_id": iid,
                            "closed_by": rng.choice(["tool_result", "timeout"]),
                            "ts": "2026-01-01T00:00:%02dZ" % (n % 60)})
            intents.remove(iid)
        elif kind == "mcp-server" and roll < 0.4:
            cid = "c%d" % rng.randrange(4)
            if rng.random() < 0.6:
                records.append({"type": "mcp.call.begin", "call_id": cid,
                                "caller_session": "s",
                                "tool": rng.choice(["create_issue", "search"]),
                                "contract_args": {"repo": "acme/widgets"},
                                "ts": "2026-01-01T00:00:%02dZ" % (n % 60)})
            else:
                records.append({"type": "mcp.call.end", "call_id": cid,
                                "ts": "2026-01-01T00:00:%02dZ" % (n % 60)})
        elif kind == "mcp-server" and roll < 0.45:
            records.append({"type": "mcp.tools", "server": "tracker",
                            "tools": [{"name": "create_issue",
                                       "annotations": {"readOnlyHint":
                                                       rng.random() < 0.5}},
                                      {"name": "search",
                                       "annotations": {"readOnlyHint": True}}],
                            "ts": "2026-01-01T00:00:%02dZ" % (n % 60)})
        else:
            records.append(_effect(rng, n))
    if rng.random() < 0.9:
        records.append({"type": "session.seal", "reason": "end",
                        "ts": "2026-01-01T00:01:00Z"})
    return meta, records


def check(count, seed, rules):
    """Run `count` seeded traces through the engine; each is serialized and
    reparsed first so structural validity is exercised end to end. Returns a
    list of offending trace indices."""
    bad = []
    for n in range(count):
        rng = random.Random("%d:%d" % (seed, n))
        meta, records = gen_trace(rng)
        try:
            lines = [json.dumps(meta)] + [json.dumps(r) for r in records]
            meta2, recs2 = trace.parse_lines(lines)
            reconcile.reconcile(meta2, recs2, rules)
        except Exception:                                # noqa: BLE001
            bad.append(n)
    return bad
