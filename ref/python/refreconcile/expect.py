#!/usr/bin/env python3
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# spec/04 §6.2 expectation rules: instantiate the expectation of an intent's
# tool input and test whether an effect's request matches it.
#
# Rule packs are JSON data (internal/reconcile/packs/*.json); this module is
# the interpreter. A rule fires only for a simple command that tokenizes with
# plain shell-word splitting and contains none of | & < > $ ` ( ) { } —
# anything else contributes no expectation and can reach at most WINDOW.
import re
import shlex
from urllib.parse import urlsplit

from . import grants

FORBIDDEN = frozenset("|&<>$`(){}")
_URL_RE = re.compile(r"^https?://[^\s]+$")


def split_simple(command):
    """Split a command on &&, ||, ; and newlines, honouring quotes.

    Returns a list of raw simple-command strings. An operator inside quotes
    does not split; the fragment then still contains the forbidden character
    and fails the raw-text test below, so nothing is gained by quoting it.
    """
    frags, cur, quote, i = [], [], None, 0
    while i < len(command):
        c = command[i]
        if quote is None:
            if c in "\"'":
                quote = c
            elif command.startswith("&&", i) or command.startswith("||", i):
                frags.append("".join(cur)); cur = []; i += 2; continue
            elif c in ";\n":
                frags.append("".join(cur)); cur = []; i += 1; continue
        else:
            if c == quote:
                quote = None
            elif c == "\\" and quote == '"' and i + 1 < len(command):
                cur.append(c); cur.append(command[i + 1]); i += 2; continue
        cur.append(c)
        i += 1
    frags.append("".join(cur))
    return frags


def tokenize(fragment):
    """04 §6.2: a rule may fire only for a fragment that tokenizes with
    plain shell-word splitting and contains no forbidden character."""
    if any(c in FORBIDDEN for c in fragment):
        return None
    try:
        argv = shlex.split(fragment, posix=True)
    except ValueError:
        return None
    return argv or None


def _basename(arg):
    return arg.rsplit("/", 1)[-1]


def _urlish(arg):
    if _URL_RE.match(arg or ""):
        try:
            u = urlsplit(arg)
            if u.hostname:
                u.port                                 # force validation now
                return u
        except ValueError:
            return None
    return None


def _when_ok(when, argv, tool_input):
    """Match a rule's `when` clause against argv / tool input."""
    if "argv0" in when and _basename(argv[0]) not in when["argv0"]:
        return False
    if "argv0_prefix" in when and \
            not any(_basename(argv[0]).startswith(p) for p in when["argv0_prefix"]):
        return False
    if "argv1" in when and (len(argv) < 2 or argv[1] not in when["argv1"]):
        return False
    if "argv_prefix" in when:
        pre = when["argv_prefix"]
        if argv[1:1 + len(pre)] != pre:
            return False
    if "argv_eq" in when and argv != when["argv_eq"]:
        return False
    if "url_arg_count" in when:
        if sum(1 for a in argv[1:] if _urlish(a) is not None) != when["url_arg_count"]:
            return False
    if "input_has" in when:
        ti = tool_input or {}
        if any(k not in ti for k in when["input_has"]):
            return False
    return True


def _bind_one(spec, argv, tool_input):
    """Evaluate one bind expression; return the bound value or None."""
    kind = spec.get("kind")
    if kind == "first-arg-url":
        schemes = spec.get("schemes") or ["https"]
        for a in (argv or [])[1:]:
            u = _urlish(a)
            if u is not None and u.scheme in schemes:
                return a
        return None
    if kind == "single-url-arg":
        urls = [a for a in (argv or [])[1:] if _urlish(a) is not None]
        return urls[0] if len(urls) == 1 else None
    if kind == "input-field":
        v = (tool_input or {}).get(spec.get("field"))
        if v is None:
            return spec.get("default")
        return v if isinstance(v, str) else None
    if kind == "literal":
        return spec.get("value")
    if kind == "curl-method":
        return _curl_method(argv or [])
    return None


_METHOD_FLAGS = ("-X", "--request", "--method")


def _curl_method(argv):
    """curl/wget row: method from -X/--request/--method, else POST when a data
    flag is present, else GET (04 §6.2)."""
    data_flags = ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii",
                  "--data-urlencode", "-F", "--form", "-T", "--upload-file",
                  "--post-data", "--post-file")
    for i, a in enumerate(argv[1:], 1):
        for f in _METHOD_FLAGS:
            if a == f and i + 1 < len(argv):
                return argv[i + 1].upper()
            if a.startswith(f + "="):
                return a.split("=", 1)[1].upper()
            if not f.startswith("--") and a.startswith(f) and len(a) > len(f):
                return a[len(f):].upper()          # curl -XPOST
    for a in argv[1:]:
        if a in data_flags:
            return "POST"
        if not a.startswith("--") and len(a) > 2 and a[0] == "-" and a[1] in "dFT":
            return "POST"                          # -dX, -F.., -T.. short forms
        if any(a.startswith(f + "=") for f in data_flags if f.startswith("--")):
            return "POST"
    return "GET"


def rule_expectations(rule, argv, tool_input):
    """Instantiate a rule on one simple command. Returns a list of concrete
    expectation objects (empty when the rule does not fire)."""
    when = rule.get("when") or {}
    if not _when_ok(when, argv or ["_"], tool_input):
        return []
    argv = argv or []
    for tok in rule.get("forbid_tokens") or []:
        if tok in argv:
            return []
    for a in argv:
        if any(a.startswith(p) for p in rule.get("forbid_prefixes") or []):
            return []
    bound = {}
    for name, spec in (rule.get("bind") or {}).items():
        v = _bind_one(spec, argv, tool_input)
        if v is None and spec.get("required"):
            return []
        bound[name] = v
    out = []
    for e in rule.get("expect") or []:
        exp = {}
        for k, v in e.items():
            if isinstance(v, str) and v.startswith("{") and v.endswith("}"):
                key = v[1:-1]
                exp[k] = bound.get(key)          # None -> unbound
            else:
                exp[k] = v
        out.append(exp)
    return out


def intent_expectations(intent, packs):
    """All expectations one intent produces, over every simple command of its
    command field and every tool-input rule that applies to its class."""
    cls = intent.get("class")
    tool_input = intent.get("input") if isinstance(intent.get("input"), dict) else {}
    command = tool_input.get(intent.get("command_field") or "command")
    out = []
    for rule in packs:
        when = rule.get("when") or {}
        tcls = when.get("tool_class")
        if tcls is not None and tcls != cls:
            continue
        if "tool" in when and when["tool"] != intent.get("tool"):
            continue
        if cls == "exec":
            if not isinstance(command, str) or not command:
                continue
            for frag in split_simple(command):
                argv = tokenize(frag)
                if argv is None:
                    continue
                out.extend(rule_expectations(rule, argv, tool_input))
        else:
            out.extend(rule_expectations(rule, None, tool_input))
    return out


def _git_expect_match(exp, request, grant):
    op = grants.git_op(request)
    if op is None:
        return False
    want = exp.get("access") or "read"
    if want == "read" and op["access"] != "read":
        return False                                # a read intent never covers a write op
    url = exp.get("url")
    if url:
        u = _urlish(url)
        if u is None:
            return False
        segs = [s for s in u.path.split("/") if s]
        if len(segs) != 2:
            return False
        host, port = grants.split_authority(request.get("authority"), 443)
        if grants.norm_host(host) != grants.norm_host(u.hostname):
            return False
        if u.port and port != u.port:
            return False
        return (op["owner"] == segs[0]
                and grants._git_seg(segs[1]) == op["repo"])
    # Unbound: any repository inside the selected grant.
    return grants._git_grant_ok((grant.get("match") or {}).get("matcher"), op)


def _http_expect_match(exp, request):
    method = request.get("method")
    if exp.get("methods") is not None and method not in exp["methods"]:
        return False
    if exp.get("method") is not None and method != exp["method"]:
        return False
    host, port = grants.split_authority(
        request.get("authority"),
        80 if (request.get("scheme") or "https") == "http" else 443)
    host = grants.norm_host(host)
    if exp.get("hosts") is not None and \
            host not in [grants.norm_host(h) for h in exp["hosts"]]:
        return False
    url = exp.get("url")
    if url:
        u = _urlish(url)
        if u is None:
            return False
        if (request.get("scheme") or "https") != u.scheme:
            return False
        uport = u.port or (80 if u.scheme == "http" else 443)
        if grants.norm_host(u.hostname) != host or uport != port:
            return False
        upath = u.path or "/"
        if grants.pct_decode_unres(request.get("path") or "/") != grants.pct_decode_unres(upath):
            return False
        if u.query:
            if (request.get("query") or "") != u.query:
                return False
        elif request.get("query"):
            return False                            # "that URL" committed to no query
    return True


def expectation_matches(exp, request, grant):
    """Does one instantiated expectation match an effect's request?"""
    shape = exp.get("shape")
    if shape == "git-smart-http":
        return _git_expect_match(exp, request, grant)
    if shape == "http":
        return _http_expect_match(exp, request)
    return False
