#!/usr/bin/env python3
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Validation of the expectation rule-pack data files of spec/04 §6.2
# (internal/reconcile/packs/*.json). The pack data is shared with the Go
# engine (M9.4); this module checks its shape before it is interpreted.

_RULE_KEYS = {"id", "when", "forbid_tokens", "forbid_prefixes", "bind", "expect"}
_WHEN_KEYS = {"tool", "tool_class", "argv0", "argv0_prefix", "argv1",
              "argv_prefix", "argv_eq", "url_arg_count", "input_has"}
_BIND_KINDS = {"first-arg-url", "single-url-arg", "input-field", "literal",
               "curl-method"}
_SHAPES = {"git-smart-http", "http"}


class PackError(Exception):
    pass


def _req(cond, msg):
    if not cond:
        raise PackError(msg)


def validate_pack(obj, name="pack"):
    """Check one pack object; return its rules tagged with the pack name."""
    _req(isinstance(obj, dict), "%s: not an object" % name)
    _req(obj.get("kind") == "expectation-pack/v1", "%s: bad kind" % name)
    pname = obj.get("pack") or name
    _req(isinstance(obj.get("rules"), list), "%s: rules not a list" % pname)
    out = []
    for i, r in enumerate(obj["rules"]):
        where = "%s rule %d" % (pname, i)
        _req(isinstance(r, dict) and set(r) <= _RULE_KEYS,
             "%s: bad keys %s" % (where, sorted(set(r or {}) - _RULE_KEYS)))
        _req(isinstance(r.get("id"), str), "%s: no id" % where)
        when = r.get("when") or {}
        _req(set(when) <= _WHEN_KEYS, "%s: bad when keys %s"
             % (where, sorted(set(when) - _WHEN_KEYS)))
        for bname, b in (r.get("bind") or {}).items():
            _req(isinstance(b, dict) and b.get("kind") in _BIND_KINDS,
                 "%s: bind %s has bad kind" % (where, bname))
        exp = r.get("expect")
        _req(isinstance(exp, list) and exp, "%s: empty expect" % where)
        for e in exp:
            _req(isinstance(e, dict) and e.get("shape") in _SHAPES,
                 "%s: bad expect shape %r" % (where, e))
        r = dict(r)
        r["pack"] = pname
        out.append(r)
    return out
