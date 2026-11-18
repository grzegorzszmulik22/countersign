#!/usr/bin/env python3
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Comparer for the M9.2 differential harness.
#
#   reconcmp.py mm91 EXPECTED.jsonl GOT.jsonl
#       Per-line compare of the reference result vs the Go result:
#       per-effect level, intents, decision (action/reason), class,
#       condition, grant, would_deny, no_auto + findings + verdict.
#   reconcmp.py mm92 PLANTED.json GOT.jsonl
#       Every planted effect must carry F_UNATTRIBUTED in its trace's
#       findings.
import json
import sys

_FIELDS = ["grant", "class", "condition", "level", "intents", "action",
           "reason", "would_deny", "no_auto", "grant_has_credential", "mode"]


def _norm(v):
    if v == []:
        return []
    return v


def _cmp_effect(rid, want, got):
    diffs = []
    if got is None:
        return ["effect %s: expected but absent" % rid]
    for k in _FIELDS:
        w = _norm(want.get(k))
        g = _norm(got.get(k))
        if k == "intents":
            w, g = w or [], g or []
        if w != g:
            diffs.append("effect %s.%s: want %r got %r" % (rid, k, w, g))
    return diffs


def _cmp_findings(want, got):
    wf = sorted((f["code"], f.get("effect") or "") for f in (want or []))
    gf = sorted((f["code"], f.get("effect") or "") for f in (got or []))
    if wf != gf:
        return ["findings: want %r got %r" % (wf, gf)]
    return []


def cmd_mm91(exp_path, got_path):
    bad = 0
    n = 0
    shown = 0
    with open(exp_path) as ef, open(got_path) as gf:
        for n, (el, gl) in enumerate(zip(ef, gf)):
            want = json.loads(el)
            got = json.loads(gl)
            if "error" in got and "effects" not in got:
                diffs = ["engine error: %s" % got["error"]]
            else:
                diffs = []
                wr = set(want["effects"])
                gr = set(got["effects"])
                for rid in sorted(wr | gr):
                    diffs += _cmp_effect(rid, want["effects"].get(rid),
                                         got["effects"].get(rid))
                diffs += _cmp_findings(want["findings"], got["findings"])
                if want["verdict"] != got["verdict"]:
                    diffs.append("verdict: want %r got %r"
                                 % (want["verdict"], got["verdict"]))
            if diffs:
                bad += 1
                if shown < 10:
                    for d in diffs[:5]:
                        print("line %d: %s" % (n, d))
                    shown += 1
    total = n + 1
    print("mm91: %d/%d traces identical" % (total - bad, total))
    return 1 if bad else 0


def cmd_mm92(planted_path, got_path):
    planted = json.load(open(planted_path))
    lines = open(got_path).read().splitlines()
    flagged = 0
    misses = []
    for p in planted:
        got = json.loads(lines[p["line"]])
        hits = [f for f in got["findings"]
                if f["code"] == "F_UNATTRIBUTED" and f.get("effect") == p["effect_id"]]
        if hits:
            flagged += 1
        else:
            misses.append(p)
            if len(misses) <= 10:
                print("line %d effect %s: no F_UNATTRIBUTED (findings: %r)"
                      % (p["line"], p["effect_id"], got["findings"]))
    print("mm92: %d/%d planted unattributed effects flagged"
          % (flagged, len(planted)))
    return 0 if flagged == len(planted) and len(planted) >= 500 else 1


def main():
    mode, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
    if mode == "mm91":
        sys.exit(cmd_mm91(a, b))
    if mode == "mm92":
        sys.exit(cmd_mm92(a, b))
    sys.exit(2)


if __name__ == "__main__":
    main()
