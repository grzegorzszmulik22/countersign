#!/usr/bin/env python3
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Differential harness driver for check-M9.2.sh (lane reconcile-go).
#
#   recongen.py mm91 --count N --seed S --work DIR
#       Writes DIR/traces.jsonl ({"meta","records"} per line) and
#       DIR/expected.jsonl (the reference engine's result per line).
#   recongen.py mm92 --count N --seed S --work DIR
#       Writes DIR/traces.jsonl of audit-mode traces in which one effect
#       per trace is planted unattributed (an allowed effect under an
#       intent condition with no qualifying intent) and DIR/planted.json
#       listing {line, effect_id} pairs the reconciler must flag.
import argparse
import copy
import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ref", "python"))
from refreconcile import corpus, randgen, reconcile, trace  # noqa: E402

_PACKS = os.path.join(os.path.dirname(__file__), "..", "..", "internal",
                      "reconcile", "packs")


def load_rules():
    return corpus.load_packs(_PACKS)


def gen_lines(count, seed):
    """Yield (meta, records) pairs like randgen.check but keeping them."""
    for n in range(count):
        rng = random.Random("%d:%d" % (seed, n))
        meta, records = randgen.gen_trace(rng)
        # Serialize and reparse exactly like the reference's check does.
        lines = [json.dumps(meta)] + [json.dumps(r) for r in records]
        yield trace.parse_lines(lines)


def cmd_mm91(args):
    rules = load_rules()
    n = 0
    with open(os.path.join(args.work, "traces.jsonl"), "w") as tf, \
            open(os.path.join(args.work, "expected.jsonl"), "w") as ef:
        for meta, records in gen_lines(args.count, args.seed):
            res = reconcile.reconcile(meta, records, rules)
            tf.write(json.dumps({"meta": meta, "records": records}) + "\n")
            ef.write(json.dumps(res) + "\n")
            n += 1
    print("wrote %d traces" % n)


def _plant_unattributed(rng, meta, records):
    """Plant one allowed-but-unattributable effect in an agent trace.

    Forces policy mode audit, requires:intent on a fresh grant for a host
    nothing else matches, then appends an allowed effect.http for that
    host whose decision claims allow — with no intent open it can never
    attribute. Returns the planted effect_id.
    """
    meta = copy.deepcopy(meta)
    records = list(records)
    pol = meta.setdefault("policy", {})
    pol["mode"] = "audit"
    pol.setdefault("autonomy", {})
    host = "planted-%d.example" % rng.randrange(1 << 30)
    pol.setdefault("grants", []).append(
        {"id": "planted", "match": {"hosts": [host]},
         "requires": "intent", "intentMatch": "exact"})
    eid = "planted-%d" % rng.randrange(1 << 30)
    # A GET is class "safe" -> autonomy allow -> the grant's
    # requires:intent is the strictest and sets the intent condition.
    # Inserted right after session.open, no intent is open yet, so the
    # recomputed level is NONE — under audit the broker records the allow
    # and the effect is unattributed by spec/04 §6.5.
    rec = {"type": "effect.http", "effect_id": eid, "actor": "sandbox",
           "ts": "2026-01-01T00:00:00Z",
           "request": {"method": "GET", "scheme": "https",
                       "authority": host, "path": "/x", "query": ""},
           "class": "safe",
           "decision": {"action": "allow", "reason": "OK",
                        "requires": "intent", "grant": "planted",
                        "credentials": [],
                        "would_deny": {"action": "deny",
                                       "reason": "NO_INTENT"}},
           "attribution": {"level": "NONE", "intents": []}}
    pos = 1 if records and records[0].get("type") == "session.open" else 0
    records.insert(pos, rec)
    for r in records:
        if r.get("type") == "session.open":
            r["mode"] = "audit"
            break
    return meta, records, eid


def cmd_mm92(args):
    n = 0
    planted = []
    with open(os.path.join(args.work, "traces.jsonl"), "w") as tf:
        for meta, records in gen_lines(args.count, args.seed):
            rng = random.Random("mm92:%d:%d" % (args.seed, n))
            if meta.get("policy", {}).get("mode") == "learn":
                continue
            if (records and records[0].get("kind") == "mcp-server"):
                # Agent sessions only: server-session effects carry no
                # intents by design.
                continue
            meta2, records2, eid = _plant_unattributed(rng, meta, records)
            tf.write(json.dumps({"meta": meta2, "records": records2}) + "\n")
            planted.append({"line": n, "effect_id": eid})
            n += 1
    with open(os.path.join(args.work, "planted.json"), "w") as pf:
        json.dump(planted, pf)
    print("wrote %d audit traces with planted unattributed effects" % n)


def main():
    p = argparse.ArgumentParser(prog="recongen")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("mm91", "mm92"):
        s = sub.add_parser(name)
        s.add_argument("--count", type=int, required=True)
        s.add_argument("--seed", type=int, required=True)
        s.add_argument("--work", required=True)
    a = p.parse_args()
    os.makedirs(a.work, exist_ok=True)
    if a.cmd == "mm91":
        cmd_mm91(a)
    else:
        cmd_mm92(a)


if __name__ == "__main__":
    main()
