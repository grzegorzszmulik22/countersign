#!/usr/bin/env python3
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Corpus and coverage harness for the reference reconciler.
#
#   python -m refreconcile.corpus trace FILE [--packs DIR]
#   python -m refreconcile.corpus corpus DIR [--packs DIR]
#   python -m refreconcile.corpus coverage DIR [--packs DIR] [--min PCT]
#   python -m refreconcile.corpus randgen --count N --seed S [--packs DIR]
#   python -m refreconcile.corpus packcheck DIR
#
# `corpus`  : every trace's recomputed result must equal its expect block.
# `coverage`: statement coverage of the engine modules by the corpus
#             (sys.settrace; statement lines from the bytecode line table).
# `randgen` : N seeded random traces, each serialized, reparsed and accepted
#             by the engine without exception.
import json
import os
import sys

from . import reconcile, trace

_PKG = os.path.dirname(os.path.abspath(__file__))
# Modules that encode the spec's semantics; corpus/randgen/__main__ are the
# check tooling itself and are not part of the measured reference surface.
_MEASURED = ("canon.py", "grants.py", "expect.py", "reconcile.py",
             "trace.py", "packs.py")


def load_packs(packs_dir):
    """Load every pack file (*.json) in a directory into one flat rule list
    tagged with its pack name."""
    from .packs import validate_pack
    rules = []
    for name in sorted(os.listdir(packs_dir)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(packs_dir, name), "r", encoding="utf-8") as f:
            pack = json.load(f)
        rules.extend(validate_pack(pack, name))
    return rules


def run_file(path, rules):
    meta, records = trace.load(path)
    return reconcile.reconcile(meta, records, rules)


def compare_expected(meta, result):
    """Diff the trace.meta expect block against the recomputed result.
    Returns a list of human-readable differences."""
    exp = meta.get("expect") or {}
    diffs = []
    ee = exp.get("effects") or {}
    for rid, want in ee.items():
        got = result["effects"].get(rid)
        if got is None:
            diffs.append("effect %s: expected but absent" % rid)
            continue
        for k, v in want.items():
            if got.get(k) != v:
                diffs.append("effect %s.%s: want %r got %r" % (rid, k, v, got.get(k)))
    extra = [r for r in result["effects"] if r not in ee] if ee else []
    for rid in extra:
        diffs.append("effect %s: produced but not expected" % rid)
    want_f = sorted((f.get("code"), f.get("effect") or "")
                    for f in (exp.get("findings") or []))
    got_f = sorted((f["code"], f.get("effect") or "")
                   for f in result["findings"])
    if want_f != got_f:
        diffs.append("findings: want %s got %s" % (want_f, got_f))
    if "verdict" in exp and exp["verdict"] != result["verdict"]:
        diffs.append("verdict: want %r got %r" % (exp["verdict"], result["verdict"]))
    return diffs


def cmd_corpus(vectors, rules, quiet=False):
    files = sorted(f for f in os.listdir(vectors) if f.endswith(".jsonl"))
    fails = []
    for name in files:
        path = os.path.join(vectors, name)
        try:
            meta, records = trace.load(path)
            result = reconcile.reconcile(meta, records, rules)
            diffs = compare_expected(meta, result)
        except Exception as e:                        # noqa: BLE001 - report, don't die
            diffs = ["exception %s: %s" % (type(e).__name__, e)]
        if diffs:
            fails.append((name, diffs))
        if not quiet:
            print("%-34s %s" % (name, "ok" if not diffs else "; ".join(diffs[:3])))
    return files, fails


def _code_lines(path):
    """Statement line numbers: every line the bytecode line table names."""
    import dis  # noqa: F401  (documents the approach)
    with open(path, "r", encoding="utf-8") as f:
        co = compile(f.read(), path, "exec")
    lines = set()

    def walk(c):
        for _, _, ln in c.co_lines():
            if ln is not None:
                lines.add(ln)
        for const in c.co_consts:
            if hasattr(const, "co_code"):
                walk(const)
    walk(co)
    return lines


# The coverage run executes in a child interpreter with the tracer installed
# before the package is imported, so module-level lines count as covered.
_COV_CHILD = r"""
import json, os, sys
pkg, vectors, packs_dir = sys.argv[1:4]
sys.path.insert(0, os.path.dirname(os.path.abspath(pkg)))
hit = {}


def tracer(frame, event, arg):
    if event == "line" and os.path.dirname(frame.f_code.co_filename) == pkg:
        hit.setdefault(frame.f_code.co_filename, set()).add(frame.f_lineno)
    return tracer


sys.settrace(tracer)
from refreconcile import corpus            # noqa: E402  (after the tracer)
rules = corpus.load_packs(packs_dir)
corpus.cmd_corpus(vectors, rules, quiet=True)
sys.settrace(None)
print(json.dumps({k: sorted(v) for k, v in hit.items()}))
"""


def _traced_run(vectors, packs_dir):
    import subprocess
    out = subprocess.run(
        [sys.executable, "-c", _COV_CHILD, _PKG, vectors, packs_dir],
        capture_output=True, text=True)
    if out.returncode != 0:
        sys.stderr.write(out.stdout + out.stderr)
        raise SystemExit("coverage child failed")
    raw = json.loads(out.stdout.strip().splitlines()[-1])
    return {os.path.basename(k): set(v) for k, v in raw.items()}


def cmd_coverage(vectors, packs_dir, minimum):
    hit = _traced_run(vectors, packs_dir)
    total, covered, uncovered = 0, 0, {}
    for mod in _MEASURED:
        path = os.path.join(_PKG, mod)
        lines = _code_lines(path)
        if not lines:
            continue
        got = len(hit[mod] & lines)
        total += len(lines)
        covered += got
        miss = sorted(lines - hit[mod])
        if miss:
            uncovered[mod] = miss
        print("%-14s %4d/%4d lines%s" % (
            mod, got, len(lines),
            "  uncovered: " + ",".join(map(str, miss)) if miss else ""))
    pct = 100.0 * covered / total if total else 0.0
    print("total: %d/%d statement lines = %.2f%% (minimum %.2f%%)"
          % (covered, total, pct, minimum))
    return pct, uncovered


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(prog="refreconcile.corpus")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("trace", "corpus", "coverage", "randgen", "packcheck"):
        s = sub.add_parser(name)
        s.add_argument("arg", nargs="?", help="trace file / corpus dir / packs dir")
        s.add_argument("--packs", default=None, help="pack directory")
        s.add_argument("--count", type=int, default=10000)
        s.add_argument("--seed", type=int, default=1)
        s.add_argument("--min", type=float, default=95.0, dest="minimum")
    a = p.parse_args(argv)
    repo = os.path.abspath(os.path.join(_PKG, "..", "..", ".."))
    packs_dir = a.packs or os.path.join(repo, "internal", "reconcile", "packs")

    if a.cmd == "packcheck":
        rules = load_packs(a.arg)
        print("packcheck: %d rules loaded from %s" % (len(rules), a.arg))
        return 0
    rules = load_packs(packs_dir)
    if a.cmd == "trace":
        result = run_file(a.arg, rules)
        print(json.dumps(result, indent=1, sort_keys=True))
        return 0
    if a.cmd == "corpus":
        files, fails = cmd_corpus(a.arg, rules)
        if fails:
            print("corpus: %d/%d traces FAILED" % (len(fails), len(files)))
            return 1
        print("corpus: all %d traces as expected" % len(files))
        return 0
    if a.cmd == "coverage":
        pct, unc = cmd_coverage(a.arg, packs_dir, a.minimum)
        return 0 if pct >= a.minimum else 1
    if a.cmd == "randgen":
        from . import randgen
        bad = randgen.check(count=a.count, seed=a.seed, rules=rules)
        if bad:
            print("randgen: %d traces raised or were malformed" % len(bad))
            return 1
        print("randgen: %d traces accepted without exception" % a.count)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
