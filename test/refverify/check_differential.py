# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""C1.5.2 — differential: every golden bundle must yield the same verdict,
error-code set and warning-code set from refverify as from csverify.

BLOCKED on this lane: csverify and the golden bundles of C1.4.3 are produced
by another lane. Exit 3 when they are absent so the check suite reports
BLOCKED rather than PASS. Once both exist on main this runs for real and the
same comparison the spec requires happens here.
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PY = os.path.join(ROOT, ".tools", "python", "bin", "python3")
GOLDENS = os.path.join(ROOT, "test", "vectors", "evidence")


def codes(items):
    """Extract a set of codes from errors/warnings (strings or objects)."""
    out = set()
    for it in items or []:
        out.add(it["code"] if isinstance(it, dict) else it)
    return out


def find_csverify():
    for cand in (os.path.join(ROOT, "bin", "csverify"),
                 os.path.join(ROOT, ".tools", "bin", "csverify")):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def main() -> int:
    csverify = find_csverify()
    goldens = []
    if os.path.isdir(GOLDENS):
        for dirpath, _d, files in os.walk(GOLDENS):
            for f in sorted(files):
                if f.endswith((".tar", ".bundle")) or f.endswith(".tar.gz"):
                    goldens.append(os.path.join(dirpath, f))
    if csverify is None or not goldens:
        print("C1.5.2 BLOCKED: csverify binary or golden bundles absent")
        return 3

    keys = os.path.join(GOLDENS, "keys.json")
    keys_arg = keys if os.path.isfile(keys) else None
    fails = 0
    for bundle in goldens:
        base = os.path.splitext(os.path.basename(bundle))[0]
        exp = subprocess.run([csverify, bundle] + (["--keys", keys_arg] if keys_arg else []),
                             capture_output=True, text=True)
        got = subprocess.run([PY, "-m", "refverify", bundle] +
                             (["--keys", keys_arg] if keys_arg else []),
                             capture_output=True, text=True,
                             env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "ref", "python")})
        try:
            ev = json.loads(exp.stdout)
            gv = json.loads(got.stdout)
        except json.JSONDecodeError:
            print(f"  {base}: non-JSON output (csverify={exp.stdout[:80]!r} refverify={got.stdout[:80]!r})")
            fails += 1
            continue
        diffs = []
        if ev.get("verdict") != gv.get("verdict"):
            diffs.append(f"verdict {gv.get('verdict')} != {ev.get('verdict')}")
        if codes(ev.get("errors")) != codes(gv.get("errors")):
            diffs.append(f"errors {codes(gv.get('errors'))} != {codes(ev.get('errors'))}")
        if codes(ev.get("warnings")) != codes(gv.get("warnings")):
            diffs.append(f"warnings {codes(gv.get('warnings'))} != {codes(ev.get('warnings'))}")
        if diffs:
            fails += 1
            print(f"  {base}: {'; '.join(diffs)}")
    if fails:
        print(f"C1.5.2: {fails}/{len(goldens)} bundles differ from csverify")
        return 1
    print(f"C1.5.2: {len(goldens)} golden bundles agree with csverify")
    return 0


if __name__ == "__main__":
    sys.exit(main())
