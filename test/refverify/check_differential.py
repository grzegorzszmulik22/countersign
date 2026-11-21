# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""C1.5.2 — differential: every golden bundle must yield the same verdict,
error-code set and warning-code set from refverify as from csverify.

Runs the real csverify binary (built from cmd/csverify with the pinned Go
toolchain when no prebuilt binary exists) and compares the full normalized
result: verdict, world, and the errors/warnings lists as sorted
(code, index, detail) tuples — stronger than the spec's code-set minimum.
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PY = os.path.join(ROOT, ".tools", "python", "bin", "python3")
GO = os.path.join(ROOT, ".tools", "bin", "go")
GOLDENS = os.path.join(ROOT, "test", "vectors", "evidence")
SCRATCH = os.path.join(ROOT, ".check-work")


def norm(res):
    """Normalize a VerifyResult for comparison: findings as sorted tuples
    so map-iteration order inside either implementation cannot matter."""
    def fs(items):
        return sorted((i.get("code"), i.get("index"), i.get("detail"))
                      for i in (items or []))
    return {
        "verdict": res.get("verdict"),
        "world": res.get("world"),
        "errors": fs(res.get("errors")),
        "warnings": fs(res.get("warnings")),
        "stats": res.get("stats"),
    }


def find_csverify():
    for cand in (os.path.join(ROOT, "bin", "csverify"),
                 os.path.join(SCRATCH, "csverify"),
                 os.path.join(ROOT, ".tools", "bin", "csverify")):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    if not os.path.isfile(GO) or not os.access(GO, os.X_OK):
        return None
    os.makedirs(SCRATCH, exist_ok=True)
    out = os.path.join(SCRATCH, "csverify")
    env = {**os.environ, "PATH": os.path.dirname(GO) + ":" + os.environ["PATH"],
           "GOFLAGS": "-mod=mod", "GOCACHE": os.path.join(SCRATCH, "gocache")}
    r = subprocess.run([GO, "build", "-o", out, "./cmd/csverify"],
                       cwd=ROOT, capture_output=True, text=True, env=env)
    if r.returncode != 0 or not os.path.isfile(out):
        print("C1.5.2: csverify build failed:", r.stderr[-300:])
        return None
    return out


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

    fails = 0
    for bundle in goldens:
        base = os.path.splitext(os.path.basename(bundle))[0]
        # Each golden ships its trusted manifest as <name>.keys.json.
        keys = os.path.join(os.path.dirname(bundle), base + ".keys.json")
        if not os.path.isfile(keys):
            keys = os.path.join(GOLDENS, "keys.json")
        karg = ["--keys", keys] if os.path.isfile(keys) else []
        exp = subprocess.run([csverify, bundle] + karg,
                             capture_output=True, text=True)
        gres = subprocess.run([PY, "-m", "refverify", bundle] + karg,
                              capture_output=True, text=True,
                              env={**os.environ,
                                   "PYTHONPATH": os.path.join(ROOT, "ref", "python")})
        try:
            ev = json.loads(exp.stdout)
            gv = json.loads(gres.stdout)
        except json.JSONDecodeError:
            print(f"  {base}: non-JSON output "
                  f"(csverify={exp.stdout[:80]!r} refverify={gres.stdout[:80]!r})")
            fails += 1
            continue
        ne, ng = norm(ev), norm(gv)
        if ne != ng:
            fails += 1
            diffs = [k for k in ne if ne[k] != ng[k]]
            print(f"  {base}: differs in {diffs}")
            for k in diffs:
                print(f"    csverify  {k}: {ne[k]}")
                print(f"    refverify {k}: {ng[k]}")
    if fails:
        print(f"C1.5.2: {fails}/{len(goldens)} bundles differ from csverify")
        return 1
    print(f"C1.5.2: {len(goldens)} golden bundles agree with csverify")
    return 0


if __name__ == "__main__":
    sys.exit(main())
