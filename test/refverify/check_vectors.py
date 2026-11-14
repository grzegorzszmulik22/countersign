# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""C1.5.5 — run every derived bundle vector through `python3 -m refverify`
and compare verdict + error-code set + warning-code set. Stand-in for the
C1.5.2 golden-bundle differential until the Go lane lands.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "ref", "python"))

import cases  # noqa: E402
import genbundle  # noqa: E402

PY = os.path.join(ROOT, ".tools", "python", "bin", "python3")
REFPY = os.path.join(ROOT, "ref", "python")

OUT_KEYS = {"verdict", "world", "errors", "warnings", "findings", "stats"}


def codes(items):
    out = set()
    for it in items or []:
        out.add(it["code"] if isinstance(it, dict) else it)
    return out


def main() -> int:
    env = {**os.environ, "PYTHONPATH": REFPY}
    fails = 0
    total = 0
    with tempfile.TemporaryDirectory(prefix="refverify-") as tmp:
        for name, verdict, errors, warnings, fn in cases.CASES:
            total += 1
            res = fn(tmp)
            if len(res) == 3:
                _s, files, keys = res
            else:
                _s, files = res
                keys = _s.key_manifest()
            tar = os.path.join(tmp, f"{name}.tar")
            if "__raw__" in files:
                with open(tar, "wb") as f:
                    f.write(files["__raw__"])
            else:
                genbundle.write_tar(files, tar)
            kf = os.path.join(tmp, f"{name}.keys.json")
            genbundle.write_keys(keys, kf)
            p = subprocess.run([PY, "-m", "refverify", tar, "--keys", kf],
                               capture_output=True, text=True, env=env)
            try:
                out = json.loads(p.stdout)
            except json.JSONDecodeError:
                print(f"  {name}: non-JSON output: {p.stdout[:120]!r} "
                      f"stderr={p.stderr[:200]!r}")
                fails += 1
                continue
            bad = []
            if set(out.keys()) != OUT_KEYS:
                bad.append(f"output keys {sorted(out.keys())}")
            if out.get("verdict") != verdict:
                bad.append(f"verdict {out.get('verdict')} != {verdict}")
            ge, gw = codes(out.get("errors")), codes(out.get("warnings"))
            if ge != errors:
                bad.append(f"errors {sorted(ge)} != {sorted(errors)}")
            if gw != warnings:
                bad.append(f"warnings {sorted(gw)} != {sorted(warnings)}")
            exp_rc = 0 if verdict in ("CLEAN", "CLEAN_WITH_DENIALS") else 1
            if p.returncode != exp_rc:
                bad.append(f"exit {p.returncode} != {exp_rc}")
            if bad:
                fails += 1
                print(f"  {name}: {'; '.join(bad)}")
    if fails:
        print(f"C1.5.5: {fails}/{total} vectors failed")
        return 1
    print(f"C1.5.5: {total}/{total} derived vectors match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
