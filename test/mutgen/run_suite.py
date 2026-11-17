# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""M1.6 mutation suite driver (spec 03 §11, milestone M1.6).

C1.6.1 — N clean seeded bundles; both verifiers must return a CLEAN-class
verdict (CLEAN or CLEAN_WITH_DENIALS) and agree.
C1.6.2 — ≥1000 mutants, ≥100 per class, fixed seed: both verifiers reject
each one; verdict and error/warning code sets identical between the two;
class 5 never yields CLEAN*. A mutant that equals its original input is
a hard failure (catches a no-op mutator).
Also emits the MM1.4 and MM1.5 inputs: mutants detected/generated and the
median stored record size across the generated corpus.

Usage: run_suite.py --seed 1 --bundles 200 --per-class 112 [--out DIR]
Exit: 0 pass, 1 check failure, 2 usage/env error.
"""
import argparse
import copy
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(HERE, "..", "refverify"))
sys.path.insert(0, os.path.join(ROOT, "ref", "python"))
sys.path.insert(0, HERE)

import genbundle as G  # noqa: E402
import mutgen  # noqa: E402
import mutate as M  # noqa: E402

from refverify import verify as _refverify  # noqa: E402
from refverify import keys as _refkeys  # noqa: E402

PY = os.path.join(ROOT, ".tools", "python", "bin", "python3")
GO = os.path.join(ROOT, ".tools", "bin", "go")
SCRATCH = os.path.join(ROOT, ".check-work")

CLEAN_CLASS = {"CLEAN", "CLEAN_WITH_DENIALS"}

# Spec 03 §11 expected error classes per mutation class. A mutant counts
# as detected only when the FIRST emitted error (in V-order — the primary
# rejection) is in the expected set; a rejection for any other primary
# reason is a suite failure, not a detection. Downstream cascade codes
# (E_CHAIN/E_INCLUSION/E_SEAL follow any content change) are recorded but
# do not satisfy detection.
EXPECTED = {
    1: {"E_SIG"},
    2: {"E_SIG"},
    3: {"E_CHAIN", "E_INCLUSION"},
    4: {"E_CHAIN", "E_INCLUSION"},
    5: {"E_SEAL", "E_INCLUSION"},  # or verdict UNSEALED
    6: {"E_SESSION", "E_CHAIN"},
    7: {"E_KEY"},
    8: {"E_CHECKPOINT", "E_INCLUSION"},
    9: {"E_CHAIN"},
}
EXTRA_EXPECTED = {
    "policy": {"E_POLICY"},
    "contract": {"E_POLICY"},
    "result-before-effect": {"E_STRUCTURE"},
    "keys-json-differs": {"E_KEY"},
}


def first_err(res):
    return res["errors"][0]["code"] if res.get("errors") else None


def in_expected(cls, res):
    """First error in the §11 expected set; class 5 also accepts an
    UNSEALED verdict (no error at all)."""
    fe = first_err(res)
    if fe is not None:
        return fe in EXPECTED[cls]
    return cls == 5 and res.get("verdict") == "UNSEALED"


def pack_tar(files):
    """Deterministic tar identical in layout to the golden bundles."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name in sorted(files):
            data = files[name]
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = 0
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def csverify_bin():
    for cand in (os.path.join(ROOT, "bin", "csverify"),
                 os.path.join(SCRATCH, "csverify"),
                 os.path.join(ROOT, ".tools", "bin", "csverify")):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    os.makedirs(SCRATCH, exist_ok=True)
    out = os.path.join(SCRATCH, "csverify")
    env = {**os.environ, "PATH": os.path.dirname(GO) + ":" +
           os.environ.get("PATH", ""),
           "GOCACHE": os.path.join(SCRATCH, "gocache")}
    r = subprocess.run([GO, "build", "-o", out, "./cmd/csverify"],
                       cwd=ROOT, capture_output=True, text=True, env=env)
    if r.returncode != 0:
        print("csverify build failed:", r.stderr[-300:], file=sys.stderr)
        return None
    return out


class Go:
    """csverify subprocess wrapper."""

    def __init__(self, path):
        self.path = path

    def verify(self, tar_path, keys_path):
        p = subprocess.run([self.path, tar_path, "--keys", keys_path],
                           capture_output=True, text=True)
        try:
            return json.loads(p.stdout)
        except json.JSONDecodeError:
            return {"verdict": "NONJSON", "raw": p.stdout[:200]}


class Py:
    """In-process refverify."""

    def verify(self, tar_bytes, keys_bytes):
        man = _refkeys.unmarshal_manifest(keys_bytes)
        return _refverify.verify_bundle(tar_bytes, man)


def norm(res):
    def fs(items):
        return sorted((i.get("code"), i.get("index"), i.get("detail"))
                      for i in (items or []))
    return {"verdict": res.get("verdict"),
            "world": res.get("world"),
            "errors": fs(res.get("errors")),
            "warnings": fs(res.get("warnings")),
            "stats": res.get("stats")}


def code_set(res, key):
    return {i.get("code") for i in (res.get(key) or [])}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--bundles", type=int, default=200)
    ap.add_argument("--per-class", type=int, default=112)
    ap.add_argument("--pool", type=int, default=40,
                    help="base bundles reused as mutant parents")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    go = csverify_bin()
    if go is None:
        print("C1.6: csverify unavailable", file=sys.stderr)
        return 2
    go = Go(go)
    py = Py()

    fails = []
    t0 = time.time()

    # ---------------- C1.6.1: clean seeded bundles --------------------
    clean_ok = 0
    record_sizes = []
    donors = []  # keep a few sessions for class-6 donor records
    for i in range(args.bundles):
        s, files, keys = mutgen.session(args.seed * 100000 + i)
        tar = pack_tar(files)
        keys_j = G.jdumps(keys)
        record_sizes += [len(l) for l in s.lines]
        with tempfile.TemporaryDirectory() as td:
            tp = os.path.join(td, "b.tar")
            kp = os.path.join(td, "b.keys.json")
            open(tp, "wb").write(tar)
            open(kp, "wb").write(keys_j)
            gv = go.verify(tp, kp)
        pv = py.verify(tar, keys_j)
        if gv["verdict"] not in CLEAN_CLASS or pv["verdict"] not in CLEAN_CLASS:
            fails.append(
                f"clean bundle {i}: verdicts go={gv['verdict']} "
                f"py={pv['verdict']}")
        elif norm(gv) != norm(pv):
            fails.append(f"clean bundle {i}: outputs differ")
        else:
            clean_ok += 1
        if len(donors) < 8:
            donors.append(s)
    print(f"C1.6.1: {clean_ok}/{args.bundles} generated bundles "
          f"CLEAN-class in both verifiers")

    # ---------------- C1.6.2: mutants --------------------------------
    rng = __import__("random").Random(args.seed)
    pool = [mutgen.session(args.seed * 200000 + i) for i in range(args.pool)]
    per_class = {c: 0 for c in M.CLASSES}
    detected = agreed = total = 0
    clean_mutants = []
    class5_clean = []
    extras_report = {}
    seq = 0
    while any(per_class[c] < args.per_class for c in M.CLASSES):
        cls = M.CLASSES[seq % len(M.CLASSES)]
        seq += 1
        if per_class[cls] >= args.per_class:
            continue
        per_class[cls] += 1
        total += 1
        s, files, keys = pool[rng.randrange(len(pool))]
        mfiles = copy.deepcopy(files)
        mkeys = copy.deepcopy(keys)
        donor = None
        if cls == 6:
            donor = donors[rng.randrange(len(donors))]
            mfiles, mkeys = M.MUTATORS[cls](
                s, mfiles, mkeys, rng, donor)
        else:
            mfiles, mkeys = M.MUTATORS[cls](s, mfiles, mkeys, rng)
        if mfiles == files and mkeys == keys:
            fails.append(f"class {cls} mutant {per_class[cls]}: "
                         f"mutant identical to original (no-op mutator)")
            continue
        tar = pack_tar(mfiles)
        keys_j = G.jdumps(mkeys)
        with tempfile.TemporaryDirectory() as td:
            tp = os.path.join(td, "m.tar")
            kp = os.path.join(td, "m.keys.json")
            open(tp, "wb").write(tar)
            open(kp, "wb").write(keys_j)
            gv = go.verify(tp, kp)
        pv = py.verify(tar, keys_j)
        agree = (gv["verdict"] == pv["verdict"] and
                 code_set(gv, "errors") == code_set(pv, "errors") and
                 code_set(gv, "warnings") == code_set(pv, "warnings"))
        if gv["verdict"] in CLEAN_CLASS or pv["verdict"] in CLEAN_CLASS:
            clean_mutants.append(
                f"class {cls} #{per_class[cls]}: go={gv['verdict']} "
                f"py={pv['verdict']}")
            if cls == 5:
                class5_clean.append(per_class[cls])
        elif agree and in_expected(cls, gv) and in_expected(cls, pv):
            detected += 1
        elif not in_expected(cls, gv) or not in_expected(cls, pv):
            fails.append(
                f"class {cls} #{per_class[cls]}: first error out of "
                f"expected {sorted(EXPECTED[cls])}: "
                f"go={first_err(gv)} py={first_err(pv)}")
        if agree:
            agreed += 1
        else:
            fails.append(
                f"class {cls} #{per_class[cls]}: disagree "
                f"go={{v:{gv['verdict']},e:{sorted(code_set(gv,'errors'))}}} "
                f"py={{v:{pv['verdict']},e:{sorted(code_set(pv,'errors'))}}}")
    print(f"C1.6.2: {total} mutants, {detected} rejected by both, "
          f"{agreed} identical error classes")

    # Directed extras — agreement + rejection required; the expected code
    # must be the first error where V-order makes that meaningful
    # (policy/contract digests at V8), present anywhere for the
    # result-before-effect structure rule (a position swap always cascades
    # E_CHAIN/E_INCLUSION first).
    extras_seq = 0
    for name in ("policy", "contract", "result-before-effect"):
        for _ in range(20):
            extras_seq += 1
            s, files, keys = pool[rng.randrange(len(pool))]
            mfiles = copy.deepcopy(files)
            mkeys = copy.deepcopy(keys)
            mfiles, mkeys = M.MUTATORS[name](s, mfiles, mkeys, rng)
            if mfiles == files and mkeys == keys:
                fails.append(f"extra {name}: no-op mutant")
                continue
            tar = pack_tar(mfiles)
            keys_j = G.jdumps(mkeys)
            with tempfile.TemporaryDirectory() as td:
                tp = os.path.join(td, "m.tar")
                kp = os.path.join(td, "m.keys.json")
                open(tp, "wb").write(tar)
                open(kp, "wb").write(keys_j)
                gv = go.verify(tp, kp)
            pv = py.verify(tar, keys_j)
            agree = (gv["verdict"] == pv["verdict"] and
                     code_set(gv, "errors") == code_set(pv, "errors") and
                     code_set(gv, "warnings") == code_set(pv, "warnings"))
            rejected = gv["verdict"] not in CLEAN_CLASS and \
                pv["verdict"] not in CLEAN_CLASS
            if name == "result-before-effect":
                exp_ok = "E_STRUCTURE" in code_set(gv, "errors") and \
                    "E_STRUCTURE" in code_set(pv, "errors")
            else:
                exp_ok = first_err(gv) in EXTRA_EXPECTED.get(
                    name, set()) and first_err(pv) in EXTRA_EXPECTED.get(
                    name, set())
            extras_report[name] = extras_report.get(name, 0) + int(agree)
            if not agree or not rejected or not exp_ok:
                fails.append(
                    f"extra {name}: agree={agree} rejected={rejected} "
                    f"expected_ok={exp_ok} "
                    f"go={gv['verdict']} py={pv['verdict']}")
    # keys.json divergence: documented gap — only agreement asserted.
    for _ in range(10):
        s, files, keys = pool[rng.randrange(len(pool))]
        mfiles = copy.deepcopy(files)
        mkeys = copy.deepcopy(keys)
        mfiles, mkeys = M.MUTATORS["keys-json-differs"](
            s, mfiles, mkeys, rng)
        tar = pack_tar(mfiles)
        keys_j = G.jdumps(mkeys)
        with tempfile.TemporaryDirectory() as td:
            tp = os.path.join(td, "m.tar")
            kp = os.path.join(td, "m.keys.json")
            open(tp, "wb").write(tar)
            open(kp, "wb").write(keys_j)
            gv = go.verify(tp, kp)
        pv = py.verify(tar, keys_j)
        if norm(gv) != norm(pv):
            fails.append("extra keys-json-differs: verifiers disagree")
    print(f"directed extras: agreement {extras_report} (+keys-json gap)")

    # ---------------- MM1.4 / MM1.5 ----------------------------------
    record_sizes.sort()
    median = record_sizes[len(record_sizes) // 2] if record_sizes else 0
    mm = {
        "MM1.4": {"mutants_detected": detected, "mutants_generated": total,
                  "agreement": agreed,
                  "detected_ratio": detected / total if total else 0,
                  "agreement_ratio": agreed / total if total else 0},
        "MM1.5": {"median_record_size_bytes": median,
                  "samples": len(record_sizes)},
    }
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        status = {
            "C1.6.1": clean_ok == args.bundles,
            "C1.6.2": (detected == total and agreed == total and
                       total >= 1000 and not class5_clean and
                       all(per_class[c] >= 100 for c in M.CLASSES) and
                       not fails),
        }
        with open(os.path.join(args.out, "status.json"), "w") as f:
            json.dump(status, f)
        with open(os.path.join(args.out, "mutations.json"), "w") as f:
            json.dump({"seed": args.seed, "clean": clean_ok,
                       "bundles": args.bundles,
                       "mutants": total, "detected": detected,
                       "agreed": agreed, "per_class": per_class,
                       "elapsed_s": round(time.time() - t0, 1),
                       "measurements": mm}, f, indent=2)
        with open(os.path.join(args.out, "record-sizes.txt"), "w") as f:
            f.write("\n".join(str(x) for x in record_sizes))
    for x in fails[:40]:
        print("  FAIL", x)
    if clean_ok != args.bundles:
        fails.append(f"clean bundles {clean_ok}/{args.bundles}")
    if detected != total:
        fails.append(f"undetected mutants: {total - detected} "
                     f"(e.g. {clean_mutants[:5]})")
    if class5_clean:
        fails.append(f"class 5 CLEAN* mutants: {len(class5_clean)}")
    if agreed != total:
        fails.append(f"verifier disagreement on {total - agreed} mutants")
    if fails:
        print(f"C1.6: {len(fails)} failure(s)")
        return 1
    print(f"C1.6: pass — {clean_ok} clean, {total} mutants detected and "
          f"agreed, median record {median} B")
    return 0


if __name__ == "__main__":
    sys.exit(main())
