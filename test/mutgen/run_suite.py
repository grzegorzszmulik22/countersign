# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""M1.6 mutation suite driver (spec 03 §11, milestone M1.6).

C1.6.1 — N clean seeded bundles; both verifiers must return a CLEAN-class
verdict (CLEAN or CLEAN_WITH_DENIALS) and agree.
C1.6.2 — ≥1000 mutants, ≥100 per class, fixed seed: both verifiers reject
each one; verdict and error/warning code sets identical between the two;
the FIRST error is in the §11 expected set; class 5 never yields CLEAN*.
A mutant byte-identical to its original is a hard failure (catches a
no-op mutator).

Verification jobs are pure functions of the seed, so they run on a worker
pool without affecting results. Emits MM1.4/MM1.5 inputs in
mutations.json and per-check booleans in status.json.

Usage: run_suite.py --seed 1 --bundles 200 --per-class 112 [--out DIR]
Exit: 0 pass, 1 check failure, 2 usage/env error.
"""
import argparse
import copy
import io
import json
import os
import random
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
EXTRA_TRIES = 20
GAP_TRIES = 10


def first_err(res):
    return res["errors"][0]["code"] if res.get("errors") else None


def in_expected(cls, res):
    """First error in the §11 expected set; class 5 also accepts an
    UNSEALED verdict (no error at all)."""
    fe = first_err(res)
    if fe is not None:
        return fe in EXPECTED[cls]
    return cls == 5 and res.get("verdict") == "UNSEALED"


def code_set(res, key):
    return {i.get("code") for i in (res.get(key) or [])}


def norm(res):
    def fs(items):
        return sorted((i.get("code"), i.get("index"), i.get("detail"))
                      for i in (items or []))
    return {"verdict": res.get("verdict"),
            "world": res.get("world"),
            "errors": fs(res.get("errors")),
            "warnings": fs(res.get("warnings")),
            "stats": res.get("stats")}


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


# ------------------------------------------------------------- workers
# Everything below runs inside worker processes; each job's inputs are
# seeds, so results do not depend on scheduling order.

_GOBIN = None
_RV = None
_RK = None


def _init(gobin):
    global _GOBIN, _RV, _RK
    _GOBIN = gobin
    sys.path.insert(0, os.path.join(HERE, "..", "refverify"))
    sys.path.insert(0, os.path.join(ROOT, "ref", "python"))
    sys.path.insert(0, HERE)
    from refverify import verify as _rv, keys as _rk  # noqa: E401
    globals()["_RV"], globals()["_RK"] = _rv, _rk


def _go_verify(tar_bytes, keys_bytes):
    with tempfile.TemporaryDirectory() as td:
        tp = os.path.join(td, "b.tar")
        kp = os.path.join(td, "b.keys.json")
        with open(tp, "wb") as f:
            f.write(tar_bytes)
        with open(kp, "wb") as f:
            f.write(keys_bytes)
        p = subprocess.run([_GOBIN, tp, "--keys", kp],
                           capture_output=True, text=True)
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        return {"verdict": "NONJSON", "raw": p.stdout[:200]}


def _py_verify(tar_bytes, keys_bytes):
    man = _RK.unmarshal_manifest(keys_bytes)
    return _RV.verify_bundle(tar_bytes, man)


def _both(files, keys):
    tar = pack_tar(files)
    kj = G.jdumps(keys)
    return _go_verify(tar, kj), _py_verify(tar, kj)


def job_clean(spec):
    """("clean", i) → generated bundle verified by both."""
    _tag, i, seed = spec
    s, files, keys = mutgen.session(seed * 100000 + i)
    gv, pv = _both(files, keys)
    return {"i": i, "gv": gv, "pv": pv,
            "sizes": [len(l) for l in s.lines]}


def job_mutant(spec):
    """("mut", cls, seq, seed, donor_lines) → mutate + verify."""
    _tag, cls, seq, seed, donor_lines = spec
    s, files, keys = mutgen.session(seed * 200000 + seq % 48)
    rng = random.Random(seed * 300000 + seq)
    mfiles = copy.deepcopy(files)
    mkeys = copy.deepcopy(keys)
    if cls == 6:
        donor = donorspace(donor_lines, rng)
        mfiles, mkeys = M.MUTATORS[cls](s, mfiles, mkeys, rng, donor)
    else:
        mfiles, mkeys = M.MUTATORS[cls](s, mfiles, mkeys, rng)
    changed = not (mfiles == files and mkeys == keys)
    gv, pv = _both(mfiles, mkeys)
    return {"cls": cls, "seq": seq, "changed": changed,
            "gv": gv, "pv": pv}


def job_extra(spec):
    """("extra", name, seq, seed) → directed-extra mutate + verify."""
    _tag, name, seq, seed = spec
    s, files, keys = mutgen.session(seed * 200000 + seq % 48)
    rng = random.Random(seed * 500000 + seq)
    mfiles = copy.deepcopy(files)
    mkeys = copy.deepcopy(keys)
    mfiles, mkeys = M.MUTATORS[name](s, mfiles, mkeys, rng)
    changed = not (mfiles == files and mkeys == keys)
    gv, pv = _both(mfiles, mkeys)
    return {"name": name, "seq": seq, "changed": changed,
            "gv": gv, "pv": pv}


def donorspace(lines_list, rng):
    """A stand-in session object carrying foreign record lines."""
    class _D:
        pass
    d = _D()
    d.lines = lines_list
    return d


def run_jobs(gobin, jobs, fn, workers):
    if workers <= 1:
        _init(gobin)
        for j in jobs:
            yield fn(j)
        return
    import multiprocessing as mp
    with mp.Pool(workers, initializer=_init, initargs=(gobin,)) as pool:
        yield from pool.imap_unordered(fn, jobs, chunksize=1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--bundles", type=int, default=200)
    ap.add_argument("--per-class", type=int, default=112)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    seed = args.seed

    gobin = csverify_bin()
    if gobin is None:
        print("C1.6: csverify unavailable", file=sys.stderr)
        return 2

    fails = []
    t0 = time.time()

    # ---------------- C1.6.1: clean seeded bundles --------------------
    clean_ok = 0
    record_sizes = []
    donor_lines = []
    jobs = [("clean", i, seed) for i in range(args.bundles)]
    for r in run_jobs(gobin, jobs, job_clean, args.workers):
        gv, pv = r["gv"], r["pv"]
        record_sizes += r["sizes"]
        if gv["verdict"] not in CLEAN_CLASS or pv["verdict"] not in \
                CLEAN_CLASS:
            fails.append(
                f"clean bundle {r['i']}: verdicts go={gv['verdict']} "
                f"py={pv['verdict']}")
        elif norm(gv) != norm(pv):
            fails.append(f"clean bundle {r['i']}: outputs differ")
        else:
            clean_ok += 1
    print(f"C1.6.1: {clean_ok}/{args.bundles} generated bundles "
          f"CLEAN-class in both verifiers", flush=True)

    # Donor record lines for class 6 (a foreign genuine record).
    ds, _df, _dk = mutgen.session(seed * 400000)
    donor_lines = ds.lines

    # ---------------- C1.6.2: mutants --------------------------------
    per_class = {c: 0 for c in M.CLASSES}
    detected = agreed = total = 0
    clean_mutants = []
    class5_clean = []
    jobs = []
    seq = 0
    for cls in M.CLASSES:
        for _ in range(args.per_class):
            jobs.append(("mut", cls, seq, seed, donor_lines))
            seq += 1
    done_ct = 0
    for r in run_jobs(gobin, jobs, job_mutant, args.workers):
        done_ct += 1
        if done_ct % 100 == 0:
            print(f"  …{done_ct}/{len(jobs)} mutants", flush=True)
        cls = r["cls"]
        total += 1
        per_class[cls] += 1
        gv, pv = r["gv"], r["pv"]
        if not r["changed"]:
            fails.append(f"class {cls} mutant {r['seq']}: "
                         f"mutant identical to original (no-op mutator)")
            continue
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
          f"{agreed} identical error classes", flush=True)

    # Directed extras — agreement + rejection required; the expected code
    # must be the first error where V-order makes that meaningful
    # (policy/contract digests at V8), present anywhere for the
    # result-before-effect structure rule (a position swap always cascades
    # E_CHAIN/E_INCLUSION first).
    extras_report = {}
    jobs = []
    for name in ("policy", "contract", "result-before-effect"):
        for k in range(EXTRA_TRIES):
            jobs.append(("extra", name, k, seed))
    for r in run_jobs(gobin, jobs, job_extra, args.workers):
        name = r["name"]
        gv, pv = r["gv"], r["pv"]
        if not r["changed"]:
            fails.append(f"extra {name}: no-op mutant")
            continue
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
    # keys.json divergence: documented gap — csverify never reads the
    # bundled copy, so both verifiers accept; only agreement asserted.
    jobs = [("extra", "keys-json-differs", k, seed)
            for k in range(GAP_TRIES)]
    for r in run_jobs(gobin, jobs, job_extra, args.workers):
        gv, pv = r["gv"], r["pv"]
        if norm(gv) != norm(pv):
            fails.append("extra keys-json-differs: verifiers disagree")
    print(f"directed extras: agreement {extras_report} (+keys-json gap)",
          flush=True)

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
            json.dump({"seed": seed, "clean": clean_ok,
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
