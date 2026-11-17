# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""M1.6 measurement driver (C1.6.3, spec 06 §12).

Builds the corpus (one seeded session → bundle + records file), builds
test/bench/csbench with the pinned Go toolchain, then runs each of
MM1.1–MM1.3 at least 5 times. MM1.4 (mutants detected/generated +
agreement) and MM1.5 (median stored record size) are taken from the
mutations.json written by run_suite.py --out.

Every metric reports: command, machine description (make sysinfo), the
raw samples, median, coefficient of variation, and the spec target. A
metric with CV > 10% is reported unstable (06 §12).

Usage: measure.py --seed 1 --work .check-work/m16 --mutations PATH
Exit: 0 if every target holds, 1 otherwise, 2 on environment failure.
"""
import argparse
import json
import os
import statistics
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(HERE, "..", "refverify"))
sys.path.insert(0, HERE)

import genbundle as G  # noqa: E402
import mutgen  # noqa: E402

PY = os.path.join(ROOT, ".tools", "python", "bin", "python3")
GO = os.path.join(ROOT, ".tools", "bin", "go")
WORK = os.path.join(ROOT, ".check-work", "m16")

TARGETS = {"MM1.1": 8000.0, "MM1.2": 5000.0, "MM1.3": 5.0}
RUNS = 5


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def sysinfo():
    r = sh(["make", "-s", "sysinfo"], cwd=ROOT)
    return r.stdout.strip()


def build_csbench():
    out = os.path.join(WORK, "csbench")
    env = {**os.environ,
           "PATH": os.path.dirname(GO) + ":" + os.environ.get("PATH", ""),
           "GOCACHE": os.path.join(ROOT, ".check-work", "gocache")}
    r = subprocess.run([GO, "build", "-o", out, "./test/bench"],
                       cwd=ROOT, capture_output=True, text=True, env=env)
    if r.returncode != 0:
        print("csbench build failed:", r.stderr[-400:], file=sys.stderr)
        return None
    return out


def corpus(seed):
    """One seeded session → (bundle.tar path, keys.json, records.jsonl)."""
    s, files, keys = mutgen.session(seed, n_records=2000)
    os.makedirs(WORK, exist_ok=True)
    bp = os.path.join(WORK, "bench-bundle.tar")
    import io
    import tarfile
    with tarfile.open(bp, "w") as tf:
        for n in sorted(files):
            d = files[n]
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            ti.mtime = 0
            tf.addfile(ti, io.BytesIO(d))
    kp = os.path.join(WORK, "bench-keys.json")
    with open(kp, "wb") as f:
        f.write(G.jdumps(keys))
    # Append corpus: decodable record lines; seals dropped so no mid-run
    # checkpoint fires (cpInterval would also inject a signing cost).
    rp = os.path.join(WORK, "bench-records.jsonl")
    with open(rp, "wb") as f:
        for l in s.lines:
            if b'"session.seal"' not in l and b'"emitter.seal"' not in l \
                    and b'"commit.closed"' not in l:
                f.write(l + b"\n")
    return bp, kp, rp


def samples_from(out):
    return [json.loads(l) for l in out.splitlines() if l.strip()]


def summarize(samples, field, target=None, lower_better=False):
    vals = [float(s[field]) for s in samples]
    med = statistics.median(vals)
    mean = statistics.fmean(vals)
    cv = (statistics.stdev(vals) / mean) if len(vals) > 1 and mean else 0.0
    ok = True
    if target is not None:
        ok = (med <= target) if lower_better else (med >= target)
    return {"samples": vals, "runs": len(vals), "median": med,
            "cv": round(cv, 4), "unstable": cv > 0.10,
            "target": target, "pass": ok}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--mutations", default=None,
                    help="mutations.json from run_suite.py --out")
    ap.add_argument("--runs", type=int, default=RUNS)
    args = ap.parse_args()

    bench = build_csbench()
    if bench is None:
        print("C1.6.3: cannot build csbench", file=sys.stderr)
        return 2
    bp, kp, rp = corpus(args.seed)
    machine = sysinfo()
    results = {"machine": machine, "seed": args.seed, "metrics": {}}
    fails = []

    def run(metric, cmd, field, target, lower=False):
        r = sh(cmd)
        if r.returncode != 0:
            fails.append(f"{metric}: bench failed: {r.stderr[-200:]}")
            return
        ss = samples_from(r.stdout)
        res = summarize(ss, field, target, lower)
        res["command"] = " ".join(cmd)
        results["metrics"][metric] = res
        status = "PASS" if res["pass"] else "FAIL"
        if res["unstable"]:
            status += " (unstable cv=%.2f)" % res["cv"]
        print(f"{metric}: median {res['median']:.1f} target {target} "
              f"{status} samples={[round(v,1) for v in res['samples']]}")
        if not res["pass"]:
            fails.append(f"{metric}: median {res['median']:.1f} missed "
                         f"target {target}")

    run("MM1.1", [bench, "verify", bp, kp, str(args.runs)],
        "records_per_s", TARGETS["MM1.1"])
    run("MM1.2", [bench, "append", os.path.join(WORK, "ledger-a"),
                  rp, "40000", "32", str(args.runs)],
        "records_per_s", TARGETS["MM1.2"])
    # csbench latency emits one sample per invocation; spec requires >=5.
    ss = []
    for i in range(args.runs):
        r = sh([bench, "latency", os.path.join(WORK, "ledger-b"),
                rp, "1000", "20000", "8"])
        if r.returncode != 0:
            fails.append(f"MM1.3 run {i}: bench failed: {r.stderr[-200:]}")
            break
        ss += samples_from(r.stdout)
    if ss:
        res = summarize(ss, "p99_ms", TARGETS["MM1.3"], lower_better=True)
        res["command"] = (f"{bench} latency {WORK}/ledger-b {rp} "
                          "1000 20000 8  (x%d)" % len(ss))
        res["all_fields"] = [
            {"p50_ms": s["p50_ms"], "p99_ms": s["p99_ms"],
             "max_ms": s["max_ms"]} for s in ss]
        results["metrics"]["MM1.3"] = res
        status = "PASS" if res["pass"] else "FAIL"
        if res["unstable"]:
            status += " (unstable cv=%.2f)" % res["cv"]
        print(f"MM1.3: median {res['median']:.1f} target {TARGETS['MM1.3']} "
              f"{status} samples={[round(v,1) for v in res['samples']]}")
        if not res["pass"]:
            fails.append(f"MM1.3: median {res['median']:.1f} missed "
                         f"target {TARGETS['MM1.3']}")

    if args.mutations and os.path.isfile(args.mutations):
        m = json.load(open(args.mutations))
        mm = m.get("measurements", {})
        results["metrics"]["MM1.4"] = {
            "command": "run_suite.py --seed %d" % m.get("seed", -1),
            "mutants_detected": mm.get("MM1.4", {}).get("mutants_detected"),
            "mutants_generated": mm.get("MM1.4", {}).get("mutants_generated"),
            "agreement": mm.get("MM1.4", {}).get("agreement"),
            "detected_ratio": mm.get("MM1.4", {}).get("detected_ratio"),
            "agreement_ratio": mm.get("MM1.4", {}).get("agreement_ratio"),
            "target": "100% / >=1000; 100%",
            "pass": (mm.get("MM1.4", {}).get("detected_ratio") == 1.0 and
                     mm.get("MM1.4", {}).get("mutants_generated", 0) >= 1000
                     and mm.get("MM1.4", {}).get("agreement_ratio") == 1.0),
        }
        results["metrics"]["MM1.5"] = {
            "command": "run_suite.py --seed %d" % m.get("seed", -1),
            "median_record_size_bytes": mm.get("MM1.5", {}).get(
                "median_record_size_bytes"),
            "samples": mm.get("MM1.5", {}).get("samples"),
            "target": "reported",
            "pass": True,
        }
        for x in ("MM1.4", "MM1.5"):
            r = results["metrics"][x]
            print(f"{x}: {r}")
            if not r["pass"]:
                fails.append(f"{x}: target missed")
    else:
        fails.append("MM1.4/MM1.5: mutations.json not provided")

    outp = os.path.join(WORK, "measurements.json")
    with open(outp, "w") as f:
        json.dump(results, f, indent=2)
    print(f"measurements → {outp}")
    if fails:
        for x in fails:
            print("  FAIL", x)
        print("C1.6.3: FAIL")
        return 1
    print("C1.6.3: all measurement targets met")
    return 0


if __name__ == "__main__":
    sys.exit(main())
