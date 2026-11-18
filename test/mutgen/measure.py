# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""M1.6 measurement driver (C1.6.3, spec 06 §12, targets restated by CR-002).

Builds the corpus (one seeded session → bundle + records file), builds
test/bench/csbench with the pinned Go toolchain, then runs:

- MM1.1  records per CPU-second of one core (GOMAXPROCS=1, user+sys),
         judged >= 50% of the raw Ed25519 verify rate calibrated in the
         same run. Sanity: a record pipeline can never outrun the raw
         verify it contains, so records_per_cpu_s > calibration is a
         harness defect, not a pass.
- MM1.2  records per CPU-second of the writer >= 5,000, and group
         commits (fsync events, counted from append-return cohorts)
         <= 1 per 10 records.
- MM1.3  append p99 <= 5 ms at 1,000/s, judged only on runs whose
         per-second 1-minute load samples all stayed <= core count;
         every run is recorded. If none qualifies the result is
         "not judged: host contended" — allowed by CR-002, open for G1.
- MM1.4/MM1.5  from run_suite.py's mutations.json.

Every metric reports: command, machine description (make sysinfo), the
raw samples, median, coefficient of variation, and the spec target. A
metric with CV > 10% is reported unstable (06 §12). Never the best run,
never a dropped run.

Usage: measure.py --seed 1 --mutations PATH
Exit: 0 if every judged target holds, 1 otherwise, 2 on environment failure.
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
CORES = os.cpu_count() or 1

MM12_RATE = 5000.0        # records per CPU-second of the writer
MM12_FSYNC = 0.10         # group commits per record
MM13_P99 = 5.0            # ms
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


def summarize(vals, target=None, lower_better=False):
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
    results = {"machine": machine, "seed": args.seed, "cores": CORES,
                   "metrics": {}}
    fails = []

    # ------------------------- MM1.1 ----------------------------------
    cmd = [bench, "verify", bp, kp, str(args.runs)]
    r = sh(cmd)
    if r.returncode != 0:
        fails.append(f"MM1.1: bench failed: {r.stderr[-200:]}")
        mm1_samples = []
        cal = None
    else:
        out = samples_from(r.stdout)
        cal_rows = [s for s in out if s.get("metric") == "calibration"]
        run_rows = [s for s in out if s.get("metric") == "MM1.1"]
        cal = cal_rows[-1]["ed25519_verify_per_cpu_s"] if cal_rows else None
        mm1_samples = [s["records_per_cpu_s"] for s in run_rows]
        wall = [s["records_per_s"] for s in run_rows]
        load = {f"run{s['run']}": s.get("load1_samples")
                for s in run_rows}
    if cal is not None and mm1_samples:
        res = summarize(mm1_samples, target=0.5 * cal)
        res.update({"command": " ".join(cmd),
                    "calibration_ed25519_per_cpu_s": cal,
                    "ratio_to_calibration": round(
                        res["median"] / cal, 4),
                    "wall_records_per_s": wall,
                    "load1_samples": load,
                    "target_text": ">= 50% of same-core Ed25519 rate "
                                   f"({cal:.0f} ops/cpu-s)"})
        results["metrics"]["MM1.1"] = res
        status = "PASS" if res["pass"] else "FAIL"
        print(f"MM1.1: median {res['median']:.0f} rec/cpu-s, "
              f"cal {cal:.0f} ops/cpu-s, ratio {res['median']/cal:.2f} "
              f"{status}")
        if not res["pass"]:
            fails.append("MM1.1: ratio below 50% of calibration")
        bad = [v for v in mm1_samples if v > cal * 1.01]
        if bad:
            fails.append(f"MM1.1: harness impossible — verify rate "
                         f"{max(bad):.0f} > ed25519 calibration {cal:.0f}")
    else:
        fails.append("MM1.1: no calibration/runs emitted")

    # ------------------------- MM1.2 ----------------------------------
    cmd = [bench, "append", os.path.join(WORK, "ledger-a"),
           rp, "40000", "32", str(args.runs)]
    r = sh(cmd)
    run_rows = ([s for s in samples_from(r.stdout)
                 if s.get("metric") == "MM1.2"]
                if r.returncode == 0 else [])
    if r.returncode != 0 or not run_rows:
        fails.append(f"MM1.2: bench failed: {r.stderr[-200:]}")
    else:
        rates = [s["records_per_cpu_s"] for s in run_rows]
        wall = [s["records_per_s"] for s in run_rows]
        fpr = [s["fsync_per_record"] for s in run_rows]
        commits = [s["fsync_commits"] for s in run_rows]
        for i, s in enumerate(run_rows):
            if not (1 <= s["fsync_commits"] <= s["records"]):
                fails.append(f"MM1.2 run {i}: impossible fsync_commits "
                             f"{s['fsync_commits']} for {s['records']} "
                             "records")
        res = summarize(rates, target=MM12_RATE)
        fres = summarize(fpr, target=MM12_FSYNC, lower_better=True)
        res.update({"command": " ".join(cmd),
                    "wall_records_per_s": wall,
                    "fsync_commits_samples": commits,
                    "fsync_per_record": fres,
                    "median_commit_gap_ms": [
                        s.get("median_commit_gap_ms") for s in run_rows],
                    "load1_samples": {f"run{s['run']}": s.get(
                        "load1_samples") for s in run_rows},
                    "target_text": ">= 5000 rec/cpu-s and <= 1 fsync "
                                   "(group commit) per 10 records",
                    "fsync_note": "each group commit syncs the entries, "
                                  "hashes and session index files"})
        res["pass"] = res["pass"] and fres["median"] <= MM12_FSYNC
        results["metrics"]["MM1.2"] = res
        status = "PASS" if res["pass"] else "FAIL"
        print(f"MM1.2: median {res['median']:.0f} rec/cpu-s, fsync/rec "
              f"{fres['median']:.3f} {status}")
        if not res["pass"]:
            fails.append(f"MM1.2: rate {res['median']:.0f} or fsync ratio "
                         f"{fres['median']:.3f} missed target")

    # ------------------------- MM1.3 ----------------------------------
    # One csbench invocation per run (each carries its own per-second
    # load1 samples). A run qualifies for judgment only when every sample
    # stayed <= cores; runs without samples cannot be classified and are
    # a harness integrity failure, not a disqualification.
    lat_rows = []
    for i in range(args.runs):
        cmd = [bench, "latency", os.path.join(WORK, "ledger-b"),
               rp, "1000", "20000", "8"]
        r = sh(cmd)
        if r.returncode != 0:
            fails.append(f"MM1.3 run {i}: bench failed: {r.stderr[-200:]}")
            break
        lat_rows += [s for s in samples_from(r.stdout)
                     if s.get("metric") == "MM1.3"]
    qualified, unqualified, missing = [], [], []
    for i, s in enumerate(lat_rows):
        ls = s.get("load1_samples")
        if not ls:
            missing.append(i)
        elif max(ls) <= CORES:
            qualified.append(s)
        else:
            unqualified.append(s)
    if missing:
        fails.append(f"MM1.3: runs without load1 samples: {missing} "
                     "(harness cannot classify them)")
    judged = qualified
    if lat_rows:
        res = {
            "command": f"{bench} latency {WORK}/ledger-b {rp} 1000 20000 8 "
                       f"(x{len(lat_rows)})",
            "cores": CORES,
            "runs": len(lat_rows),
            "qualified_runs": len(qualified),
            "all_samples": [{
                "p50_ms": s["p50_ms"], "p99_ms": s["p99_ms"],
                "max_ms": s["max_ms"],
                "load1_max": s.get("load1_max"),
                "load1_samples": s.get("load1_samples")}
                for s in lat_rows],
            "target": MM13_P99,
        }
        if judged:
            p99 = [s["p99_ms"] for s in judged]
            res.update(summarize(p99, target=MM13_P99, lower_better=True))
            res["judgment"] = "judged"
        else:
            res.update({"samples": [s["p99_ms"] for s in lat_rows],
                        "median": statistics.median(
                            [s["p99_ms"] for s in lat_rows]),
                        "judgment": "not judged: host contended",
                        "pass": True,
                        "note": "no run had every 1s load1 sample <= "
                                f"{CORES} cores; open for gate G1"})
        results["metrics"]["MM1.3"] = res
        if res["judgment"] == "judged":
            status = "PASS" if res["pass"] else "FAIL"
            print(f"MM1.3: median p99 {res['median']:.1f} ms on "
                  f"{len(judged)} qualified runs {status}")
            if not res["pass"]:
                fails.append(f"MM1.3: p99 {res['median']:.1f} ms over "
                             "5 ms on qualified runs")
        else:
            print(f"MM1.3: {res['judgment']} — {len(unqualified)} runs "
                  "recorded, p99s "
                  f"{[round(s['p99_ms'],1) for s in lat_rows]}")

    # ------------------------- MM1.4 / MM1.5 ---------------------------
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
