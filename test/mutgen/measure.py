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
         commits <= 1 per 10 records, counted exactly from strace
         fsync() calls on log/entries.jsonl — one per commit. Without
         strace the fsync bound is not judged; the bench's in-process
         return-cohort estimate is recorded beside it, never judged.
- MM1.3  append p99 <= the disk's fsync p99 + 5 ms at 1,000/s (CR-003),
         judged only on runs whose per-second 1-minute load samples all
         stayed <= core count; every run is recorded. The fsync p99 is
         calibrated co-timed with each run on the same file system as
         the ledger under test (>= 400 single 300-byte O_APPEND
         write+fsync samples paced >= 5 ms apart per run, every sample
         recorded) — a missing, cached, supplied or estimated
         calibration fails. If no run qualifies the result is "not
         judged: host contended" — allowed by CR-002, open for G1.
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
import threading
import time

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
MM13_SLACK_MS = 5.0       # append p99 may exceed the measured fsync p99 by
MM13_ABS_MS = 5.0         # the absolute figure shown at G1 (CR-003)
MM13_CALIB_MIN = 400      # write+fsync calibration samples
MM13_CALIB_PACE_MS = 5.0  # minimum ms between calibration sample starts
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


# ------------------------- judgment helpers -----------------------------
# Extracted so the harness negative tests (selftest.py) can feed each rule
# a wrong input and require it to be rejected.

def rate_consistent(row, single_core):
    """A bench row's reported per-CPU rate must be exactly records/cpu_s of
    the measured process, with the wall rate reported separately as
    records/wall_s — never derived from the CPU time and never substituted
    for it. On a single core (GOMAXPROCS=1) cpu_s cannot exceed wall_s;
    multi-worker writers may use more CPU than wall and only the field
    identities are asserted."""
    try:
        n = float(row["records"])
        cpu = float(row["cpu_s"])
        wall = float(row["wall_s"])
        r_cpu = float(row["records_per_cpu_s"])
        r_wall = float(row["records_per_s"])
    except (KeyError, TypeError, ValueError):
        return False
    if n <= 0 or cpu <= 0 or wall <= 0:
        return False
    if single_core and cpu > wall * 1.05:
        return False
    return (abs(r_cpu - n / cpu) <= 1e-9 * (n / cpu) + 1e-9 and
            abs(r_wall - n / wall) <= 1e-9 * (n / wall) + 1e-9)


def fsync_samples(rows):
    """Exact group-commit ratios, one per run — the ONLY fsync source that
    may judge the MM1.2 bound is a strace-derived count on the bench row.
    The in-process return-cohort estimate is the benchmark's own claim,
    not an observation of syscalls, and can never stand in: any run
    without an exact count makes the whole bound not judged (None)."""
    out = []
    for s in rows:
        v = s.get("fsync_per_record")
        if v is None:
            return None
        out.append(v)
    return out


def mm13_classify(load1_samples, cores):
    """A latency run is judged only when EVERY per-second 1-minute load
    sample stayed <= cores. One sample above makes it not judged; a run
    carrying no samples cannot be classified at all (integrity failure,
    not a disqualification)."""
    if not load1_samples:
        return "missing"
    return "qualified" if max(load1_samples) <= cores else "unqualified"


def mm13_calib_p99(calib):
    """The disk's fsync p99, recomputed from the calibration's own
    recorded samples — the claimed summary field is never trusted."""
    s = sorted(float(x) for x in calib["samples"])
    return s[int(0.99 * (len(s) - 1))]


def fsync_calib_ok(calib, ledger_dir, observed_wall_s=None, since=None):
    """CR-003: MM1.3's bound is the same disk's fsync p99 + 5 ms, and the
    calibration must be measured in THIS run on the SAME file system as
    the ledger under test. A missing, cached, supplied or estimated
    calibration fails; so does one on a different file system or one
    whose record could not have been produced by a real paced run.

    observed_wall_s is how long the harness watched the calibration
    command run (a fabricated record returns instantly); since is the
    epoch time just before it started, used to prove the calibration
    file was written in this run. Both are supplied in production and
    may be omitted only by tests exercising the data checks alone."""
    if not isinstance(calib, dict):
        return False, "missing calibration"
    if calib.get("source") != "measured-in-run":
        return False, (f"source {calib.get('source')!r} — the calibration "
                       "must be measured in this run, never supplied, "
                       "cached or estimated")
    samples = calib.get("samples")
    n = len(samples) if isinstance(samples, list) else 0
    if n < MM13_CALIB_MIN:
        return False, f"{n} samples, need >= {MM13_CALIB_MIN}"
    if calib.get("n") != n:
        return False, f"recorded n {calib.get('n')} != {n} samples"
    if not all(isinstance(x, (int, float)) and x > 0 for x in samples):
        return False, "non-numeric or non-positive sample"
    pace = calib.get("pace_ms")
    if not isinstance(pace, (int, float)) or pace < MM13_CALIB_PACE_MS:
        return False, f"pace {pace!r} ms < {MM13_CALIB_PACE_MS} ms"
    floor = (n - 1) * pace / 1000.0
    wall = calib.get("wall_s")
    if not isinstance(wall, (int, float)) or wall < floor:
        return False, (f"reported wall {wall!r}s cannot contain {n} "
                       f"samples paced {pace} ms — record is estimated, "
                       "not measured")
    if observed_wall_s is not None and observed_wall_s < floor * 0.9:
        return False, (f"calibration command returned in "
                       f"{observed_wall_s:.2f}s but {n} samples paced "
                       f"{pace} ms need >= {floor:.2f}s — record was "
                       "supplied, not run")
    if not isinstance(calib.get("path"), str):
        return False, "calibration file path not recorded"
    try:
        cst = os.stat(calib["path"])
        dev = os.stat(ledger_dir).st_dev
    except OSError as e:
        return False, f"cannot stat calibration/ledger: {e}"
    if cst.st_dev != dev or calib.get("st_dev") != dev:
        return False, (f"calibration on device {cst.st_dev} (recorded "
                       f"{calib.get('st_dev')}), ledger on {dev} — "
                       "different file system")
    if since is not None and cst.st_mtime < since - 1.0:
        return False, ("calibration file predates this run — a cached "
                       "result was supplied")
    claimed = calib.get("fsync_p99_ms")
    recomputed = mm13_calib_p99(calib)
    if (not isinstance(claimed, (int, float)) or
            abs(claimed - recomputed) > max(0.01, recomputed * 0.01)):
        return False, (f"claimed p99 {claimed!r} != samples-derived "
                       f"{recomputed:.3f}")
    return True, "ok"


def mm13_res_ok(res, ctx):
    """MM1.3 (CR-003): a judged metric's bound must BE the in-run
    calibration — every latency run carries its own co-timed calibration
    (>= 400 paced samples on the ledger's file system), the target is the
    median fsync p99 of the qualified runs' calibrations + 5 ms, and
    pass/fail follows it, with the absolute p99 recorded beside. A
    missing/bad calibration, a run whose recorded qualification
    contradicts its own load samples, or any other bound fails C1.6.3."""
    calibs = res.get("calibration")
    runs = res.get("all_samples") or []
    if not isinstance(calibs, list) or len(calibs) != len(runs):
        return ["MM1.3 calibration: missing or not one per run"]
    problems = []
    cores = res.get("cores", CORES)
    for i, (c, r) in enumerate(zip(calibs, runs)):
        ok, why = fsync_calib_ok(c, ctx["ledger_dir"])
        if not ok:
            problems.append(f"MM1.3 calibration run {i}: {why}")
        want = mm13_classify(r.get("load1_samples"), cores) == "qualified"
        if r.get("qualified") != want:
            problems.append(f"MM1.3 run {i}: qualified flag contradicts "
                            "its recorded load samples")
    if problems:
        return problems
    if res.get("judgment") == "not judged: host contended":
        return []
    if res.get("judgment") != "judged":
        return [f"MM1.3: judgment {res.get('judgment')!r} not recognized"]
    q = [mm13_calib_p99(c) for c, r in zip(calibs, runs)
         if r.get("qualified")]
    if not q:
        return ["MM1.3: judged but no qualified run has a calibration"]
    bound = statistics.median(q) + MM13_SLACK_MS
    if abs(res.get("target", -1) - bound) > 1e-6:
        problems.append(f"MM1.3: target {res.get('target')} is not the "
                        f"measured fsync p99 + {MM13_SLACK_MS} ms "
                        f"({bound:.3f})")
    expect = isinstance(res.get("median"), (int, float)) and \
        res["median"] <= bound
    if res.get("pass") != expect:
        problems.append("MM1.3: pass flag does not follow the "
                        "calibrated bound")
    if res.get("absolute_p99_ms") != res.get("median"):
        problems.append("MM1.3: absolute p99 not recorded beside the "
                        "calibrated bound")
    return problems


def validate_metric(name, res, want_runs, calib_ctx=None):
    """06 §12: every run reported, none dropped. Checks the recorded run
    count and that each per-run sample list is complete; returns a list of
    problems (empty when the metric is complete)."""
    problems = []
    runs = res.get("runs")
    if not isinstance(runs, int) or runs < want_runs:
        problems.append(f"{name}: {runs} runs recorded, need >= "
                        f"{want_runs}")
        return problems
    samples = res.get("samples")
    if samples is not None and len(samples) != runs:
        problems.append(f"{name}: {len(samples)} samples for {runs} "
                        "runs — a run's samples were dropped")
    per_run = res.get("all_samples")
    if per_run is not None:
        if len(per_run) != runs:
            problems.append(f"{name}: {len(per_run)} run records for "
                            f"{runs} runs — a run was dropped")
        empty = [i for i, e in enumerate(per_run)
                 if isinstance(e, dict) and not e.get("load1_samples")]
        if empty:
            problems.append(f"{name}: run(s) {empty[:5]} missing "
                            "per-second load samples")
    loads = res.get("load1_samples")
    if isinstance(loads, dict):
        if len(loads) != runs:
            problems.append(f"{name}: load samples for {len(loads)} of "
                            f"{runs} runs")
        empty = sorted(k for k, v in loads.items() if not v)
        if empty:
            problems.append(f"{name}: empty load samples in run(s) "
                            f"{empty[:5]}")
    if name == "MM1.3" and calib_ctx is not None:
        problems += mm13_res_ok(res, calib_ctx)
    return problems


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
        # CR-002: the judged rate is records / (user+sys CPU-s) of this
        # process. Assert the bench reports exactly that (never the wall
        # rate) and that the wall rate is separately reported; a bench
        # that invents or substitutes the number is a harness defect.
        for s in run_rows:
            if not rate_consistent(s, single_core=True):
                fails.append(f"MM1.1 run {s.get('run')}: reported "
                             "records_per_cpu_s is not records/cpu_s, or "
                             "wall rate missing")
        if len(run_rows) < args.runs:
            fails.append(f"MM1.1: {len(run_rows)} run rows emitted, "
                         f"need >= {args.runs}")
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
        fails += validate_metric("MM1.1", res, args.runs)
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
    # Each run is one csbench invocation; when strace(1) is present the run
    # is wrapped in --seccomp-bpf -f -y so the group-commit count is exact:
    # one fsync() on log/entries.jsonl per commit (each commit also syncs
    # hashes.bin and the session index). Without strace the fsync bound is
    # recorded not judged — the in-process cohort estimate is the bench's
    # own claim, never an observation of syscalls, and cannot judge it.
    import re
    import shutil
    strace = shutil.which("strace")
    run_rows = []
    for i in range(args.runs):
        ldir = os.path.join(WORK, f"ledger-a{i}")
        inner = [bench, "append", ldir, rp, "20000", "32", "1"]
        cmd = inner
        trace = None
        if strace:
            trace = os.path.join(WORK, f"mm12-trace-{i}.txt")
            cmd = [strace, "--seccomp-bpf", "-f", "-y",
                   "-e", "trace=fsync,fdatasync", "-o", trace] + inner
        r = sh(cmd)
        rows = [s for s in samples_from(r.stdout)
                if s.get("metric") == "MM1.2"]
        if r.returncode != 0 or not rows:
            fails.append(f"MM1.2 run {i}: bench failed: {r.stderr[-200:]}")
            break
        row = rows[0]
        if trace:
            commits = None
            try:
                tl = open(trace).read()
                ent = len(re.findall(
                    r"(?:fsync|fdatasync)\(\d+<[^>]*entries\.jsonl", tl))
                tot = len(re.findall(r"(?:fsync|fdatasync)", tl))
                # commits = fsyncs on entries.jsonl; tot/3 bounds it when
                # a call was split unfinished/resumed (each commit issues
                # exactly 3 syscalls here: entries+hashes+session idx).
                commits = max(ent, tot // 3)
                row["fsync_commits"] = commits
                row["fsync_calls_on_entries"] = ent
                row["fsync_syscalls_total"] = tot
                row["fsync_per_record"] = commits / row["records"]
            except OSError:
                pass
            if commits is None:
                fails.append(f"MM1.2 run {i}: strace output unreadable — "
                             "fsync count cannot be verified")
                break
        run_rows.append(row)
    if run_rows:
        for s in run_rows:
            if not rate_consistent(s, single_core=False):
                fails.append(f"MM1.2 run {s.get('run')}: reported "
                             "records_per_cpu_s is not records/cpu_s, or "
                             "wall rate missing")
        if len(run_rows) < args.runs:
            fails.append(f"MM1.2: {len(run_rows)} run rows emitted, "
                         f"need >= {args.runs}")
        rates = [s["records_per_cpu_s"] for s in run_rows]
        wall = [s["records_per_s"] for s in run_rows]
        # The fsync bound judges ONLY on strace-derived exact counts; the
        # in-process cohort estimate is the benchmark's own claim and can
        # never estimate the bound into a pass — with any run uncounted
        # the bound is recorded not judged.
        fpr = fsync_samples(run_rows)
        commits = [s.get("fsync_commits") for s in run_rows]
        for i, s in enumerate(run_rows):
            c = s.get("fsync_commits")
            if strace and (c is None or not (1 <= c <= s["records"])):
                fails.append(f"MM1.2 run {i}: impossible commit count "
                             f"{c} for {s['records']} records")
        res = summarize(rates, target=MM12_RATE)
        res.update({"command": ("strace --seccomp-bpf -f -y -e "
                                "trace=fsync,fdatasync " if strace else "")
                               + f"{bench} append {WORK}/ledger-a<i> "
                               f"{rp} 20000 32 1",
                    "wall_records_per_s": wall,
                    "fsync_commits_samples": commits,
                    "cluster_commits_estimate": [
                        s.get("cluster_commits") for s in run_rows],
                    "cluster_per_record_estimate": [
                        s.get("cluster_per_record") for s in run_rows],
                    "median_commit_gap_ms": [
                        s.get("median_commit_gap_ms") for s in run_rows],
                    "load1_samples": {f"run{i}": s.get(
                        "load1_samples") for i, s in enumerate(run_rows)},
                    "target_text": ">= 5000 rec/cpu-s and <= 1 fsync "
                                   "(group commit) per 10 records",
                    "fsync_note": "one group commit fsyncs entries.jsonl, "
                                  "hashes.bin and the session index"})
        if fpr is not None:
            fres = summarize(fpr, target=MM12_FSYNC, lower_better=True)
            res["fsync_counting"] = ("exact: fsync() calls on "
                                     "log/entries.jsonl via strace")
            res["fsync_per_record"] = fres
            res["fsync_judgment"] = "judged"
            res["pass"] = res["pass"] and fres["median"] <= MM12_FSYNC
            fsync_status = f"fsync/rec {fres['median']:.3f} (exact)"
        else:
            res["fsync_counting"] = ("unavailable: no strace — "
                                     "cohort estimate never judges")
            res["fsync_judgment"] = ("not judged: fsync counting "
                                     "unavailable (strace missing)")
            fsync_status = "fsync bound not judged (no strace)"
        results["metrics"]["MM1.2"] = res
        fails += validate_metric("MM1.2", res, args.runs)
        status = "PASS" if res["pass"] else "FAIL"
        print(f"MM1.2: median {res['median']:.0f} rec/cpu-s, "
              f"{fsync_status} {status}")
        if not res["pass"]:
            fails.append(f"MM1.2: rate {res['median']:.0f} or fsync "
                         "bound missed target")

    # ------------------------- MM1.3 ----------------------------------
    # CR-003: the bound is the same disk's fsync p99 + 5 ms, measured in
    # this run on the same file system as the ledger under test. The
    # calibration is co-timed with every latency run — a fscal loop keeps
    # writing 400-sample paced batches for the run's whole duration, so
    # the bound tracks the disk conditions the appends actually saw (a
    # one-shot snapshot cannot: it drifts over the run window). Every
    # batch's samples are recorded; a run without a real, complete,
    # same-device calibration fails C1.6.3.
    ledger_dir = os.path.join(WORK, "ledger-b")
    os.makedirs(ledger_dir, exist_ok=True)

    def calib_loop(path, out, stop):
        while not stop.is_set():
            cr = sh([bench, "fscal", path, str(MM13_CALIB_MIN),
                     str(int(MM13_CALIB_PACE_MS))])
            if cr.returncode != 0:
                break
            rec = next((s for s in samples_from(cr.stdout)
                        if s.get("metric") == "MM1.3-calib"), None)
            if rec:
                out.append(rec)

    lat_rows, calib_recs = [], []
    for i in range(args.runs):
        calib_path = os.path.join(WORK, f"fscal-calib-{i}.dat")
        batch, stop = [], threading.Event()
        t0 = time.time()
        th = threading.Thread(target=calib_loop,
                              args=(calib_path, batch, stop))
        th.start()
        r = sh([bench, "latency", ledger_dir, rp, "1000", "20000", "8"])
        stop.set()
        th.join()
        obs_wall = time.time() - t0
        if r.returncode != 0:
            fails.append(f"MM1.3 run {i}: bench failed: {r.stderr[-200:]}")
            break
        rows = [s for s in samples_from(r.stdout)
                if s.get("metric") == "MM1.3"]
        if len(rows) != 1:
            fails.append(f"MM1.3 run {i}: {len(rows)} row(s) emitted, "
                         "need 1")
        samples_acc, walls = [], 0.0
        for c in batch:
            samples_acc += c.get("samples") or []
            walls += c.get("wall_s") or 0.0
        crec = None
        if samples_acc:
            try:
                dev = os.stat(calib_path).st_dev
            except OSError:
                dev = None
            crec = {"metric": "MM1.3-calib", "source": "measured-in-run",
                    "path": calib_path, "st_dev": dev,
                    "n": len(samples_acc), "record_bytes": 300,
                    "pace_ms": MM13_CALIB_PACE_MS, "wall_s": walls,
                    "batches": len(batch), "samples": samples_acc,
                    "fsync_p99_ms": mm13_calib_p99(
                        {"samples": samples_acc})}
        ok, why = fsync_calib_ok(crec, ledger_dir, obs_wall, t0)
        if not ok:
            fails.append(f"MM1.3 run {i}: fsync calibration rejected "
                         f"({why})")
            crec = None
        for s in rows:  # keep calib_recs aligned 1:1 with lat_rows
            lat_rows.append(s)
            calib_recs.append(crec)
    calib_ctx = {"ledger_dir": ledger_dir}

    # A run qualifies for judgment only when every per-second load sample
    # stayed <= cores; runs without samples cannot be classified and are
    # a harness integrity failure, not a disqualification.
    qualified, unqualified, missing = [], [], []
    for i, s in enumerate(lat_rows):
        cls = mm13_classify(s.get("load1_samples"), CORES)
        if cls == "missing":
            missing.append(i)
        elif cls == "qualified":
            qualified.append(i)
        else:
            unqualified.append(s)
    if missing:
        fails.append(f"MM1.3: runs without load1 samples: {missing} "
                     "(harness cannot classify them)")
    if len(lat_rows) < args.runs:
        fails.append(f"MM1.3: {len(lat_rows)} run rows emitted, "
                     f"need >= {args.runs}")
    judged = [lat_rows[i] for i in qualified]
    jcalib = [calib_recs[i] for i in qualified]
    bound = (statistics.median(
                 [mm13_calib_p99(c) for c in jcalib]) + MM13_SLACK_MS
             if jcalib and all(jcalib) else None)
    if lat_rows:
        res = {
            "command": f"{bench} latency {ledger_dir} {rp} 1000 20000 8 "
                       f"(x{len(lat_rows)})",
            "calibration": calib_recs[:len(lat_rows)],
            "calibration_command": f"{bench} fscal <run-file> "
                                   f"{MM13_CALIB_MIN} "
                                   f"{int(MM13_CALIB_PACE_MS)} "
                                   "co-timed per run",
            "cores": CORES,
            "runs": len(lat_rows),
            "qualified_runs": len(qualified),
            "samples": [s["p99_ms"] for s in lat_rows],
            "all_samples": [{
                "p50_ms": s["p50_ms"], "p99_ms": s["p99_ms"],
                "max_ms": s["max_ms"],
                "load1_max": s.get("load1_max"),
                "load1_samples": s.get("load1_samples"),
                "qualified": idx in qualified,
                "calib_p99_ms": (mm13_calib_p99(calib_recs[idx])
                                 if idx < len(calib_recs)
                                 and calib_recs[idx] else None)}
                for idx, s in enumerate(lat_rows)],
            "target": bound,
            "absolute_target_ms": MM13_ABS_MS,
        }
        if judged and bound is not None:
            s99 = summarize([s["p99_ms"] for s in judged],
                            target=bound, lower_better=True)
            res.update({"judged_samples": s99["samples"],
                        "median": s99["median"], "cv": s99["cv"],
                        "unstable": s99["unstable"],
                        "pass": s99["pass"], "judgment": "judged",
                        "absolute_p99_ms": s99["median"]})
        elif judged:
            res.update({"median": statistics.median(
                            [s["p99_ms"] for s in judged]),
                        "judgment": "judged", "pass": False,
                        "absolute_p99_ms": statistics.median(
                            [s["p99_ms"] for s in judged])})
        else:
            res.update({"median": statistics.median(res["samples"]),
                        "judgment": "not judged: host contended",
                        "pass": True,
                        "absolute_p99_ms": statistics.median(
                            res["samples"]),
                        "note": "no run had every 1s load1 sample <= "
                                f"{CORES} cores; open for gate G1"})
        results["metrics"]["MM1.3"] = res
        fails += validate_metric("MM1.3", res, args.runs, calib_ctx)
        if res["judgment"] == "judged":
            status = "PASS" if res["pass"] else "FAIL"
            tgt = (f" vs co-timed fsync p99 {bound - MM13_SLACK_MS:.1f} "
                   f"+ {MM13_SLACK_MS} ms = {bound:.1f} ms"
                   if bound is not None else " (no calibration)")
            print(f"MM1.3: median p99 {res['median']:.1f} ms on "
                  f"{len(judged)} qualified runs{tgt} {status}")
            if not res["pass"]:
                fails.append(f"MM1.3: p99 {res['median']:.1f} ms over "
                             f"calibrated bound {bound} ms on "
                             "qualified runs")
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
