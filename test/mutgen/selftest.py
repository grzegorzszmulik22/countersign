# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""M1.6 harness negative tests (C1.6.4, supervisor review requirement).

On the seeded corpus every mutant already yields its expected error and
every measurement already comes out right, so a green suite alone never
proves the harness would NOTICE when they do not. Each enforced property
gets a negative test here: a wrong input is fed through the SAME judgment
functions the suite uses, and the harness must reject it. Every case also
checks the honest direction so a check that rejects everything is caught
too. Runs in-process against run_suite.py and measure.py — if a sabotage
weakens a rule, the case feeding that rule its wrong input passes where
it must fail, and this program exits non-zero.

Usage: selftest.py — exits 0 when every property rejects its wrong input.
"""
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_suite as RS  # noqa: E402
import measure as ME  # noqa: E402

CORES = 4
RUNS = 5


def deny(*codes, verdict="DENIED", warns=None):
    return {"verdict": verdict,
            "errors": [{"code": c, "index": i, "detail": c}
                       for i, c in enumerate(codes)],
            "warnings": [{"code": c, "index": i, "detail": c}
                         for i, c in enumerate(warns or [])]}


def bench_row(metric, run, records=1000, cpu_s=1.0, wall_s=2.0,
              load=None, **extra):
    row = {"metric": metric, "run": run, "records": records,
           "cpu_s": cpu_s, "wall_s": wall_s,
           "records_per_cpu_s": records / cpu_s,
           "records_per_s": records / wall_s,
           "load1_samples": load if load is not None else [1.0, 1.0]}
    row.update(extra)
    return row


def case(name, fn):
    """fn returns (ok, detail); ok means the wrong input was rejected and
    the honest input accepted."""
    try:
        ok, detail = fn()
    except Exception as e:
        ok, detail = False, f"raised {e!r}"
    print(("  hold " if ok else "  MISS ") + name +
          (f" — {detail}" if detail else ""))
    return ok


def t_detected_needs_expected_error():
    """03 §11 Denied: first error out of the class's expected set is NOT a
    detection even when both verifiers reject identically. Covers every
    class's set and the CLEAN-class and UNSEALED paths."""
    wrong = deny("E_BUNDLE", "E_CHAIN")
    if RS.judge_mutant(1, wrong, wrong)["detected"]:
        return False, "class-1 mutant with first error E_BUNDLE counted detected"
    right = deny("E_SIG", "E_CHAIN")
    if not RS.judge_mutant(1, right, right)["detected"]:
        return False, "class-1 mutant with first error E_SIG not detected"
    # Every class: a real error code outside its expected set must not
    # detect — catches tampering that broadens any EXPECTED entry.
    all_codes = {"E_SIG", "E_CHAIN", "E_INCLUSION", "E_SEAL", "E_SESSION",
                 "E_KEY", "E_CHECKPOINT", "E_BUNDLE", "E_POLICY",
                 "E_STRUCTURE"}
    for cls, exp in RS.EXPECTED.items():
        bad = sorted(all_codes - exp)[0]
        w = deny(bad, "E_STRUCTURE")
        if RS.judge_mutant(cls, w, w)["detected"]:
            return False, (f"class {cls}: first error {bad} outside "
                           f"{sorted(exp)} counted detected")
    # A CLEAN-class verdict can never count as detected.
    for v in ("CLEAN", "CLEAN_WITH_DENIALS"):
        cl = deny("E_SIG", verdict=v)
        if RS.judge_mutant(1, cl, cl)["detected"]:
            return False, f"{v} verdict counted detected"
    # Class 5's UNSEALED verdict (no error) is a legitimate detection.
    unsealed = {"verdict": "UNSEALED", "errors": [], "warnings": []}
    if not RS.judge_mutant(5, unsealed, unsealed)["detected"]:
        return False, "class-5 UNSEALED not detected"
    return True, "wrong first error rejected per class; expected/" \
                 "UNSEALED paths detected"


def t_agreement_needs_full_sets():
    """C1.6.2: agreement is on the FULL error+warning code sets; a pair
    matching on the first error and diverging later disagrees."""
    gv = deny("E_SIG", "E_CHAIN", warns=["W_TAINT"])
    pv = deny("E_SIG", "E_INCLUSION", warns=["W_TAINT"])
    if RS.verdicts_agree(gv, pv):
        return False, "same first error, different later errors counted agree"
    if RS.judge_mutant(1, gv, pv)["agree"]:
        return False, "judge_mutant counted diverging sets agree"
    gw = deny("E_SIG", "E_CHAIN", warns=["W_TAINT"])
    pw = deny("E_SIG", "E_CHAIN")
    if RS.verdicts_agree(gw, pw):
        return False, "diverging WARNING sets counted agree"
    gd = deny("E_SIG", verdict="DENIED")
    pd = deny("E_SIG", verdict="SEALED")
    if RS.verdicts_agree(gd, pd):
        return False, "diverging verdicts counted agree"
    same = deny("E_SIG", "E_CHAIN", warns=["W_TAINT"])
    if not RS.verdicts_agree(same, dict(same)):
        return False, "identical outputs counted disagree"
    return True, "later-error and warning divergence both disagreed"


def t_mm11_rate_is_cpu_derived():
    """CR-002 MM1.1: reported records_per_cpu_s must equal records/cpu_s
    (user+sys), wall rate reported separately — never the same number."""
    bad = bench_row("MM1.1", 0, records_per_cpu_s=5000.0)
    if ME.rate_consistent(bad, single_core=True):
        return False, "fabricated rate 5000 != 1000/1.0 accepted"
    no_wall = bench_row("MM1.1", 0)
    del no_wall["records_per_s"]
    if ME.rate_consistent(no_wall, single_core=True):
        return False, "row without wall rate accepted"
    cpu_over_wall = bench_row("MM1.1", 0, cpu_s=3.0, wall_s=1.0)
    if ME.rate_consistent(cpu_over_wall, single_core=True):
        return False, "single-core cpu_s > wall_s accepted"
    honest = bench_row("MM1.1", 0, cpu_s=1.8, wall_s=2.0)
    if not ME.rate_consistent(honest, single_core=True):
        return False, "honest row rejected"
    return True, "fabricated, wall-less and impossible rows rejected"


def t_mm12_rate_is_cpu_derived():
    """The writer-rate check is identical for MM1.2 (multi-core: cpu may
    exceed wall, only the field identities are asserted)."""
    bad = bench_row("MM1.2", 0, records_per_cpu_s=99999.0)
    if ME.rate_consistent(bad, single_core=False):
        return False, "fabricated writer rate accepted"
    multicore = bench_row("MM1.2", 0, cpu_s=6.0, wall_s=1.5)
    if not ME.rate_consistent(multicore, single_core=False):
        return False, "honest multi-core row (cpu>wall) rejected"
    return True, "fabricated writer rate rejected, cpu>wall allowed"


def t_mm13_one_high_sample_unqualifies():
    """CR-002 MM1.3: a run is judged only if EVERY per-second load sample
    stayed <= cores; one sample above makes it not judged."""
    if ME.mm13_classify([1.0, 1.0, 4.01, 1.0], CORES) != "unqualified":
        return False, "single sample above cores did not unqualify the run"
    if ME.mm13_classify([CORES * 1.0] * 3, CORES) != "qualified":
        return False, "samples exactly at cores not qualified (<= is the bound)"
    if ME.mm13_classify([], CORES) != "missing":
        return False, "empty sample list not classed missing"
    if ME.mm13_classify(None, CORES) != "missing":
        return False, "absent samples not classed missing"
    return True, "one high sample unqualifies; boundary and missing held"


def t_runs_and_samples_counted():
    """06 §12: every run's samples reported, none dropped; the recorded
    counts are checked per metric."""
    short = {"runs": 4, "samples": [1, 2, 3, 4]}
    if not ME.validate_metric("MM1.1", short, RUNS):
        return False, "4-run metric accepted"
    dropped = {"runs": 5, "samples": [1, 2, 3],
               "load1_samples": {f"run{i}": [1.0] for i in range(5)}}
    if not ME.validate_metric("MM1.1", dropped, RUNS):
        return False, "3 samples for 5 runs accepted"
    miss_load = {"runs": 5, "samples": [1] * 5,
                 "all_samples": [{"p99_ms": 1.0, "load1_samples": [1.0]}
                                 for _ in range(4)] +
                                [{"p99_ms": 1.0}]}
    if not ME.validate_metric("MM1.3", miss_load, RUNS):
        return False, "a run without load samples accepted"
    honest = {"runs": 5, "samples": [1] * 5,
              "load1_samples": {f"run{i}": [1.0, 2.0] for i in range(5)}}
    if ME.validate_metric("MM1.1", honest, RUNS):
        return False, "complete metric flagged"
    return True, "short runs, dropped samples and missing loads rejected"


def t_summarize_enforces_target():
    """summarize is the pass/fail gate for every metric: a median off
    target in EITHER direction must fail, in both comparator modes."""
    if ME.summarize([9.0, 10.0], target=20.0)["pass"]:
        return False, "median 10 under a >=20 target passed"
    if ME.summarize([8.0], target=5.0, lower_better=True)["pass"]:
        return False, "median 8 over a <=5 target passed"
    if not ME.summarize([21.0], target=20.0)["pass"]:
        return False, "median 21 over a >=20 target failed"
    if not ME.summarize([4.0], target=5.0, lower_better=True)["pass"]:
        return False, "median 4 under a <=5 target failed"
    return True, "targets enforced in both comparator directions"


def t_fsync_bound_needs_exact_count():
    """MM1.2 fsync bound: only a strace-derived count may judge it; the
    bench's own cohort estimate can never estimate it into a pass — or a
    fail. Any uncounted run leaves the whole bound not judged."""
    est_high = [{"records": 1000, "cluster_per_record": 0.9}]
    if ME.fsync_samples(est_high) is not None:
        return False, "estimate over the bound judged the bound"
    est_low = [{"records": 1000, "cluster_per_record": 0.001}]
    if ME.fsync_samples(est_low) is not None:
        return False, "estimate under the bound judged the bound"
    mixed = [{"records": 1000, "fsync_per_record": 0.05},
             {"records": 1000, "cluster_per_record": 0.01}]
    if ME.fsync_samples(mixed) is not None:
        return False, "one uncounted run still judged the bound"
    exact = [{"records": 1000, "fsync_per_record": 0.05},
             {"records": 1000, "fsync_per_record": 0.20}]
    if ME.fsync_samples(exact) != [0.05, 0.20]:
        return False, "exact counts not returned for judgment"
    return True, "estimates never judge; exact counts do"


def _calib(tmpdir, samples=400, pace=5.0, wall=4.0, dev_off=0,
           claimed=None, mtime_age=0.0, name="fscal-calib.dat"):
    """A plausible MM1.3 fsync-calibration record: `samples` write+fsync
    latencies (8 ms each) on a real file inside tmpdir."""
    path = os.path.join(tmpdir, name)
    vals = samples if isinstance(samples, list) else [8.0] * samples
    with open(path, "wb") as f:
        f.write(b"x" * (len(vals) * 300))
    dev = os.stat(path).st_dev
    if mtime_age:
        old = time.time() - mtime_age
        os.utime(path, (old, old))
    rec = {"metric": "MM1.3-calib", "source": "measured-in-run",
           "path": path, "st_dev": dev + dev_off, "n": len(vals),
           "record_bytes": 300, "pace_ms": pace, "wall_s": wall,
           "samples": vals}
    rec["fsync_p99_ms"] = (claimed if claimed is not None
                           else ME.mm13_calib_p99(rec))
    return rec


def _pair(tmpdir, pre_p99=8.0, post_p99=8.0, rs=100.0, re_=200.0):
    """An honest pre/post calibration pair bracketing a latency run:
    pre ends at 20, the run spans [rs, re_]=[100, 200], post starts at
    210 — the disk measured alone, larger leg p99 recorded."""
    pre = _calib(tmpdir, samples=[pre_p99] * 400, name="pre.dat")
    pre.update(t_start=10.0, t_end=20.0, observed_wall_s=10.0)
    post = _calib(tmpdir, samples=[post_p99] * 400, name="post.dat")
    post.update(t_start=210.0, t_end=220.0, observed_wall_s=10.0)
    return ({"pre": pre, "post": post,
             "calib_p99_ms": max(pre_p99, post_p99)},
            {"run_t_start": rs, "run_t_end": re_})


def t_mm13_calib_measured_in_run():
    """CR-003: the calibration must be measured in THIS run — missing,
    cached, supplied or estimated records all fail C1.6.3."""
    with tempfile.TemporaryDirectory() as d:
        if ME.fsync_calib_ok(None, d)[0]:
            return False, "missing calibration accepted"
        for src in ("cached", "supplied", "estimated", "earlier-run"):
            c = _calib(d)
            c["source"] = src
            if ME.fsync_calib_ok(c, d)[0]:
                return False, f"source {src!r} accepted"
        c = _calib(d, samples=40)  # n matches len, just too few
        if ME.fsync_calib_ok(c, d)[0]:
            return False, "40-sample calibration accepted"
        c = _calib(d, pace=2.0)
        if ME.fsync_calib_ok(c, d)[0]:
            return False, "2 ms pacing accepted"
        c = _calib(d, wall=0.05)  # record claims impossible duration
        if ME.fsync_calib_ok(c, d)[0]:
            return False, "wall too short for the pacing accepted"
        # Harness-observed wall: the command returned in 50 ms but 400
        # paced samples need >= 2 s — the record was supplied, not run.
        c = _calib(d)
        if ME.fsync_calib_ok(c, d, observed_wall_s=0.05)[0]:
            return False, "instant-return calibration accepted"
        # A file written before this run is a cached result.
        c = _calib(d, mtime_age=3600)
        if ME.fsync_calib_ok(c, d, since=time.time())[0]:
            return False, "stale calibration file accepted"
        c = _calib(d, claimed=1.0)  # claimed p99 not from the samples
        if ME.fsync_calib_ok(c, d)[0]:
            return False, "claimed p99 != samples-derived accepted"
        c = _calib(d)
        ok, why = ME.fsync_calib_ok(c, d, observed_wall_s=10.0,
                                    since=time.time() - 10)
        if not ok:
            return False, f"honest calibration rejected: {why}"
        return True, "missing/cached/estimated/forged calibrations rejected"


def t_mm13_calib_same_filesystem():
    """CR-003: the calibration must be on the same file system as the
    ledger under test — a record from another device cannot stand in."""
    with tempfile.TemporaryDirectory() as d:
        c = _calib(d, dev_off=999)
        if ME.fsync_calib_ok(c, d)[0]:
            return False, "different-device calibration accepted"
        c = _calib(d)
        ok, why = ME.fsync_calib_ok(c, d)
        if not ok:
            return False, f"same-device calibration rejected: {why}"
        return True, "foreign-device calibration rejected"


def t_mm13_calib_spec_constants():
    """CR-003: 400 samples, 300-byte O_APPEND write+fsync, >= 5 ms pace
    and a reported wall >= samples x pacing are SPEC constants — a leg
    short of any of them was not measured, whatever the harness was
    configured to take. Violating cases just under each floor reject;
    the exact boundary accepts."""
    with tempfile.TemporaryDirectory() as d:
        for n in (100, 399):  # a harness that accepts either must fail
            c = _calib(d, samples=n, wall=n * 5.0 / 1000 + 0.5)
            if ME.fsync_calib_ok(c, d)[0]:
                return False, f"{n}-sample calibration accepted"
        c = _calib(d, samples=400)   # boundary: exactly 400
        ok, why = ME.fsync_calib_ok(c, d)
        if not ok:
            return False, f"400-sample boundary rejected: {why}"
        c = _calib(d, pace=4.9)      # pace under the 5 ms constant
        if ME.fsync_calib_ok(c, d)[0]:
            return False, "4.9 ms pacing accepted"
        c = _calib(d)
        c["record_bytes"] = 299      # write shape differs from the spec
        if ME.fsync_calib_ok(c, d)[0]:
            return False, "299-byte write+fsync shape accepted"
        c = _calib(d)                # own file too small for the samples
        with open(c["path"], "wb") as f:
            f.write(b"x" * 300)
        if ME.fsync_calib_ok(c, d)[0]:
            return False, "file too small for 400 x 300-byte appends"
        # Reported wall just under samples x pacing (2.0 s) but over the
        # looser (n-1)-floor (1.995 s): only the spec floor rejects it.
        c = _calib(d, wall=1.998)
        if ME.fsync_calib_ok(c, d)[0]:
            return False, "reported wall under samples x pacing accepted"
        c = _calib(d, wall=2.0)      # boundary: wall == samples x pacing
        ok, why = ME.fsync_calib_ok(c, d)
        if not ok:
            return False, f"wall == samples x pacing rejected: {why}"
        return True, "spec constants enforced at the boundary"


def t_mm13_calib_device_is_measured():
    """CR-003 clarification: the file system check must measure the
    calibration FILE's real device — never trust the st_dev the record
    claims. A record whose claim matches the ledger while its file
    actually sits on another device is the exploit; every other
    claimable field (n, path) is likewise measured, not trusted."""
    with tempfile.TemporaryDirectory() as d:
        dev = os.stat(d).st_dev
        foreign = None
        for cand in ("/dev/shm", "/run"):
            try:
                if (os.stat(cand).st_dev != dev and
                        os.access(cand, os.W_OK)):
                    foreign = cand
                    break
            except OSError:
                continue
        if foreign is None:
            return False, "no writable different-device dir on this host"
        c = _calib(foreign, name="fscal-foreign.dat")
        c["st_dev"] = dev                            # claim the ledger's device
        try:
            if ME.fsync_calib_ok(c, d)[0]:
                return False, "claimed-device-matches/real-device-differs accepted"
        finally:
            os.unlink(c["path"])
        c = _calib(foreign, name="fscal-foreign.dat")  # honest foreign claim too
        try:
            if ME.fsync_calib_ok(c, d)[0]:
                return False, "honestly-recorded foreign device accepted"
        finally:
            os.unlink(c["path"])
        c = _calib(d)
        c["n"] = c["n"] - 1  # claim differs from the measured sample count
        if ME.fsync_calib_ok(c, d)[0]:
            return False, "recorded n != actual samples accepted"
        c = _calib(d)
        c["path"] = os.path.join(d, "ghost.dat")  # claim a file that isn't there
        if ME.fsync_calib_ok(c, d)[0]:
            return False, "nonexistent calibration file accepted"
        c = _calib(d)  # boundary: claim == real == ledger device
        ok, why = ME.fsync_calib_ok(c, d)
        if not ok:
            return False, f"claim == real == ledger device rejected: {why}"
        return True, "device measured from the file, claims never trusted"


def t_mm13_bound_uses_calibration():
    """CR-003: the judged bound must BE the calibration — every run has
    its own pre/post pair, target is the median qualified calib p99 +
    5 ms, and pass follows it. A fixed bound, wrong pass, missing
    records or doctored qualified flags all fail."""
    with tempfile.TemporaryDirectory() as d:
        ctx = {"ledger_dir": d}
        cpair, times = _pair(d)      # both legs p99 8.0 -> bound 13.0
        run = {"p99_ms": 12.0, "load1_samples": [1.0, 2.0],
               "qualified": True, "calib_p99_ms": 8.0, **times}
        base = {"runs": 5, "samples": [12.0] * 5, "cores": 4,
                "judgment": "judged", "calibration": [cpair] * 5,
                "all_samples": [dict(run) for _ in range(5)],
                "median": 12.0, "pass": True, "target": 13.0,
                "absolute_p99_ms": 12.0}
        fixed = {**base, "target": 5.0}
        if not ME.mm13_res_ok(fixed, ctx):
            return False, "fixed 5 ms bound accepted as calibrated"
        wrong_pass = {**base, "pass": False}  # 12 <= 13 must pass
        if not ME.mm13_res_ok(wrong_pass, ctx):
            return False, "pass flag not following the bound accepted"
        no_abs = dict(base)
        del no_abs["absolute_p99_ms"]
        if not ME.mm13_res_ok(no_abs, ctx):
            return False, "absolute p99 not recorded accepted"
        no_cal = dict(base)
        del no_cal["calibration"]
        if not ME.mm13_res_ok(no_cal, ctx):
            return False, "judged metric without calibration accepted"
        short_cal = {**base, "calibration": [cpair] * 4}
        if not ME.mm13_res_ok(short_cal, ctx):
            return False, "4 calibrations for 5 runs accepted"
        one_leg = {**base, "calibration": [
            {"pre": cpair["pre"], "calib_p99_ms": 8.0}] * 5}
        if not ME.mm13_res_ok(one_leg, ctx):
            return False, "single-leg calibration accepted"
        over = {**base, "median": 14.0, "pass": False,
                "absolute_p99_ms": 14.0}  # 14 > 13 must fail
        if ME.mm13_res_ok(over, ctx):
            return False, "median over the calibrated bound passed"
        # A run doctored qualified but whose own load samples exceed
        # cores must not count toward the bound.
        doctored = [dict(run) for _ in range(4)]
        doctored.append({**run, "load1_samples": [9.0, 9.0]})
        lie = {**base, "all_samples": doctored}
        if not ME.mm13_res_ok(lie, ctx):
            return False, "qualified flag contradicting load accepted"
        nj = {**base, "judgment": "not judged: host contended"}
        if ME.mm13_res_ok(nj, ctx):
            return False, "honest not-judged metric flagged"
        if ME.mm13_res_ok(base, ctx):
            return False, "honest judged metric flagged"
        return True, "fixed bounds, wrong pass, missing/doctored " \
                     "records rejected"


def t_mm13_calib_runs_alone():
    """CR-003 clarification: the disk is measured alone — a calibration
    whose harness-recorded brackets overlap the latency run (or a run
    without brackets to prove they do not) fails C1.6.3."""
    with tempfile.TemporaryDirectory() as d:
        ctx = {"ledger_dir": d}
        cpair, times = _pair(d)
        run = {"p99_ms": 12.0, "load1_samples": [1.0],
               "qualified": True, "calib_p99_ms": 8.0, **times}
        ok = {"runs": 1, "samples": [12.0], "cores": 4,
              "judgment": "judged", "calibration": [cpair],
              "all_samples": [run], "median": 12.0, "pass": True,
              "target": 13.0, "absolute_p99_ms": 12.0}
        if ME.mm13_res_ok(ok, ctx):
            return False, "honest alone-window calibration flagged"
        pre_over = {**ok, "calibration": [
            {**cpair, "pre": {**cpair["pre"], "t_end": 150.0}}]}
        if not ME.mm13_res_ok(pre_over, ctx):
            return False, "pre-calibration ending inside the run accepted"
        post_over = {**ok, "calibration": [
            {**cpair, "post": {**cpair["post"], "t_start": 150.0}}]}
        if not ME.mm13_res_ok(post_over, ctx):
            return False, "post-calibration starting inside the run " \
                          "accepted"
        no_t = {**ok, "all_samples": [
            {"p99_ms": 12.0, "load1_samples": [1.0], "qualified": True,
             "calib_p99_ms": 8.0}]}
        if not ME.mm13_res_ok(no_t, ctx):
            return False, "run without timing brackets accepted"
        # Boundary: a pre ending exactly when the run starts is alone.
        tight = {**ok, "calibration": [
            {**cpair, "pre": {**cpair["pre"], "t_end": 100.0}}]}
        if ME.mm13_res_ok(tight, ctx):
            return False, "boundary pre-t_end == run-start flagged"
        return True, "overlapping and bracket-less calibrations " \
                     "rejected; boundary alone window held"


def t_mm13_uses_larger_p99():
    """CR-003 clarification: the run's calibration p99 — and therefore
    the bound — is the LARGER of the pre and post legs; recording or
    judging from the smaller fails C1.6.3."""
    with tempfile.TemporaryDirectory() as d:
        ctx = {"ledger_dir": d}
        cpair, times = _pair(d, pre_p99=8.0, post_p99=20.0)
        run = {"p99_ms": 12.0, "load1_samples": [1.0],
               "qualified": True, "calib_p99_ms": 20.0, **times}
        base = {"runs": 1, "samples": [12.0], "cores": 4,
                "judgment": "judged", "calibration": [cpair],
                "all_samples": [run], "median": 12.0, "pass": True,
                "target": 25.0, "absolute_p99_ms": 12.0}
        if ME.mm13_res_ok(base, ctx):
            return False, "honest larger-p99 bound flagged"
        small = {"pre": cpair["pre"], "post": cpair["post"],
                 "calib_p99_ms": 8.0}
        bad = {**base, "calibration": [small],
               "all_samples": [{**run, "calib_p99_ms": 8.0}]}
        if not ME.mm13_res_ok(bad, ctx):
            return False, "smaller of pre/post recorded as the p99 " \
                          "accepted"
        bad_t = {**base, "target": 13.0}  # smaller leg + 5 ms
        if not ME.mm13_res_ok(bad_t, ctx):
            return False, "bound computed from the smaller p99 accepted"
        return True, "smaller-of-two p99s rejected in record and bound"


def t_calib_wall_floor():
    """CR-003 clarification: a calibration whose harness-observed wall
    is shorter than samples x pacing could not have run the paced
    samples — violating rejected, exact boundary accepted."""
    with tempfile.TemporaryDirectory() as d:
        c = _calib(d)  # 400 samples x 5 ms -> observed must be >= 2.0 s
        if ME.fsync_calib_ok(c, d, observed_wall_s=1.99)[0]:
            return False, "observed wall under samples x pacing accepted"
        ok, why = ME.fsync_calib_ok(c, d, observed_wall_s=2.0)
        if not ok:
            return False, f"boundary wall == samples x pacing: {why}"
        return True, "short observed wall rejected; boundary accepted"


CASES = [
    ("denied: first error outside the class expected set is not detected",
     t_detected_needs_expected_error),
    ("agreement: full error+warning code sets, never first error only",
     t_agreement_needs_full_sets),
    ("mm1.1: reported rate must be records/cpu_s, wall separate",
     t_mm11_rate_is_cpu_derived),
    ("mm1.2: writer rate must be records/cpu_s, wall separate",
     t_mm12_rate_is_cpu_derived),
    ("mm1.3: one load sample above cores unqualifies the run",
     t_mm13_one_high_sample_unqualifies),
    ("06§12: run counts and per-run samples checked per metric",
     t_runs_and_samples_counted),
    ("summarize: medians off target fail in both comparator modes",
     t_summarize_enforces_target),
    ("mm1.2 fsync bound judges only on exact (strace) counts",
     t_fsync_bound_needs_exact_count),
    ("mm1.3: calibration measured in-run, never cached/supplied/estimated",
     t_mm13_calib_measured_in_run),
    ("mm1.3: calibration must be on the ledger's file system",
     t_mm13_calib_same_filesystem),
    ("mm1.3: judged bound is the measured fsync p99 + 5 ms",
     t_mm13_bound_uses_calibration),
    ("mm1.3: calibration runs alone, never overlapping a latency run",
     t_mm13_calib_runs_alone),
    ("mm1.3: the larger of pre/post calibrations is the bound",
     t_mm13_uses_larger_p99),
    ("mm1.3: observed wall < samples x pacing is not a calibration",
     t_calib_wall_floor),
    ("mm1.3: file system measured by the calib file's real device",
     t_mm13_calib_device_is_measured),
    ("mm1.3: 400 samples, 300-byte writes, 5 ms pace, wall are spec constants",
     t_mm13_calib_spec_constants),
]


def main():
    if len(CASES) != 16:
        print(f"selftest: {len(CASES)} cases registered, need 16 — the "
              "negative-test set itself was tampered with")
        return 1
    print(f"harness negative tests ({len(CASES)} properties):")
    misses = [n for n, fn in CASES if not case(n, fn)]
    if misses:
        print(f"selftest: {len(misses)} propert(ies) NOT enforced: "
              f"{misses}")
        return 1
    print("selftest: every enforced property rejected its wrong input")
    return 0


if __name__ == "__main__":
    sys.exit(main())
