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
    detection even when both verifiers reject identically."""
    wrong = deny("E_BUNDLE", "E_CHAIN")
    if RS.judge_mutant(1, wrong, wrong)["detected"]:
        return False, "class-1 mutant with first error E_BUNDLE counted detected"
    right = deny("E_SIG", "E_CHAIN")
    if not RS.judge_mutant(1, right, right)["detected"]:
        return False, "class-1 mutant with first error E_SIG not detected"
    return True, "wrong first error rejected, expected error detected"


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
    ("mm1.2 fsync bound judges only on exact (strace) counts",
     t_fsync_bound_needs_exact_count),
]


def main():
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
