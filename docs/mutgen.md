<!-- Copyright 2026 The Countersign Authors
     SPDX-License-Identifier: Apache-2.0 -->

# mutgen — seeded bundle generator and mutation suite (M1.6)

`test/mutgen/` produces valid evidence bundles with a seeded RNG and then
mutates them along the nine classes of `spec/03-evidence-format.md` §11,
running every mutant through **both** verifiers (`csverify` and
`ref/python/refverify`).

## Pieces

- `mutgen.py` — seeded session generator: 1–3 emitters, 5–500 records,
  random mixes of every record family (effects, intents, commits, undos,
  MCP, observer events). Deterministic: same seed → same bytes.
- `mutate.py` — the nine mutation classes plus directed extras
  (policy.yaml, result-before-effect, bundled keys.json).
- `run_suite.py` — C1.6.1 (200 clean bundles) + C1.6.2 (≥1,000 mutants,
  ≥100/class) differential driver.
- `measure.py` — C1.6.3 measurements MM1.1–MM1.5 per `06` §12, targets as
  restated by `spec/CHANGE_REQUESTS/002` and `003` (accepted).
- `test/bench/csbench.go` — Go-side timing for MM1.1–MM1.3 (verify
  throughput, durable-append throughput, append latency, fsync
  calibration).
- `selftest.py` — C1.6.4 harness negative tests: feeds every enforced
  property a wrong input through the same judgment functions the suite
  uses and requires rejection. `check-M1.6` runs it first — a harness
  that cannot flag bad input produces a green suite that proves nothing.

## Measurement rules (CR-002, CR-003)

- Rates are per **CPU-second** (process user+sys via `getrusage`), so an
  oversubscribed host does not depress the number being judged; wall
  rates are reported beside them.
- MM1.1 runs at `GOMAXPROCS=1` and is judged ≥ 50% of a raw Ed25519
  verify loop calibrated in the same invocation. Sanity: record
  verification can never outrun the calibration — a faster reported
  verify rate means a broken measurement, not a pass (this is what the
  `calibration-underreport` sabotage exercises).
- MM1.2 counts group commits exactly: the append runs execute under
  `strace --seccomp-bpf -f -y -e trace=fsync,fdatasync`, and commits are
  the fsync calls on `log/entries.jsonl` (one per commit; each commit
  also syncs `hashes.bin` and the session index). Bound: ≤ 1 commit
  per 10 records (the `fsync-per-record` sabotage exercises this). When
  strace is unavailable the fsync bound is recorded `not judged` — the
  in-process return-cohort estimate is the benchmark's own claim, not an
  observation of syscalls, and can never estimate the bound into a pass
  (`fsync-estimate-judged` sabotage). The strace-derived rates are also
  verified field-by-field: `records_per_cpu_s` must equal
  `records/cpu_s` with `records_per_s` separately from `wall_s`
  (`rate-not-verified` sabotage).
- MM1.3 samples `/proc/loadavg` every second per run; a run is judged
  only if every sample stayed ≤ core count — one sample above makes it
  not judged (`load-gate-accepts-high` sabotage). If no run qualifies
  the metric reports `not judged: host contended` (open for gate G1).
  Runs without samples are a harness integrity failure
  (`load-samples-missing` sabotage). The bound is host-referenced
  (CR-003): append p99 ≤ the same disk's fsync p99 + 5 ms, where the
  fsync p99 is the disk measured ALONE (CR-003 clarification): a
  `csbench fscal` run of 400 single 300-byte `O_APPEND` write+fsync
  samples paced ≥ 5 ms apart executes immediately before each latency
  run and another immediately after it, never concurrently — a
  concurrent calibration would measure the benchmark's own load and its
  fsyncs would slow the appends under test. Both records are kept with
  every sample, their harness-bracketed start/end times must prove no
  overlap with the run window, and the run's calibration p99 is the
  larger of the two legs. A missing leg, an overlap, or a bound taken
  from the smaller p99 all fail C1.6.3 (`calib-overlaps-run`,
  `calib-uses-min` sabotages). A missing, cached, supplied or
  estimated calibration fails too — the harness checks the record's
  source marker, sample count and pacing, that the reported wall and
  the harness-observed wall (≥ samples × pacing) and file mtime prove
  it ran in this run, and that the file's device matches the ledger
  directory's (`calib-accepts-supplied`, `calib-estimated-ok`,
  `calib-any-filesystem`, `wall-bound-loose` sabotages). The judged
  bound must be exactly the median qualified calibration p99 + 5 ms —
  a fixed bound, a swapped-in calibration, or a qualified flag that
  contradicts the run's own load samples all fail
  (`bound-not-calibrated` sabotage).
- Every metric must report ≥ 5 runs with each run's samples complete —
  dropped runs or samples fail the metric (`runs-not-counted` sabotage).

## Detection rule

A mutant counts as detected only when:

1. neither verifier returns a `CLEAN*`-class verdict,
2. the two verifiers emit identical error and warning code sets, and
3. the **first** error (in V-order — the primary rejection) is in the
   §11 expected set for that class.

Any record-content change cascades `E_CHAIN`/`E_INCLUSION`/`E_SEAL`
downstream; those codes are recorded but never satisfy detection.
A mutant byte-identical to its original is a hard failure — that is what
the `mutator-noop-class-5` sabotage exercises.

## Known divergence

The bundled `keys.json` member is required to exist, but `csverify` does
not compare it to the trusted `--keys` manifest; §11's directed extra
"keys differing from trusted → `E_KEY`" is therefore accepted by both
verifiers today. The suite asserts agreement only and reports the gap.
