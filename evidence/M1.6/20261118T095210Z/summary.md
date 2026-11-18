# M1.6 — mutation suite and measurements (CR-002 restated targets)

Run 20261118T095210Z, host `Neoverse-N1 aarch64 4 cores`, kernel
6.12.0-204.92.4.4.3.el9uek. Targets per `spec/milestones/M1-evidence-core.md`
as restated by accepted `spec/CHANGE_REQUESTS/002`.

## Checks

- **C1.6.1 PASS** — 200/200 seeded valid bundles (1–3 emitters, 5–500
  records, all record families) CLEAN-class in both `csverify` and
  `refverify`, identical output.
- **C1.6.2 PASS** — 1,008 mutants (112 per each of nine §11 classes):
  all rejected by both verifiers, identical error/warning code sets,
  first error inside the §11 expected set, class 5 never `CLEAN*`,
  zero byte-identical mutants. Directed extras agreed (policy 20,
  contract 20, result-before-effect 20); bundled keys.json remains a
  documented agreement-only gap.
- **C1.6.3 PASS** — all judged targets met; MM1.3 not judged (host
  contended), open for gate G1.

## Measurements (06 §12: ≥5 runs, raw samples, median, CV)

- **MM1.1 PASS** — median 3,239 records/CPU-s of one core
  (GOMAXPROCS=1, user+sys). Same-run Ed25519 calibration 5,607
  ops/CPU-s → ratio 0.578 ≥ 0.50. Calibration ops/cpu_s and all run
  load samples in measurements.json.
- **MM1.2 PASS** — median 7,505 records/CPU-s of the writer ≥ 5,000.
  Group commits counted exactly via `strace --seccomp-bpf -f -y`
  (fsync on log/entries.jsonl, one per commit): median fsync/record
  0.033 ≤ 0.10. In-process return-cohort estimate kept alongside.
- **MM1.3 not judged: host contended** — 5 runs at 1,000 appends/s;
  no run had all 1-second load1 samples ≤ 4 cores (samples recorded
  per run). p99s recorded unjudged: 92.9, 52.3, 36.2, 27.1, 20.5 ms.
- **MM1.4 PASS** — 1,008/1,008 detected (100%), 100% agreement.
- **MM1.5** — median stored record 1,416 B (n = 51,904).

## Sabotages

- `mutator-noop-class-5` — caught (C1.6.2 byte-equality + MM1.4 ratio).
- `calibration-underreport` — caught (verify rate > halved calibration
  trips the harness-impossibility invariant in MM1.1).
- `fsync-per-record` — caught (exact strace count: ~1 commit per
  record, ratio ≈ 1.1 > 0.10).
- `load-samples-missing` — caught (MM1.3 runs without per-second load
  samples are a harness integrity failure, not a judgment).

Artifacts: `mutations.json` (per-mutant verdicts), `measurements.json`
(all raw samples, calibration, load series), `record-sizes.txt`,
`status.json`, `suite.log`, `output.log`, `result.json`, `sysinfo.txt`,
`sabotage/` (per-patch logs).
