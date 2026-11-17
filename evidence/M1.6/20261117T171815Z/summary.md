# M1.6 evidence — mutation suite and measurements

## Suite result (`.check-work/m16/suite`, copied here)

- **C1.6.1 PASS** — 200 seeded valid bundles (1–3 emitters, 5–500 records,
  deterministic ULIDs), both verifiers `CLEAN`-class with identical output.
- **C1.6.2 PASS** — 1,008 mutants (112 per class, ≥100 required), seed 1:
  - 1,008/1,008 rejected by both verifiers,
  - 1,008/1,008 identical error+warning code sets between Go `csverify`
    and Python `refverify`,
  - first error of every mutant inside the spec §11 expected class set
    (verdict alone never counts — the milestone's denied rule),
  - class 5 never `CLEAN`/`CLEAN_WITH_DENIALS`,
  - every mutant byte-differs from its original (no-op mutator caught),
  - directed extras: policy 20, contract 20, result-before-effect 20
    agreed; keys.json-vs-trusted recorded as the known agreement gap
    (both verifiers trust the external manifest — documented in
    docs/mutgen.md).
- **MM1.4** — 1008/1008 detected, 1008/1008 agreement (target 100%/≥1000/100%). PASS.
- **MM1.5** — median stored record size 1416 B over 51,904 records. Reported.

## Measurements MM1.1–MM1.3 (`measurements.json`, `csbench`)

All `[T]` targets missed on this lane host; raw samples, commands, machine
description and the per-core CPU analysis are in `measurements.json`.

| metric | target | wall-clock median | per-core CPU capability | verdict |
|---|---|---|---|---|
| MM1.1 verify, 1 core | ≥8,000 rec/s | 496 rec/s (5 runs, cv 0.18) | ~3,207 rec/s | unreachable per-core |
| MM1.2 durable append | ≥5,000 rec/s | 1,706 rec/s (5 runs, cv 0.24) | ~7,353 rec/s | contention-depressed |
| MM1.3 p99 @1,000/s | ≤5 ms | 35.7 ms (5 runs, cv 0.08) | — | contention-depressed |

Host: Neoverse-N1 aarch64, 4 cores, shared tenancy; loadavg 20–40 during
all runs. Per-core CPU measured via `/usr/bin/time` user+sys with
GOMAXPROCS=1 — MM1.1 cannot reach 8,000 rec/s on this hardware even on an
idle core (raw Ed25519 verify alone is ~4,300–5,000 ops/s per core).
Filed as **spec/CHANGE_REQUESTS/002-m16-perf-targets-vs-host.md** →
chunk marked `BLOCKED-CR-002`.

## Sabotage

`mutator-noop-class-5`: patch makes `class5_truncate` return the inputs
unmodified. The suite's byte-equality check flags every class-5 mutant as
"mutant identical to original" → C1.6.2 FAIL. Run log in
`../<sabotage-ts>/sabotage/`.
