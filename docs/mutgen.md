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
- `measure.py` — C1.6.3 measurements MM1.1–MM1.5 per `06` §12.
- `test/bench/csbench.go` — Go-side timing for MM1.1–MM1.3 (verify
  throughput, durable-append throughput, append latency).

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
