# Lane progress: evidence-py

Rows follow 06-agent-loop.md §13.

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M1.5 | DONE | 2 | evidence/M1.5/20261114T164037Z | `ref/python/refverify` implements V1–V11 + V15 from `03` + upstream only. C1.5.1/3/4 green; C1.5.2 PASS for real — all 17 golden bundles byte-identical to csverify after normalization (verdict, world, error+warning code sets, stats); every csverify rejection on goldens is made by Python. C1.5.5 65/65 derived vectors incl. index/records count mismatch in both directions and entry-level disagreement (E_BUNDLE). Sabotages caught: `py-skip-chain-check` (C1.5.2+C1.5.5), `go-skip-seal-check` (C1.5.2 differential). MM1.5 median stored record size 1420 B (n=496, derived corpus). |
| M1.6 | IN_PROGRESS | 1 | evidence/M1.6/ | mutgen: seeded generator (1–3 emitters, 5–500 records, deterministic ULIDs); mutate: 9 classes + directed extras; run_suite differential driver. Detection rule: non-clean verdict in both + identical error/warning code sets + first error in the §11 expected set (cascade codes recorded; verdict alone never counts). Medium run: 135/135 detected+agreed. Pending: full C1.6.1/C1.6.2 at spec scale, MM1.1–MM1.3 measurements (host heavily loaded, may need [T] change requests), mutator-noop-class-5 sabotage run. |
