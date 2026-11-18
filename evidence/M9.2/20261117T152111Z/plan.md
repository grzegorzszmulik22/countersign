# M9.2 plan — Go reconciliation engine + V16 in csverify

Files to touch (lane scope only):
- `internal/reconcile/`: new engine — canon.go (RFC 8785), trace.go (abstract
  trace parser), grants.go (04 §2 select + 05 §1 class + 05 §2 condition),
  expect.go (04 §6.2 rule interpreter over internal/reconcile/packs/*.json),
  engine.go (04 §5–§7 semantics, §6.5 comparison, verdict lattice of 03 §10),
  query.go (literal vs digested queries), bundle.go (bundle members -> abstract
  records: query_sha256/query_len -> digest comparisons, input_preview -> input
  when it re-canonicalizes to input_sha256).
- `cmd/csverify/main.go`: `--reconcile` (V16: findings -> VIOLATIONS between
  LEARN and CLEAN_WITH_DENIALS), `explain <bundle> --keys K <effect_id>`,
  `reconcile-trace FILE` and `reconcile-batch FILE` (corpus/differential IO).
- `test/gen/recongen.py`, `test/gen/reconcmp.py`: seeded trace generation
  (refreconcile.randgen) + python-side expected results + comparers for
  MM9.1 (10k traces) and MM9.2 (>=500 audit traces w/ planted unattributed).
- `test/checks/check-M9.2.sh`: C9.2.1 corpus, C9.2.2 differential, C9.2.3
  unattributed plants, C9.2.4 tampered re-signed bundles (Go test in
  cmd/csverify), C9.2.5 verdict lattice cases.
- `test/sabotage/M9.2/`: verifier-trusts-broker-attribution,
  exact-match-ignores-access-level, mcp-intent-reusable.
- `spec/progress/reconcile-go.md`, `docs/csverify-reconcile.md`.

Checks first: check-M9.2.sh runs corpus via `csverify reconcile-corpus`,
differential via python driver + `csverify reconcile-batch`, bundle tamper
matrix via `go test ./cmd/csverify`. First test written: corpus runner —
fail until engine exists. Engine is written from 04/05/03 text (semantics
pinned by the frozen corpus + MM9.1 differential vs refreconcile).
