# M9.1 plan — reference reconciler (Python) + trace corpus

- Files: `ref/python/refreconcile/{__init__,canon,grants,rules,expect,reconcile,trace,corpus,randgen}.py` (stdlib only; `match.py` untouched); packs as JSON under `internal/reconcile/packs/`; `test/checks/check-M9.1.sh`; `test/sabotage/M9.1/`; `test/vectors/reconcile/*.jsonl`; `docs/refreconcile.md`; `spec/progress/reconcile-ref.md`.
- Trace format: JSONL, one JSON object per record body; first line `trace.meta` carrying policy, contracts, derivation note and `expect` block.
- Engine: log-order intent windows (never `ts`; timeout closes via `intent.result{closed_by:timeout}`); levels CONTROL/EXACT/WINDOW/STANDING/NONE per 04 §6.1; §6.3 tools/call exact-or-NONE, one intent one call; §6.2 expectation rules from pack data; §7 contract checks (startup grace uses `ts`, call windows use log order); decision per 05 §2 + mode; findings + verdict lattice of 03 §10.
- Checks first: `check-M9.1.sh` runs corpus→expect (C9.1.1), settrace statement coverage ≥95% (C9.1.2), seeded randgen 10k accepted (C9.1.3); confirm they fail before implementation completes.
- Sabotages: `window-uses-timestamps`, `local-class-authorizes-network` (+ extras: tools/call-as-window, reusable intent, result-inclusive window edge) — each must turn a check red.
- Corpus: ~95 hand-derived traces covering every required matrix cell (levels×conditions, window edges incl. ts/log skew, classes, packs ±, §6.3, §7, modes, findings paths).
