# Lane progress: reconcile-ref

Rows follow 06-agent-loop.md §13. Host: agent-vpc (no Docker/Podman).

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M9.1 | DONE | 1 | evidence/M9.1/20261116T104002Z | ref/python/refreconcile implements 04 §5–§7 + 05 §1–§2/§12 (stdlib only, no internal/ imports; match.py untouched); 198 hand-derived traces (floor 80) cover the whole M9.1 matrix incl. window edges, ts/log-order inversions, local/provider/parallel intents, every §6.2 row ±, §6.3 exact/mismatch/repeat/name, every §7.3 check, enforce/audit/learn; C9.1.1 198/198, C9.1.2 96.85% statement coverage (uncovered lines listed in evidence), C9.1.3 10,000 random traces accepted; 2/2 sabotages caught (window-uses-timestamps -> b0x/d03/j35 flip NONE->WINDOW, local-class-authorizes-network -> c01/c02 flip); packs as data under internal/reconcile/packs/ (the only internal/ path written) |
