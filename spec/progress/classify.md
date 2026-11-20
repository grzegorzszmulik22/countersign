# Lane progress: classify

Rows follow 06-agent-loop.md §13. Host: agent-vpc (no Docker/Podman).

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M5.2 | BLOCKED | 1 | evidence/M5.2/20261120T073225Z | broker wiring and C5.2.5 wait for M2.4 (lane broker2). Classifier scope green: internal/classify (05 §1 ordered rules, §2 strictest of autonomy/requires/whenTainted, declared_safe flag); ref/python/refclassify spec-derived, no Go imports; 257-row decision table test/vectors/policy/classes.yaml derived from spec text via test/gen/classes_table.py; 18 invalid policies (stager, class, tools, calls, autonomy, requires:intent); C5.2.1–C5.2.4 PASS (table 257/257 + 10,000-case Go/Python differential identical; no-rule→irreversible; ≥20 c523 strictest-wins rows; declared_safe survives the strict record codec + record schemas); 3/3 named sabotages caught (0 uncaught); go test ./... and make lint green. Deferred per lane note: recording class/decision.requires per effect and REVIEW_REQUIRED denial live in internal/proxy (M2.4). Decisions recorded: requires:intent stays rejected at validation until M9 enforcement lands (M9.3 TODO); requires:none is invalid per the 04 §1 enum and is treated as allow defensively in the classifier, matching refreconcile; rule 5 git reads require the grant's git-smart-http matcher to cover the repo, same reading as refreconcile; declared_safe flag limited to the spec's three cases (non-GET, tunnel, WebSocket). |

