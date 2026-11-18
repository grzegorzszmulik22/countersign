# Lane progress: reconcile-go

Rows follow 06-agent-loop.md §13. Host: agent-vpc (no Docker/Podman).

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M9.2 | DONE | 2 | evidence/M9.2/20261118T094940Z | After supervisor reopen: (1) every recorded decision field tampered one at a time on re-signed bundles × enforce/audit/learn — action, reason, grant, requires→F_CLASS_MISMATCH, credentials→F_CREDENTIAL_SCOPE, would_deny dropped/changed in audit (deny, hold, NO_GRANT and abstract object forms) → F_DECISION_MISMATCH (C9.2.4); (2) V16 fails closed — injected ledger.ReadBundle and engine errors append E_BUNDLE/E_POLICY and force INVALID, never CLEAN (C9.2.5); (3) no discarded output writes — verify/explain/reconcile-batch/-corpus route stdout through checked writers, failing writer exits non-zero (C9.2.5). New sabotages fail the suite: decision-compare-skips-would-deny (C9.2.4), reconcile-read-error-passes-clean + reconcile-batch-drops-write-errors (C9.2.5); 6/6 sabotages caught. Corpus 198/198, MM9.1 10000/10000 identical, MM9.2 711/711 planted flagged |
