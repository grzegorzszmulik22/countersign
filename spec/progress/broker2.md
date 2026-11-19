# Lane progress: broker2

Rows follow 06-agent-loop.md §13.

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M2.4 | DONE | 1 | evidence/M2.4/20261119T034526Z | write-ahead evidence: effect.http durable before first upstream byte (100k ordering proof), 200xSIGKILL crash proof with incremental ledger scan, fail-closed on append error/slow-append>500ms/read-only store (502 LEDGER_UNAVAILABLE, 0 upstream hits), exact deny counts incl conn-level smuggling attribution, 100k count equality + eseq order; real ledger sink, broker/controller/world emitters sealed, bundle exported, csverify + Python refcheck both CLEAN. Ledger.Line index fixed O(N^2)->O(N) restart scans. 5/5 sabotages caught (incl eseq-out-of-lock) |
| M2.5 | DONE | 1 | evidence/M2.5/20261119T034730Z | conn-level head inspector (CL+TE, dup CL, obs-fold, bare LF, malformed Connection tokens, 64KiB cap, banned path forms) before grant eval; h1 keep-alive off so pipelined heads can't slip; 61-vector smuggling corpus with upstream-target==recorded path/query byte fidelity; resolve-once + rebinding resistance + range blocks + cluster opt-in + upstream.ip==dialled; WebSocket upgrade gated by grant (PROTOCOL_DENIED else), 101+frames relayed with counted bytes; CONNECT passthrough relays opaque TLS, SNI recorded, no leaf; isolation under 256-conn flood (B p99 unchanged); 2x10min fuzz clean. 7/7 sabotages caught |
