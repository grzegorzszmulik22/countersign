# Lane progress: matchers

Rows follow 06-agent-loop.md §13. Host: agent-vpc (no Docker/Podman).

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M3.6 | DONE | 1 | evidence/M3.6/20261115T163628Z | git-smart-http matcher of 04 §2: exact owner/repo scoping (.git suffix optional on wire and in repos entries), read = info/refs?service=git-upload-pack + POST git-upload-pack, write adds receive-pack; 74 gitm decision-table rows (C3.6.4 ≥30); real git through test/gateproxy CONNECT gate vs fakehub (C3.6.1/3.6.2 — no broker data plane yet, same posture as M3.1 ahead of M2); unknown service/extra segments/traversal/percent/case/nested/prefix rejects (C3.6.3); 4/4 sabotages caught incl. 2 added beyond spec (git-prefix-repo-match, git-any-service-on-info-refs); regress green incl. M3.1 fuzz |
