# Lane progress: fixtures

Rows follow 06-agent-loop.md §13. Host: agent-vpc (no Docker/Podman — cluster packaging deferred to oci-free-a1 per supervisor note).

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M0.3 | IN_PROGRESS | 1 | evidence/M0.3/20261114T165152Z | 13 checks green (incl. real git clone/push vs fakehub, real pip/npm install vs fakereg, byte-identical mockllm goldens); 2/2 sabotages caught; fixtures run as local processes — no Docker/Podman here, cluster packaging deferred to oci-free-a1; MCP pinned to current revision 2026-07-28 (upstream diff vs older assumptions — see evidence upstream/) |
