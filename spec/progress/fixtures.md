# Lane progress: fixtures

Rows follow 06-agent-loop.md §13. Host: agent-vpc (no Docker/Podman — cluster packaging deferred to oci-free-a1 per supervisor note).

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M0.3 | IN_PROGRESS | 2 | evidence/M0.3/20261114T171118Z | 13 checks green (incl. real git clone/push vs fakehub, real pip/npm install vs fakereg, byte-identical mockllm goldens); 3/3 sabotages caught (added mockllm-accepts-wrong-tool-result after supervisor review: tests now assert rejection reasons for missing AND wrong tool-result content in all three shapes); also de-flaked check-M0.5 C0.5.4 (tooling race: ls -dt could pick a sabotage-only evidence dir — now reads the dir check-DUMMY1 reported); fixtures run as local processes — no Docker/Podman here, cluster packaging deferred to oci-free-a1; MCP pinned to current revision 2026-07-28 (upstream diff vs older assumptions — see evidence upstream/) |
