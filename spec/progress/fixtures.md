# Lane progress: fixtures

Rows follow 06-agent-loop.md §13. Host: agent-vpc (no Docker/Podman — cluster packaging deferred to oci-free-a1 per supervisor note).

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M0.3 | DONE | 3 | evidence/M0.3/20261114T214704Z | 13 checks green (incl. real git clone/push vs fakehub, real pip/npm install vs fakereg, byte-identical mockllm goldens); 4/4 sabotages caught (mockllm-accepts-wrong-tool-result, fakehub-drops-token, fixtures-in-release, sink-drops-udp); supervisor-review hardening: C0.3.1.fakehub sweeps every observation asserting recorded token == token presented (accepted + rejected git smart-HTTP and REST, nonexistent repo), rejected auth now records the presented token; all ~20 previously-ignored json.Unmarshal/Decode sites handled (fixture servers 400 malformed bodies; tests Fatalf; sniffers flag unparseable); also de-flaked check-M0.5 C0.5.4 earlier (tooling race); fixtures run as local processes — no Docker/Podman here, cluster packaging deferred to oci-free-a1; MCP pinned to current revision 2026-07-28 (upstream diff vs older assumptions — see evidence upstream/) |
