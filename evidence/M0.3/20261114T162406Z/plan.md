# M0.3 plan

1. Fixtures live in `test/fixtures/{fxlib,fxres,echo,sink,fakehub,fakereg,fakemsg,mockllm,mcpdemo}` (library pkgs, `//go:build fixtures`) plus thin `test/fixtures/cmd/<name>` mains (`run()` split across fixtures/release stubs so `go build ./...` stays green without the tag).
2. `fxlib`: test root CA (gen-or-load under `--ca-dir`), TLS serving, `__observed`/`__state`/`__reset` admin endpoints, CONNECT proxy + dial override (`fxres`) mapping realistic hostnames (github.com, pypi.org, api.anthropic.com, api.slack.com, mcp.example.com, …) to local listeners.
3. `fakehub` shells out to stock `git http-backend`; seeded bare repos `acme/widgets`, `attacker/loot`; token auth; REST issues/comments/PRs/releases with ETag/If-Match; `__admin` third-party ref/resource changes + pre-receive hook slot.
4. `fakereg`: PEP 503 simple index + wheel/sdist serving; npm metadata + tarballs; `evilpkg` runs a configurable command at install; docs page with injectable string. Self-test uses real `pip`/`npm` via the CONNECT proxy + test CA.
5. `mockllm`: scenario transcript (`test/vectors/transcripts/reference.scenario.json`) served per-turn in three API shapes; validates carried tool results; `/v1/files`; `--variant`/`--conditional`/`--flaky` modes; goldens at `reference.<shape>.golden` (MCP pinned to 2026-07-28 upstream — see upstream/).
6. `sink`: HTTPS/HTTP/TCP/UDP/DNS(UDP+TCP)/ICMP listeners recording exact bytes; ICMP probed for CAP_NET_RAW → SKIPPED-ENV on this host if absent.
7. Checks first: `test/checks/check-M0.3.sh` emits CHECK lines for C0.3.1–C0.3.5; Go self-tests under `-tags fixtures`; C0.3.4 via `go list` gating + `go tool nm` on release binaries.
8. Sabotages: `sink-drops-udp`, `fixtures-in-release` under `test/sabotage/M0.3/`; docs page `docs/fixtures.md`.
