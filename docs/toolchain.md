<!-- Copyright 2026 The Countersign Authors
     SPDX-License-Identifier: Apache-2.0 -->

# Toolchain and repository layout (M0.1)

The repository builds and tests only with the pinned toolchain in
`tools/versions.env`. `make tools` installs everything into `./.tools/`
without root and verifies each download against the pinned sha256. Downloads
are kept in `~/.cache/countersign/tools` (override with `CS_TOOLS_CACHE`), so
installing into a fresh clone works offline once the cache is warm. Every
pinned tool has a `linux/arm64` build, matching the build hosts of
`06-agent-loop.md` §11.

Prerequisite on a fresh host: GNU `make` ≥ 4 and `curl` on `PATH` (the
scripts also look in `~/.local/bin` and `~/.local/usr/bin`). This host had no
`make`; it was installed in user space via
`apt-get download make && dpkg -x make_*.deb ~/.local` — no root needed.

## Layout

`02-architecture.md` §7, created up front with `.gitkeep` placeholders:
`cmd/` for the eight binaries, `internal/` packages per milestone,
`ref/python/` for the reference implementations, `api/`, `deploy/helm/`,
`test/{vectors,sabotage,fixtures,e2e,checks,dummy}`, `bench/`, `evidence/`,
`spec/`. The project name, API group and module path live only in
`internal/names/` (C0.1.4 enforces this).

## Make targets

| Target | Does |
|---|---|
| `make tools` | install/verify the pinned toolchain into `.tools/` |
| `make lint` | golangci-lint (gofmt/goimports enforcement), Apache-2.0 header check, progress-row lint |
| `make test` | `go build ./...` + `go test ./...` |
| `make clean` | remove `bin/`, `.check-work/`, Go test cache — never `.tools/` |
| `make sysinfo` | kernel, arch, CPU model, cores, memory, Docker version |
| `make check-<chunk>` | run `test/checks/check-<chunk>.sh`, tee output to `evidence/<chunk>/<UTC>/`, write `result.json` |
| `make sabotage-<chunk>` | apply each `test/sabotage/<chunk>/*.patch` to a scratch copy and require `check-<chunk>` to fail |
| `make regress` | verify `spec/FROZEN.sha256`, re-run checks of all `DONE` chunks |

Checks and sabotage evidence land under `evidence/<chunk>/<UTC timestamp>/`.
