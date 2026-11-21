# Change request 004 — C3.5.3 `-race` vs a host with no C compiler

**Status:** ACCEPTED 2026-11-21 by supervisor (C3.5.3 `-race` requires a C compiler; SKIP on `free-a1` listed in `tools/env-skips.txt`, runs on `agent-vpc`).
**Raised with:** `make regress` inside `.lane/verify.sh` on oci-free-a1,
plus a direct probe reproducing both arms.

## What

`test/checks/check-M3.5.sh` job `C3.5.3` runs
`go test -tags fixtures -race -count=200 ./internal/proxy`. On
oci-free-a1 there is no C compiler (`cc`/`gcc`/`clang` all absent) and
Go reports `CGO_ENABLED=0`, so the job fails with
`go: -race requires cgo; enable cgo by setting CGO_ENABLED=1` and the
suite exits 1. Because `C3.5.3` is not listed in
`tools/env-skips.txt` for this host and the suite prints FAIL (not
SKIP), `make regress` fails — and with it `.lane/verify.sh` — on this
host regardless of lane state.

This is the same class of gap already dispositioned for `race.runner`
in `check-M2.7.sh`: that job probes `command -v cc|gcc|clang`, reports
SKIP when none exists, and is allowlisted for free-a1 in
`tools/env-skips.txt` (row added by the supervisor, 2026-11-20).
`C3.5.3` needs the equivalent pair:

1. a probe in `job_C3.5.3` that prints the SKIP path when no C compiler
   exists (same `no C compiler; -race unsupported here` convention), and
2. a `C3.5.3 free-a1 …` row in `tools/env-skips.txt` citing pass
   evidence where a compiler exists.

Both files are outside this lane's scope (`env-skips.txt` is
supervisor-only; `check-M3.5.sh` belongs to the M3.5 lane), so the need
is recorded here per the review note's instruction.

## Evidence the check passes where a compiler exists

- This host, 2026-11-20 earlier runs: with `CC=zig CGO_ENABLED=1` in the
  user go env (since removed by the supervisor), `check-M3.5` ran the
  `-race -count=200` job for real and passed inside `make regress`
  (verify run of that day: `check-M3.5: PASS`).
- `race.runner` under `-race` **fails** on this host even with a
  compiler present — its own tests need the unprivileged userns this
  kernel denies (`apparmor_restrict_unprivileged_userns=1`), which is
  why simply installing a `cc`/`gcc` shim cannot resolve the conflict:
  it flips `race.runner` from SKIP to RUN to FAIL. Verified by direct
  run: `go test -race -tags fixtures -count=1 ./internal/runner` → 8
  failures, all `unprivileged user namespaces unavailable`. The only
  consistent disposition on free-a1 is SKIP for both `-race` jobs.

## Alternatives considered

- **Install a user-level `gcc` (zig cc) on `~/.local/bin`:** makes
  C3.5.3 run, but `race.runner`'s probe then runs its suite under
  `-race` and it fails on the userns gap — a relocated regress
  failure. Rejected.
- **Skip the suite via `CS_CHECK_RUNNING`:** env-only dodge; a bare
  supervisor verify would still fail. Rejected.
- **Record only:** leaves `make regress` red on this host for every
  lane's verify. Kept as the fallback — this CR is the escalation.
