# Change request 002 — M1.6 performance targets vs lane host capability

**Status:** ACCEPTED 2026-11-18 by the human ("Re-base per core"). Applied to `milestones/M1-evidence-core.md` (MM1.1–MM1.3, C1.6.3) and `FROZEN.sha256` by the supervisor.
**Raised by:** lane `evidence-py`, 2026-11-17, with five raw runs per metric (`evidence/M1.6/20261117T171815Z/` on that lane).

## What

Relax or re-base the `[T]` targets MM1.1–MM1.3 of milestone M1
(spec/milestones/M1-evidence-core.md) so they are expressed per unit of
host capability, or accept the measured values on this lane's host as the
recorded numbers.

| metric | spec target | measured (wall) | per-core CPU capability |
|---|---|---|---|
| MM1.1 verify throughput, one core | >= 8,000 rec/s | median 496 rec/s (5 runs: 597, 516, 496, 377, 409; cv 0.18) | ~3,207 rec/s |
| MM1.2 durable append, group commit | >= 5,000 rec/s | median 1,706 rec/s (5 runs: 1821, 916, 1506, 1753, 1706; cv 0.24) | ~7,353 rec/s |
| MM1.3 append p99 at 1,000/s | <= 5 ms | median 35.7 ms (5 runs p99: 34.0, 38.2, 36.4, 30.2, 35.7; p50 ~7.9 ms) | — |

## Why (data)

Host is the lane build box (see `make sysinfo` dump in
`evidence/M1.6/20261117T171815Z/`): aarch64 Neoverse-N1, 4 cores, shared
tenancy — loadavg 20–40 sustained during all runs (5–10x oversubscription).

Where the time goes (per `/usr/bin/time` user+sys, GOMAXPROCS=1):

- **MM1.1**: verifying 6,126 records consumed 1.91 s CPU → ~3,207 rec/s on
  a whole core, i.e. the target is unreachable on this hardware *even at
  100% of one core*. Raw `crypto/ed25519` verify on this box is
  ~4,300–5,000 ops/s per core — signature verification alone consumes
  ~60%+ of the 8,000 rec/s budget before any JSON/DSSE/Merkle work.
- **MM1.2**: 40,000 durable appends consumed 5.44 s CPU → ~7,353 rec/s of
  per-core capability; the ~1,700 rec/s wall figure is the process
  receiving ~27% of a core. The append path could plausibly meet target
  on an idle machine; it cannot be demonstrated here.
- **MM1.3**: p50 is already ~7.9 ms (> the 5 ms p99 target) — group-commit
  cadence + fsync + scheduler latency under oversubscription. p99 30–38 ms.

Full raw samples, commands, CVs:
`evidence/M1.6/20261117T171815Z/measurements.json`.

## Alternatives

- Re-run on a quiet machine — not available inside this lane (single
  shared build host; contention sustained for the entire session).
- Report unstable (CV > 10% per 06 §12) and keep targets — MM1.1/MM1.2 are
  already unstable *and* below capability; reporting unstable does not
  make them pass.
- Optimize `internal/ledger`, `internal/evidence`, `internal/keys` —
  owned by another lane, and cannot close a 2.5x per-core crypto gap.
- Re-express targets per-core-second or per host class — this request.

## Effect on properties/headline numbers

None on the format, the evidence chain, or verifier semantics; only the
three `[T]` performance targets move to host-referenced values (or are
re-confirmed with a noted host requirement, e.g. "on a dedicated
<core-class> core"). MM1.4 and MM1.5 are unaffected and pass.

## Decision

The targets were written without naming a machine. On the build hosts (aarch64 Neoverse-N1, shared) they measure the host, not the code: one Ed25519 verification costs this core 200–230 µs, so MM1.1 at 8,000 records/s is out of reach at 100% of an idle core. Each target is now stated per core of the machine that runs it, calibrated in the same run:

- **MM1.1** Go verification throughput, signatures included, in records per CPU-second of one core (`GOMAXPROCS=1`, user+sys CPU time): **≥ 50% of the same core's raw Ed25519 verification rate**, measured by a calibration loop in the same run and printed beside it. Why 50%: every record carries at least one signature, so the raw rate is the ceiling, and the original 8,000 records/s is about half the Ed25519 rate of a current x86 server core. The absolute records/s (CPU and wall) is still reported.
- **MM1.2** Durable append throughput, single writer, group commit: **≥ 5,000 records per CPU-second of the writer** (user+sys), **and** at most one fsync per 10 records (group commit must group). Wall throughput is reported beside it.
- **MM1.3** Append latency at 1,000 appends/s: **p99 ≤ 5 ms**, judged only on runs during which the host's 1-minute load average stayed at or below its core count (sampled every second and recorded). Latency under an oversubscribed scheduler measures the other tenants. Every run is reported. If no run qualifies, the result is recorded as `not judged: host contended` with all samples, C1.6.3 passes on the other targets, and MM1.3 is listed as open for gate G1, where the human decides whether to run it on a quiet machine.

Unchanged: the `06` §12 rules (≥ 5 runs, all samples, median, CV, never the best run), MM1.4, MM1.5, and every check other than C1.6.3's wording.

## Effect

M1.6 can finish on the build hosts without weakening what the targets were for. A slow verifier or a per-record fsync still fails. G1 gets one open measurement instead of a blocked chunk.
