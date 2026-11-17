# Change request 002 — M1.6 performance targets vs lane host capability

**Status:** draft — filled with the official 5-run samples before filing.

## What

Relax or re-base the `[T]` targets MM1.1–MM1.3 of milestone M1
(spec/milestones/M1-evidence-core.md) so they are expressed per unit of
host capability, or accept the measured values on this lane's host as the
recorded numbers.

| metric | spec target | what the lane host delivers |
|---|---|---|
| MM1.1 verify throughput, one core | >= 8,000 rec/s | TBD (samples below) |
| MM1.2 durable append, group commit | >= 5,000 rec/s | TBD |
| MM1.3 append p99 at 1,000/s | <= 5 ms | TBD |

## Why (data)

Host is agent-vpc (see `make sysinfo` dump in the M1.6 evidence folder):
aarch64 Neoverse-N1, 4 cores, shared tenancy — loadavg was 20–50 during
the whole session, i.e. sustained oversubscription 5–10x.

Raw Ed25519 verify on this host measures ~850 ops/s (20000 samples,
crypto/ed25519 stdlib). One record verification is dominated by that
signature cost plus strict-JSON decode; the measured bundle rate tracks
the signature rate almost 1:1, so MM1.1's 8,000/s needs ~10x the per-core
crypto throughput this VM provides. MM1.2's append path decodes each
record line before writing, so it scales with the same CPU ceiling;
MM1.3's p99 is set by fsync cadence plus scheduler latency under load —
p50 is already ~10 ms when the box is this contended.

Samples (median / all runs / CV) are in
`evidence/M1.6/<ts>/measurements.json`.

## Alternatives

- Re-run on a quiet machine — not available inside this lane.
- Report unstable (CV > 10% per 06 §12) and keep targets — still fails.
- Optimize `internal/ledger`/`internal/evidence` — owned by another lane
  and would not close a 10x crypto gap on this VM anyway.

## Effect on properties/headline numbers

None on the format or verifier semantics; only the three [T] performance
targets move to host-referenced values.
