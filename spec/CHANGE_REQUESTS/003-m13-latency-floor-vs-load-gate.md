# Change request 003 — MM1.3: host latency floor vs the load-qualification gate

**Status:** RAISED 2026-11-19 by lane `evidence-py`.
**Raised with:** six check-M1.6/verify measurement runs plus direct idle
probes (`evidence/M1.6/20261118T200837Z/`, `20261118T212209Z/`,
`20261118T221551Z/`, `20261118T224459Z/`, `20261118T230103Z/`,
`20261119T032605Z/`), AND the supervisor's own verify run of
2026-11-19 (~03:30Z), which hit the same wall: 4 of 5 runs qualified at
load 1.5–3.9 and were judged, p99 10.1–14.2 ms →
`CHECK C1.6.3 FAIL`. The lottery fails for every runner of the check on
this host, including the supervisor — it is not specific to this lane's
timing.

## What

CR-002 re-stated MM1.3 as: p99 ≤ 5 ms, judged only on runs whose every
per-second loadavg sample stayed ≤ core count; if no run qualifies the
result is recorded `not judged: host contended` and deferred to G1.

On this lane host the load gate produces only two outcomes, never a
judged pass:

- ambient load > 4 through the sampling window → all runs unqualified →
  `not judged: host contended` (the outcome CR-002 intended);
- ambient load ≤ 4 → runs qualify → **guaranteed miss**, because this
  host's append p99 floor is ~9.5–10 ms at idle and 25–37 ms under
  boundary load — always above the 5 ms bound.

The measured floor is a property of the disk's group-commit cycle
(commit cadence + fsync ≈ 8–10 ms on this filesystem), not of scheduler
contention: at loadavg ≈ 0.5–1.2 with nothing else running, direct
probes show p50 ≈ 3.7–3.9 ms and p99 ≈ 9.4–10.0 ms. CR-002's own data
(table line: median p99 35.7 ms, p50 ~7.9 ms) already showed the bound
unreachable here; the load gate only decides *whether* the miss is
recorded as a judgment or a deferral, and that now depends on ambient
tenancy luck rather than on the code.

## Why (data)

Seven consecutive qualified-run misses on this lane host (six by this
lane, one by the supervisor's own verify run):

| run | qualified runs | judged p99 |
|---|---|---|
| verify attempt (19:5xZ) | 1 | 8.9 ms |
| verify attempt (21:1xZ) | 5 | median 22.0 ms (9.4–47.2) |
| check r3 (21:5xZ) | 5 | median 10.0 ms |
| check r4 (22:44Z) | 1 | 36.8 ms |
| check r5 (23:01Z) | 4 | median 10.6 ms |
| check r6 (23:36Z) | 5 | median 11.2 ms |
| **supervisor verify (03:30Z)** | **4** | **10.1–14.2 ms** |

Two passes were also recorded when ambient stayed > 4 cores
(check-M1.6 20261119T000134Z and verify 20261119T020216Z): every run was
unqualified → `not judged: host contended`. Passing requires ambient
tenancy luck at the moment each embedded suite runs, for every runner.

Idle probes (`mm13-idle-floor.md`): p99 9.36–9.98 ms at load 0.5–1.2.
Every qualified run on this host misses; no sample has ever come near
5 ms. MM1.1, MM1.2, MM1.4, MM1.5 all pass (ratios 0.58–0.59 vs same-run
calibration; ~7,200–7,800 rec/CPU-s writer; fsync/record 0.032 by exact
strace count).

## Alternatives

- Keep retrying until ambient load holds > 4 through every embedded
  sampling window — completion then depends on shared-tenancy luck, not
  on the code (current state; ambient has sat ~1–3 for ~1.5 h).
- Optimize `internal/ledger`'s commit path — owned by another lane, and
  the floor is the disk's fsync cost, not CPU.
- Amend MM1.3 per this request.

## Requested decision

Either:

1. Re-base MM1.3 for this host class, the way MM1.1 was re-based per
   core — e.g. p99 ≤ k × the measured group-commit period, calibrated
   in the same run; or
2. Accept a third recorded outcome, `not judged: host floor above
   bound`, reported with all samples when qualified runs miss (same G1
   deferral as `not judged: host contended`); or
3. Confirm the ambient-load lottery is the intended mechanism, in which
   case this lane simply re-runs until a contended window lands.

## Effect on properties/headline numbers

None on the format, the evidence chain, verifier semantics, or the
mutation suite; only MM1.3's unreachable-on-this-host bound is at
issue. MM1.1/MM1.2 remain enforced per CR-002.
