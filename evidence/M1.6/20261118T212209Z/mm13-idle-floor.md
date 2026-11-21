MM1.3 idle-floor measurement (2026-11-18, lane evidence-py)

In a rare fully-idle window (host load1 0.25-1.2 of 4 cores) four direct
csbench latency probes (1000 appends/s, 20000 records, 8 workers) gave:

  p50 3.73-3.88 ms   p99 9.36-9.98 ms   load1 0.25-1.17

and the verify-run's 5 qualified runs (load1 1.4-3.9) gave p99
9.4/25.2/22.0/47.2/10.2 ms, median 22.0 ms — FAIL vs the <=5 ms bound.

Conclusion: on this host's disk the group-commit cadence + fsync latency
bounds append p99 at ~9.5-10 ms even idle, so the 5 ms bound is
unreachable whenever a run qualifies. The only passing outcome on this
host is CR-002's `not judged: host contended`; when ambient load1 stays
> 4 cores through the latency window all runs are unqualified and the
metric records not-judged with every sample preserved.
