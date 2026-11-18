
## r4 boundary run (20261118T224459Z) — gate correct, floor unreachable

Suite-peak decay held 4/5 runs unqualified (samples 4.1-6.5 > 4 cores).
Run5 qualified at load 2.6-2.9 (all <= 4) → p99 36.8 ms — far over the 5 ms
bound. Note p50 5.8 ms at load ~2.7 vs p50 ~3.8 ms at load ~1.2: latency
degrades even at low CPU load, i.e. I/O contention from other tenants is
invisible to loadavg but still inflates p99. The 5 ms bound is unreachable
on this host whenever a run qualifies; the only passing outcome here is
`not judged: host contended` (all 5 runs unqualified), which CR-002
sanctions as open for G1.
