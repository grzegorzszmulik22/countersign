# Lane progress: evidence-go

Rows follow 06-agent-loop.md §13.

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M1.1 | DONE | 2 | evidence/M1.1/20261116T191937Z | review fix: C1.1.3 rejects dup keys at every depth + decoded-key identity (escapes, \/, surrogate pairs); 5/5 checks green; 3/3 sabotages caught; C1.1.5 = two 10-min fuzzes |
| M1.2 | DONE | 2 | evidence/M1.2/20261116T192726Z | review fix: C1.2.2 asserts eseq == prev+1 (wrong start, gap, repeat, decrease each rejected) + eprev mismatch; 5/5 checks green; 3/3 sabotages caught |
| M1.3 | DONE | 2 | evidence/M1.3/20261116T192729Z | review fix: C1.3.1 exact RFC 9162 proof length (truncated + extended rejected; last leaf, non-pow2); C1.3.2 recomputes+checks both roots; 5/5 checks green; 3/3 sabotages caught |
| M1.4 | DONE | 3 | evidence/M1.4/20261116T201445Z | reopened by supervisor review; ReadBundle now bounded (per-member 64 MiB / total 256 MiB / 4096 members, declared size ≤ bytes remaining, allocations only after checks), all non-EOF tar errors + trailing garbage → E_BUNDLE; deterministic non-fuzz tests for V1–V11 and V15 (TestC143_*, TestC147_*); writeTar propagates tar.Writer errors, nondeterministic-tar.patch regenerated for new signature; 6/6 sabotages caught incl. unbounded-tar-alloc and swallow-tar-errors; two consecutive clean check runs |
