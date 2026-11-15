# Lane progress: evidence-go

Rows follow 06-agent-loop.md §13.

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M1.1 | DONE | 1 | evidence/M1.1/20261114T181132Z | 5/5 checks green 2x from clean; 3/3 sabotages caught; C1.1.5 = two 10-min fuzzes |
| M1.2 | DONE | 1 | evidence/M1.2/20261114T193707Z | 5/5 checks green 2x from clean; 3/3 sabotages caught |
| M1.3 | DONE | 1 | evidence/M1.3/20261114T194142Z | 5/5 checks green 2x from clean; 3/3 sabotages caught |
| M1.4 | DONE | 2 | evidence/M1.4/20261115T173652Z | reopened by supervisor review; ReadBundle now bounded (per-member 64 MiB / total 256 MiB / 4096 members, declared size ≤ bytes remaining, allocations only after checks), all non-EOF tar errors + trailing garbage → E_BUNDLE; deterministic non-fuzz tests for V1–V11 and V15 (TestC143_*, TestC147_*); 6/6 sabotages caught incl. unbounded-tar-alloc and swallow-tar-errors; two consecutive clean check runs |
