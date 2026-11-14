# Lane progress: evidence-py

Rows follow 06-agent-loop.md §13.

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M1.5 | DONE | 1 | evidence/M1.5/20261114T164037Z | `ref/python/refverify` implements V1–V11 + V15 from `03` + upstream only; C1.5.1/3/4/5 green 2x from clean (61/61 derived vectors, 2080 RFC 6962 proofs, C2SP note/checkpoint vectors); `py-skip-chain-check` sabotage caught by C1.5.5. C1.5.2 marked BLOCKED per lane note (csverify + C1.4.3 golden bundles not on main; differential activates when the Go lane lands). `go-skip-seal-check` is the Go lane's patch — not in this lane. MM1.5 median stored record size 1420 B (n=496, derived corpus). Added cffi pin (runtime dep of cryptography wheel, `--no-deps` install). |
