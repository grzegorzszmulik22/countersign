# Lane progress: agent

Rows follow 06-agent-loop.md §13. Host: agent-vpc (Docker available; sandbox
image built for linux/arm64; no kind cluster on this host).

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M0.4 | DONE | 3 | evidence/M0.4/20261116T124842Z | 7 checks green (C0.4.1-C0.4.5 + image + fixtures-tagged lint); 3/3 sabotage caught (agent-ignores-tool-result, mockllm, image-built-from-live-tree -> C0.4.1 red); lint+regress green; reopened twice: (1) image-tag/work-dir races with parallel regress — fixed with PID-scoped tag/net/vol/containers/.check-work; (2) live-tree docker context raced parallel regress — fixed: image builds from immutable `git archive HEAD` snapshot; proven by 2x green `make regress` from a clean clone on this host; measurements.json: 6-sample warm replay 15-38 ms, cv reported unstable |
