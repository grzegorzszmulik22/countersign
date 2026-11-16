# Lane progress: agent

Rows follow 06-agent-loop.md §13. Host: agent-vpc (Docker available; sandbox
image built for linux/arm64; no kind cluster on this host).

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M0.4 | DONE | 2 | evidence/M0.4/20261116T124842Z | 7 checks green 2x from clean (C0.4.1-C0.4.5 + image + fixtures-tagged lint); 1/1 sabotage caught (agent-ignores-tool-result -> C0.4.1 red); lint+regress green; reopened once for image-tag/work-dir races with parallel regress — fixed: tag, net, vol, containers and .check-work dir are PID-scoped per run; measurements.json: 6-sample warm replay 15-38 ms, cv reported unstable |
