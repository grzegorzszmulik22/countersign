# Lane progress: agent

Rows follow 06-agent-loop.md §13. Host: agent-vpc (Docker available; sandbox
image built for linux/arm64; no kind cluster on this host).

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M0.4 | DONE | 5 | evidence/M0.4/20261117T164941Z | 15 checks green (C0.4.1-C0.4.5 + image + lint + snap.* + tree.restored); 8/8 sabotage caught; lint green; reopened a fourth time: the suite edited tracked files and left untracked probes in the tree it tests, and nothing proved restoration — fixed: the suite now records `git status --porcelain -z -uall` plus sha256 manifests of every tracked and non-ignored untracked file before it runs, and an EXIT/INT/TERM trap re-records and diffs after cleanup; `tree.restored` reports FAIL on any drift (status lines, content hashes, per-run `.check-work/M0.4-<pid>` dir). New `snap.capture` runs the snapshot routine on a scratch repo seeded with uncommitted/untracked/ignored/.check-work content to prove the mechanism even in a clean tree, and `snap.fidelity` verifies SNAP equals the recorded snapshot-instant state for every ls-files path and captured untracked file. Sabotages that drop the agent.go restore, leave a probe file, or skip the work-dir removal all go red on tree.restored, proven applied uncommitted and under SIGTERM; measurements.json: 6-sample warm replay 15-38 ms, cv reported unstable |
