# Lane progress: agent

Rows follow 06-agent-loop.md §13. Host: agent-vpc (Docker available; sandbox
image built for linux/arm64; no kind cluster on this host).

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M0.4 | DONE | 5 | evidence/M0.4/20261117T164941Z | 15 checks green (C0.4.1-C0.4.5 + image + lint + snap.* + tree.restored); 8/8 sabotage caught; lint green; reopened a fourth time: the suite edited tracked files and left untracked probes in the tree it tests, and nothing proved restoration — final design never writes the live tree at all: the snapshot is taken of the pristine tree, `snap.fidelity` proves SNAP equals it byte-for-byte (every ls-files path, symlink-aware, plus non-ignored untracked files), and the marker edits are injected into SNAP after capture so `snap.uncommitted`/`snap.untracked` prove the SNAP->image/binary half while `snap.capture` proves live->snap on a seeded scratch repo. `snap.post-snapshot` runs entirely against a scratch repo under $WORK (post-snapshot writes reach neither its snapshot nor a binary built from it, under a churn loop). `tree.restored` still guards the invariant — an EXIT/INT/TERM trap re-records `git status --porcelain -z -uall` plus sha256 manifests and FAILs on any drift incl. a surviving `.check-work/M0.4-<pid>` — and sabotages that write the live tree or skip work-dir removal go red on it (plus snap.*/lint where they change semantics); measurements.json: 6-sample warm replay 15-38 ms, cv reported unstable |
