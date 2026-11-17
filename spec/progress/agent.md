# Lane progress: agent

Rows follow 06-agent-loop.md §13. Host: agent-vpc (Docker available; sandbox
image built for linux/arm64; no kind cluster on this host).

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M0.4 | IN_PROGRESS | 4 | evidence/M0.4/20261117T000209Z | 11 checks green (C0.4.1-C0.4.5 + image + lint + 4 snap.*); 5/5 sabotage caught (incl. sequential-tools -> C0.4.2, rogue-extra-twice -> C0.4.4); lint+regress green; reopened a third time: `git archive HEAD` tested the last commit, not the tree under test — fixed: snapshot now captures the working tree via a temporary index (`git add -A` + `git write-tree` + `git archive`), so uncommitted edits and untracked files reach the image while ignored files stay out; proven: each of sequential-tools and rogue-extra-twice applied to the live tree WITHOUT a commit failed its own check (C0.4.2 / C0.4.4, not only lint); new snap.* checks prove an uncommitted source edit and a needed untracked file reach the image, post-snapshot edits do not, and concurrent writers cannot break docker build; measurements.json: 6-sample warm replay 15-38 ms, cv reported unstable |
