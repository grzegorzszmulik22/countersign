# Lane progress: runner

Rows follow 06-agent-loop.md §13.

| chunk | status | attempts | last evidence folder | note |
|---|---|---|---|---|
| M2.7 | IN_PROGRESS | 1 | evidence/M2.7/20261118T093526Z | local runner `cs run`: enforced user+mount+net+pid namespaces with loopback-only netns, in-ns relay over parent unix socket to the broker, tmpfs-covered data dir, fresh /proc, ambient env over inherited pipe (not init's environ), csph_ placeholders only; cooperative mode records boundary: cooperative on session.open and csverify prints it; SIGINT->grace->SIGKILL reaps the agent tree via pid-1 Wait4; sealed bundle verifies in csverify and the independent Python refcheck. 5/5 sabotages caught |
