# M0.4 iteration 2 — fix parallel-run isolation (reopened by supervisor)

Supervisor reopened M0.4: "image build races with parallel regress". The check
suite built the image under the fixed tag cs-sandbox-m04:local and used the
fixed .check-work/M0.4 directory — daemon-global and same-worktree shared
state. A parallel run (regress re-running M0.4, or the sabotage scratch which
builds the SAME tag with a patched agent) could overwrite the image mid-run.

Fix in test/checks/check-M0.4.sh + scriptagent/Dockerfile:
- unique image tag per invocation (PID-scoped), removed on cleanup;
- docker build context becomes the per-run work dir ($WORK), so the
  Dockerfile COPYs bin/scriptagent and no longer depends on repo root;
- $WORK becomes PID-unique (.check-work/M0.4-<pid>) so two concurrent
  same-worktree runs cannot clobber each other;
- drop .dockerignore (context no longer the repo).

Verify: make check-M0.4 twice from make clean, two parallel direct runs of the
script green, sabotage still caught, lint+regress green, DONE row attempt 2.
