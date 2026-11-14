# Plan M0.5 — check, sabotage and evidence tooling

- Harness already landed with M0.1: tools/{check,sabotage,regress,verify-frozen,lint-progress}.sh and make targets.
- New files: spec/FROZEN.sha256 (pins spec/0*.md + spec/milestones/*.md, "from the start" per 06 §7),
  test/dummy/greeting.txt, test/checks/{DUMMY1,DUMMY2}.sh (self-test chunks for the harness),
  test/sabotage/{DUMMY1,DUMMY2}/corrupt-greeting.patch, test/checks/check-M0.5.sh,
  test/sabotage/M0.5/sabotage-runner-always-green.patch, docs/check-tooling.md.
- DUMMY1: suite reads greeting.txt; its sabotage corrupts it -> caught. DUMMY2: suite passes without
  reading it; same sabotage -> uncaught, sabotage runner must exit non-zero and name the patch.
- Checks: C0.5.1 DUMMY1 check+sabotage green; C0.5.2 DUMMY2 sabotage non-zero naming patch;
  C0.5.3 one-byte change to a FROZEN-listed file -> make regress fails, restore verifies;
  C0.5.4 DUMMY1 evidence dir holds command/exit/duration/git commit/full output.
- Sabotage: sabotage-runner-always-green (patch tools/sabotage.sh to exit 0) -> C0.5.2 fails.
- First test: test/checks/check-M0.5.sh asserting all four; then the sabotage patch; then implement.
