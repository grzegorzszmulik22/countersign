<!-- Copyright 2026 The Countersign Authors
     SPDX-License-Identifier: Apache-2.0 -->

# Check, sabotage and evidence tooling (M0.5)

Every chunk has a check suite at `test/checks/check-<chunk>.sh` that prints
one `CHECK <id> PASS|FAIL` line per numbered check and exits non-zero on any
failure.

| Command | Behaviour |
|---|---|
| `make check-<chunk>` | Runs the suite, tees output to `evidence/<chunk>/<UTC>/output.log`, writes `result.json` (command, exit code, duration, git commit, dirty flag) and a `sysinfo.txt` snapshot. |
| `make sabotage-<chunk>` | Applies every `test/sabotage/<chunk>/*.patch` to a scratch copy of the repo (committed there with a throwaway identity), runs `check-<chunk>`, and requires a non-zero exit. Reports which check IDs caught each sabotage; exits non-zero naming any uncaught patch (06 §4). |
| `make regress` | Verifies `spec/FROZEN.sha256` (every listed file hashes; every `spec/0*.md` and `spec/milestones/*.md` is listed — spec files change only via §6 change requests), then re-runs `check-<chunk>` for each chunk marked `DONE` in `spec/PROGRESS.md` or `spec/progress/*.md`. The currently running chunk is skipped to avoid recursion. |

`spec/FROZEN.sha256` currently pins the spec documents ("from the start", 06
§7). Later gates add the `test/vectors/` corpora; adding new vector files is
allowed, changing listed ones is not.

`tools/lint-progress.sh` (part of `make lint`) validates progress rows against
the §13 format: `| chunk | status | attempts | last evidence folder | note |`
with a known status and integer attempts.

Self-test chunks `DUMMY1` (suite reads the sabotaged file) and `DUMMY2`
(blind suite) exist only to prove the harness; they are never lane work.
