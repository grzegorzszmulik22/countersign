# M3.6 plan — semantic matchers (git-smart-http)

- Files: `internal/policy/git.go` (new: repo scoping + read/write access per 04 §2),
  `internal/policy/match.go` (dispatch `match.matcher` to it), `internal/policy/git_test.go`
  (unit edges, C3.6.3), `internal/policy/gite2e_test.go` (fixtures tag, C3.6.1/3.6.2),
  `test/gateproxy/` (new fixtures-tagged CONNECT proxy that runs `SessionPolicy.Match`
  per request — the §2 step-1/2 decision path the broker runs; M2's data plane does not
  exist yet, same posture as M3.1 ahead of M2), `ref/python/refreconcile/match.py`,
  `test/gen/matching_table.py` + `test/vectors/policy/matching.yaml` (append ≥30 gitm rows;
  existing rows untouched), `test/checks/check-M3.6.sh`, `test/sabotage/M3.6/`, docs note.
- Checks: C3.6.1 real git vs fakehub through the gate (clone+fetch ok @read; push NO_GRANT;
  push ok @write); C3.6.2 push to attacker/loot → NO_GRANT, no write recorded; C3.6.3 bad
  service/extra segments/traversal → no match; C3.6.4 ≥30 matcher rows in the table.
- Matcher semantics: path `/<owner>/<repo>[.git]/info/refs` GET with query exactly
  `service=git-upload-pack` (read) or `service=git-receive-pack` (write only); POST
  `/<owner>/<repo>[.git]/git-upload-pack` (read) / `git-receive-pack` (write), empty query.
  Repo compare exact case, one `.git` suffix stripped on both sides; anything else no match.
- First test: the new gitm-* decision-table rows (fail today: matcher grants never match).
- Sabotages: git-matcher-ignores-repo, git-read-allows-receive-pack.
