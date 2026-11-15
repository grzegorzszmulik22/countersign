<!-- Copyright 2026 The Countersign Authors
     SPDX-License-Identifier: Apache-2.0 -->

# SessionPolicy schema and request matcher (M3.1, M3.6)

`internal/policy` implements the `SessionPolicy` document of spec/04 §1 and
request matching per §2 steps 1–2, still in local mode.

## What is implemented

- **Strict loading.** `policy.Load` parses one YAML document, rejects unknown
  fields and applies the defaults table of 04 §1. Validation failure names the
  offending field (`policy: spec.grants[i].match.hosts: …`).
- **Scope.** Fields defined by spec/05 — session-level `autonomy`, `world`,
  `commit`, `budgets`, `tape`, `attest` and grant-level `class`, `stager`,
  `compensate`, `tools`, `egress` — are unknown keys and rejected; the Go types
  and `api/schema/sessionpolicy.schema.json` are additive-only so those fields
  can be added later without breaking the schema.
- **Digest.** `policy.Digest` is the SHA-256 of the exact file bytes, so a
  whitespace-only change alters it.
- **Matcher.** `(*SessionPolicy).Match(r *Request)` evaluates §2 step 1
  (authority consistency, path traversal/encoding rejects, IP literals) and
  step 2 (first match in document order; `*.dom` is one-or-more labels and
  never the apex; `*` alone skips IP literals; `*` in a path glob stays inside
  one segment, `**` spans segments; percent-encoded unreserved characters are
  decoded; `action: deny` yields `DENY_GRANT`). Steps 3–6 (upstream check,
  limits, credentials, class/condition) belong to later chunks; a grant whose
  `match` carries `matcher` is resolved by the semantic matchers of 04 §2
  (M3.6) instead of the generic host/path glob rules.

## git-smart-http matcher (M3.6)

A grant may carry `match.matcher.git-smart-http` with `repos` (list of
`owner/repo`) and `access` (`read` or `write`). It matches only Git smart
HTTP endpoints on the grant's `hosts`:

- **Read** (`access: read` or `write`):
  `GET /<owner>/<repo>[.git]/info/refs?service=git-upload-pack` and
  `POST /<owner>/<repo>[.git]/git-upload-pack`.
- **Write** (`access: write` only): the same endpoints with
  `git-receive-pack` (`service=git-receive-pack` on `info/refs`, POST path
  `git-receive-pack`).

Matching rules:

- `owner` and `repo` are exactly two path segments; extra segments,
  traversal, or a missing pair never match.
- `.git` is an optional suffix on the repo segment, on the wire and in a
  `repos` entry; everything else is case-sensitive.
- `info/refs` requires the query to be exactly `service=git-upload-pack` or
  `service=git-receive-pack`; POST endpoints carry no query. Unknown
  services, duplicated/extra parameters, and any other method do not match.
- A grant lists whole repositories only — repository-name prefixes do not
  match (`acme/widgets` does not authorize `acme/widgets-evil`).

## Checks and vectors (M3.6)

- `internal/policy/git_test.go` — edge-case vectors (C3.6.3) and the
  ≥30-row decision-table requirement (C3.6.4).
- `internal/policy/gite2e_test.go` — real `git` client through the policy
  gate against the fakehub fixture (C3.6.1, C3.6.2).
- `test/gateproxy` — the test-only CONNECT gate used by the e2e tests.
- Run: `make check-M3.6`, `make sabotage-M3.6`.

## Checks and vectors (M3.1)

- Decision table: `test/vectors/policy/matching.yaml` (348+ rows; expected
  column derived from the spec by `test/gen/matching_table.py`, reviewed by
  reading, never produced by running the matcher).
- Invalid policies: `test/vectors/policy/invalid/` (20 files, one rule each).
- Reference matcher: `ref/python/refreconcile/match.py` (used by the
  randomized Go-vs-Python agreement test, C3.1.4).
- Run: `make check-M3.1`, `make sabotage-M3.1`.
