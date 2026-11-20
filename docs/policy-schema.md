<!-- Copyright 2026 The Countersign Authors
     SPDX-License-Identifier: Apache-2.0 -->

# SessionPolicy schema and request matcher (M3.1, M3.6, M5.2)

`internal/policy` implements the `SessionPolicy` document of spec/04 §1 and
request matching per §2 steps 1–2, still in local mode. `internal/classify`
implements the reversibility classes and autonomy conditions of spec/05 §1–§2.

## What is implemented

- **Strict loading.** `policy.Load` parses one YAML document, rejects unknown
  fields and applies the defaults table of 04 §1. Validation failure names the
  offending field (`policy: spec.grants[i].match.hosts: …`).
- **Scope.** The spec/05 fields `world`, `commit`, `budgets`, `tape`,
  `attest` and grant-level `egress` remain unknown keys and are rejected;
  `autonomy`, `class`, `requires`, `stager`, `tools`, `calls` and
  `compensate` landed with M5.2 (below).
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

## Reversibility classes and autonomy (M5.2)

New policy fields (spec/05 §1–§2):

- `spec.autonomy`: map from class (`control`, `safe`, `staged`,
  `compensable`, `irreversible`) to a condition (`allow`, `review`, `deny`).
  Missing entries default to `allow`. The `intent` condition is rejected at
  validation until M9.
- `grant.class`: an explicit class; wins over every computed rule except
  `control` sources. `class: staged` requires a `stager`.
- `grant.requires`: the grant's own condition (`allow`, `review`, `deny`;
  `intent` rejected until M9). The imposed condition is the **strictest** of
  `autonomy[class]`, `requires` and — for `compensable`/`irreversible`
  effects only — the grant's `whenTainted` outcome for the taint labels
  present (04 §8). A looser `requires` never weakens `autonomy`.
- `grant.stager`: exactly one of `git` (`refs` patterns, `allowDelete`,
  `allowNonFastForward`, `maxPackBytes`) or `outbox` (`respond`, `idMap` JSON
  pointers, `idempotencyHeader`). Git stagers stage smart-HTTP writes inside
  the grant's matcher; outbox stagers stage every non-GET/HEAD/OPTIONS
  request.
- `grant.tools` (`inspect: mcp` only): per-tool class for `tools/call`;
  a missing tool is `irreversible`; server annotations are never trusted.
- `grant.calls: serialized` (`inspect: mcp` only): `tools/call` on the
  brokered server is `control`.
- `grant.compensate`: `restore` or `deleteCreated` method lists; a matching
  request is `compensable`.

Classification (`classify.Classify`) applies 05 §1's ten rules in order —
control sources, explicit class, passthrough/WebSocket, stager, git read,
GET/HEAD/OPTIONS, serialized MCP, per-tool class, compensation, else
`irreversible` — and returns `{class, requires, declared_safe}`.
`declared_safe` flags a `class: safe` declaration on a non-GET method, a
tunnel or a WebSocket; it lands on the shared `decision` block of
`effect.http`/`effect.tunnel` records. Recording `class` and
`decision.requires` per effect, and `review`→`REVIEW_REQUIRED`, is the
broker wiring of M2.4.

## Checks and vectors (M5.2)

- Decision table: `test/vectors/policy/classes.yaml` (≥ 250 rows; expected
  column derived from spec/05 §1–§2 by `test/gen/classes_table.py`).
- Reference classifier: `ref/python/refclassify` (spec-derived, stdlib only);
  a 10,000-case Go-vs-Python differential runs in
  `internal/classify/diff_test.go`.
- Run: `make check-M5.2`, `make sabotage-M5.2`.

## Checks and vectors (M3.1)

- Decision table: `test/vectors/policy/matching.yaml` (348+ rows; expected
  column derived from the spec by `test/gen/matching_table.py`, reviewed by
  reading, never produced by running the matcher).
- Invalid policies: `test/vectors/policy/invalid/` (20 files, one rule each).
- Reference matcher: `ref/python/refreconcile/match.py` (used by the
  randomized Go-vs-Python agreement test, C3.1.4).
- Run: `make check-M3.1`, `make sabotage-M3.1`.
