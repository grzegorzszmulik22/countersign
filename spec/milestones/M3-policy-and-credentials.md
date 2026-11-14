# M3. Policy and credential binding

**Goal.** Grants scoped at HTTP level; real secrets held only by the broker; placeholders in the sandbox; pinning; response scrubbing; limits. Still local mode.

**Properties advanced.** P1 (secret confinement), P4 (release bound to a grant; intent and review conditions attach in M9 and M6), P5 (pinning).

**Normative references.** `04` §1–§4; `03` §8, §9.

**Expected results.**
- A real secret is attached to a request only when a grant matches at host, method and path level.
- A request to a credentialed host carrying somebody else's credential is refused.
- A real secret never appears in anything delivered to the client side, nor in the ledger.

**Measurements [T].**

| ID | Metric | Target |
|---|---|---|
| MM3.1 | Decision-table rows passing (`test/vectors/policy/matching.yaml`) | 100% of ≥ 200 rows |
| MM3.2 | Occurrences of any real canary in client-visible bytes, ledger files, or broker logs across the M3 suite | 0 |
| MM3.3 | Added p50 latency of policy evaluation and injection over M2 | ≤ 0.3 ms |
| MM3.4 | Throughput penalty of response scrubbing on a 100 MiB credentialed download | ≤ 25% |

**Milestone-wide denied.** A policy language with expressions, variables or includes. Regex matching in policy. OAuth flows, token refresh, token minting or exchange (the store holds static secrets). Secret rotation. Fetching secrets from external vaults. Body-content rules beyond the credential-shape detector. Per-user policies.

---

## M3.1 Policy schema and matcher

**Build.** `internal/policy`: strict YAML parsing of `SessionPolicy` with the defaults table of `04` §1; validation; digest; matcher implementing `04` §2 (grant order, host wildcards, method, path globs, ports, scheme, `action: deny`). JSON Schema in `api/schema/`.

**Decision table.** `test/vectors/policy/matching.yaml`: each row is `{policy, request, expected: {grant|null, reason}}`. At least 200 rows, generated as the cross product of the dimensions below plus the hand-written rows, then **reviewed by reading**, not by running the implementation:

- Hosts: exact, wildcard one label, wildcard two labels, apex against wildcard (no match), uppercase, trailing dot, IP literal, internationalized name in A-label form.
- Paths: exact, `*` inside a segment, `**` middle and end, trailing slash differences, empty path, percent-encoded unreserved characters.
- Methods: listed, unlisted, lowercase method token.
- Order: two overlapping grants in both orders; a `deny` grant before and after an allow.
- Scheme and port: https default, explicit 8443, http without and with `scheme: http`.

Hand-written rows that must exist: wildcard does not match the apex; `/repos/acme/widgets` does not match `/repos/acme/widgets-evil`; `/repos/acme/*` does not match `/repos/acme/a/b`; first-match-wins with a broader grant placed second; deny grant carving `/admin/**`; host with trailing dot normalized; `*` host rejected on a credentialed grant at validation.

**Checks.**
- C3.1.1 MM3.1.
- C3.1.2 Twenty invalid policies (one per validation rule) are each rejected with a message naming the field.
- C3.1.3 Policy digest is over the exact file bytes: a whitespace-only change alters the digest.
- C3.1.4 Property test: for random policies and requests, the matcher's result equals that of a 60-line reference matcher written in Python inside `ref/python/refreconcile/match.py`.
- C3.1.5 Fuzz the YAML loader 10 minutes: no panic.

**Sabotage.** `prefix-match-instead-of-segment`; `last-match-wins`; `wildcard-matches-apex`; `case-sensitive-host`.

**Denied.** See milestone list. Also: computing the decision table's expected column by running the code.

## M3.2 Credential store, placeholders, injection

**Build.** `internal/creds`: store interface with a file-backed implementation (local mode) and a Kubernetes-Secret-backed one (used from M4); placeholder generation per `04` §4.1; injection per §4.2 for header format and for HTTP Basic; the mapping exists only in broker memory. `effect.http.decision.credentials` lists credential IDs (the `ref`), never values.

**Checks.**
- C3.2.1 Request with the placeholder in the inject location to a matching grant: `echo` receives the real canary; the record lists the credential ID.
- C3.2.2 Same request with the inject location absent: broker adds it.
- C3.2.3 Request to the same host but a path outside the grant: `NO_GRANT`; `echo` receives nothing.
- C3.2.4 Basic form: `git` against `fakehub` using the placeholder as password clones and pushes successfully; `fakehub` records the real token.
- C3.2.5 Invariant test: a wrapper around the injection function logs every injection; over 50,000 randomized requests, every logged injection has a matching grant with that credential and passed all §2 checks (asserted by the Python reference matcher).
- C3.2.6 Injection happens after the write-ahead record is acknowledged (ordering assertion as in C2.4.1).

**Sabotage.** `inject-by-host-only` (ignore method and path: this is baseline B2's behaviour and must fail C3.2.3); `log-secret-value-in-record`; `inject-before-ack`.

**Denied.** Injecting into bodies or URLs. More than one credential per grant.

## M3.3 Pinning, placeholder misuse, credential shapes

**Build.** `04` §4.3 and §4.4. Detector vectors in `test/vectors/credshapes.json` with at least five positive and five negative strings per shape.

**Checks.**
- C3.3.1 Credentialed grant, request carries a different `x-api-key` / `Authorization` / `Cookie` → `FOREIGN_CREDENTIAL`; `mockllm /v1/files` records no upload (this is scenario A6 in miniature).
- C3.3.2 Placeholder in query string, in a JSON body, in a non-inject header, or sent to another host → `PLACEHOLDER_MISUSE`.
- C3.3.3 Placeholder from session B used in session A → `PLACEHOLDER_MISUSE`.
- C3.3.4 Credential-shaped string in the URL or buffered body of a request to a credentialed grant → `FOREIGN_CREDENTIAL`; the same string to a non-credentialed grant is allowed (and redacted in any preview).
- C3.3.5 Detector vectors: 100% of positives detected, 0 negatives flagged.
- C3.3.6 Ordinary bearer-less requests to a non-credentialed grant are unaffected.

**Sabotage.** `pinning-only-checks-authorization-header`; `placeholder-in-body-allowed`; `detector-disabled`.

**Denied.** Entropy-based secret detection. Extending the shape list beyond `04` §4.4.

## M3.4 Response scrubbing

**Build.** `04` §4.5: streaming search-and-replace with a carry-over window, for the raw, Basic-encoded and URL-encoded forms; headers included; `Accept-Encoding` control and gzip decode for credentialed requests; `scrubbed` count in the result record.

**Checks.**
- C3.4.1 `fakehub /debug/echo` through a credentialed grant: the client sees the placeholder where the secret was reflected; `scrubbed ≥ 1` (scenario A5 in miniature).
- C3.4.2 Secret split across every possible chunk boundary (for a 40-byte secret: 39 split points) is always scrubbed.
- C3.4.3 Secret inside a gzip-encoded response is scrubbed; the client receives a valid identity-encoded body.
- C3.4.4 Secret in a response header, in an HTTP/2 trailer, and in a 1 GiB body near the end: scrubbed.
- C3.4.5 Non-credentialed requests are not scanned and not decoded (byte-exact pass-through as in M2.3).
- C3.4.6 MM3.2 and MM3.4.

**Sabotage.** `scrub-without-carry-window`; `scrub-skips-gzip`; `scrub-skips-headers`.

**Denied.** Scrubbing other patterns. Decoding encodings other than gzip (the broker does not offer them upstream for credentialed requests). Scrubbing inside WebSocket or passthrough tunnels (credentials are never injected there).

## M3.5 Limits

**Build.** `limits` of `04` §1: request body size, URL length, per-grant per-session rate (token bucket, burst = one tenth of the per-minute value).

**Checks.**
- C3.5.1 Each limit: at the limit allowed, one over denied with the right `LIMIT_*`.
- C3.5.2 Rate limit is per (session, grant): session B and another grant are unaffected.
- C3.5.3 Body limit enforced while streaming: the upstream receives at most the limit, the connection is closed, the result record has `error: limit-body`.
- C3.5.4 Redirects: the broker never follows them; a `3xx` is returned to the client and the client's follow-up request is evaluated on its own (a redirect from a credentialed host to another host results in no credential there).

**Sabotage.** `rate-limit-global-not-per-session`; `url-limit-ignores-query`.

**Denied.** Quotas, budgets, cost accounting. Adaptive rate limiting.

## M3.6 Semantic matchers

**Build.** `git-smart-http` matcher per `04` §2, with repository scoping and read/write access. Package-index grants are ordinary method/path grants; no special code.

**Checks.**
- C3.6.1 Real `git` client against `fakehub` through the broker: clone and fetch succeed with `access: read`; push fails with `NO_GRANT`; with `access: write` push succeeds.
- C3.6.2 Push to `attacker/loot` on the same host with a grant for `acme/widgets` → `NO_GRANT`; `fakehub` records no write (scenario A2/B3 in miniature).
- C3.6.3 Unknown `service` parameter, extra path segments, repository name with a traversal attempt → no match.
- C3.6.4 Rows for the matcher are in the decision table (at least 30).

**Sabotage.** `git-matcher-ignores-repo`; `git-read-allows-receive-pack`.

**Denied.** Parsing pack data. (The ref-update command lines of an apply push are read in M6.4, and nowhere else.) Matchers for other protocols. Git over SSH.

---

## Exit: none here; gate G2 follows M4

Exit review must restate P1, P4, P5 with the suite results, and list exactly which baseline-B2 behaviours the sabotages `inject-by-host-only`, `pinning-only-checks-authorization-header` and `scrub-skips-headers` correspond to.
