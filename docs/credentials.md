<!-- Copyright 2026 The Countersign Authors
     SPDX-License-Identifier: Apache-2.0 -->

# Credential store, placeholders, injection, scrubbing, limits (M3.2–M3.5)

`internal/creds` plus the broker-side rules in `internal/proxy` implement
04 §4 (credentials) and the `limits` table of 04 §1, still in local mode.
The design invariant: every byte leaving a sandbox passes one broker that
holds the secrets and writes signed evidence first — a real credential
value exists only in broker memory and on the upstream wire, never in the
sandbox environment, the ledger, or the response a client sees.

## Store (`internal/creds/store.go`)

- `Store` resolves `Ref{Secret, Key}` to a value; `Ref.ID()` is the
  `"<secret>:<key>"` string recorded in `effect.http.decision.credentials`.
- `FileStore` is the local-mode implementation: strict YAML, loaded once
  into memory; empty names, keys and values are rejected. A missing
  reference at session open fails closed.
- `KubeStore` is the interface-backed shape the M4 cluster source will
  implement (`SecretSource`); no cluster behavior lives here yet.

## Placeholders (`internal/creds/placeholder.go`)

One per (session, credentialed grant):
`csph_<8 hex of session>_<grant id>_<22 base62 random>`, generated with
crypto/rand and delivered to the sandbox through `placeholderEnv`. The
mapping lives only in the broker.

## Injection (`internal/creds/inject.go`, `internal/proxy/creds.go`)

- Supported forms: `inject.header` with `format` (`{secret}` substituted)
  and `inject.basic` (`Authorization: Basic base64(user:secret)`).
- `InjectSpec.Eval` authorizes replacement only when the inject location
  is absent or holds exactly this session's placeholder form. Anything
  else is denied before injection.
- `Apply` runs only after the write-ahead `effect.http` record is durable
  (evidence first, then secrets touch the wire). With a failing record
  sink the request is denied `LEDGER_UNAVAILABLE` and no injection occurs.
- Pinning (04 §4.3): on a credentialed-grant request, a non-empty value in
  `authorization`, `proxy-authorization`, `x-api-key`, `api-key`,
  `x-auth-token`, `cookie` or the inject header that is not this session's
  placeholder is `FOREIGN_CREDENTIAL`. Any `csph_` token anywhere else —
  URL, userinfo, buffered body, other headers, a Basic username — is
  `PLACEHOLDER_MISUSE`, as is another session's or another grant's
  placeholder in the slot.
- Credential shapes (04 §4.4): a fixed detector list (Anthropic, OpenAI,
  GitHub, AWS, Slack, JWT, PEM) flags `FOREIGN_CREDENTIAL` when a shape
  appears in the URL or buffered body of a credentialed-grant request —
  raw or percent-decoded. Non-credentialed grants are never scanned.

## Response scrubbing (`internal/creds/scrub.go`, `internal/proxy/scrub.go`)

When (and only when) a credential was injected, the response is scanned
streaming with a carry-over window of `len(pattern)−1` bytes, so a secret
split at any chunk boundary is still caught. The raw, base64 and
URL-escaped forms — plus the `base64(user:secret)` Basic composite — are
replaced by the session placeholder and counted in
`effect.http.result.scrubbed`. Headers and trailers are scrubbed as whole
values; `Content-Length`, `Content-Encoding` and per-field integrity
headers (ETag, Content-Digest, Digest, Content-MD5) are dropped on
scrubbed responses. Credentialed requests offer only
`Accept-Encoding: gzip, identity` upstream; gzip is decoded in the broker
and anything else fails closed (`UPSTREAM_ENCODING`). Non-credentialed
responses pass through byte-exact.

## Limits (`internal/proxy/limits.go`)

- `limits.maxRequestBodyBytes` — declared length over the cap is denied
  `LIMIT_BODY` before upstream; a deferred/streaming body is capped on
  the wire (the write aborts mid-body and `result.error` is `limit-body`).
- `limits.maxUrlBytes` — path + query bytes over the cap → `LIMIT_URL`.
- `limits.requestsPerMinute` — token bucket per (session, grant), burst =
  one tenth of the per-minute value (floor 1); exhaustion → `LIMIT_RATE`.
- The broker never follows redirects; a 3xx is relayed and the client's
  follow-up is evaluated on its own grant.

## What is not here

Policy expressions/variables/includes, regex matching, OAuth flows,
token mint/refresh/exchange, rotation, external vaults, body-content
rules beyond the shape list, per-user policies (milestone-wide denials).
