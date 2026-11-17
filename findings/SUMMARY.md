# SUMMARY — Red-team B2, Countersign broker local mode

Target: `csbroker -local` (`cmd/csbroker`, `internal/proxy`,
`internal/policy`) as of commit `b9a8f56`. Everything ran on loopback,
Windows, `GOMAXPROCS=2`, Go 1.27.4, tests under `-tags fixtures`; every
upstream/sink was a process started by the test. No product code, spec,
check, vector or fixture was edited. Repro files are
`internal/proxy/rt_*_test.go`; copied sources are stored next to each
finding.

## Numbers

- **75 attempt rows** in `findings/TRIED.md` (several cover a family of
  inputs: 13 CONNECT authorities, 7 path-encoding forms, 7 policy
  fields).
- **6 findings**, each reproduced twice from clean `-count=1` runs:
  - **01 `findings/01-retry-unrecorded-effect/`** — the broker's
    `http.Transport` retries a POST carrying a client `Idempotency-Key`
    after the upstream received and applied it but dropped the
    connection: **two upstream effects, one `effect.http` record**, one
    client 200. M2 explicitly denies any broker retry. High confidence;
    deterministic 3/3 iterations, 2/2 runs.
  - **02 `findings/02-record-chain-reordering/`** — `appendRecord`
    assigns `eseq`/`eprev` under the session lock but appends after
    releasing it. 120 concurrent requests per round produce a JSONL whose
    file order is not `eseq` order (first line `eseq 130`; `eseq 344
    after 240`); V5 would be `E_CHAIN`. A client can make its own
    session's evidence unverifiable with ordinary concurrent traffic.
    High confidence, 2/2 clean runs.
  - **03 `findings/03-forwarded-request-target-mismatch/`** — `forward`
    round-trips the escaped path through `url.URL.String()` +
    `NewRequest`, re-escaping `%` (`/a%41b` → upstream `/a%2541b`), and a
    `#` in the raw query is re-parsed as a fragment and truncated
    (`?x=1#frag` → upstream `?x=1`). The record's path/query/digest
    describe the original, so the evidence misstates the request that
    reached the upstream; path-sensitive upstream APIs also break.
    High confidence, tunnel + plain, 2/2.
  - **04 `findings/04-dns-address-check-missing/`** — 04 §2 step 3 is
    absent: a granted name answered with a loopback address is dialled
    and a **canary reaches the sink** (200). This is the only
    cross-upstream reach I achieved. It is a documented M2.5 TODO, so
    the supervisor should weigh it as a known missing control, not a
    surprise implementation bug. High confidence in the behaviour.
  - **05 `findings/05-smuggling-prechecks-missing/`** — CL+TE, bare LF
    and obsolete line folding are accepted and forwarded (200) instead
    of `403 SMUGGLING_SUSPECT` (04 §2 step 1). Also a documented M2.5
    TODO. `net/http` normalised all three into one request in my probes,
    so I do not claim a demonstrated desync; the refusal is missing.
  - **06 `findings/06-upstream-ip-misrecorded/`** — `upstream.ip` in
    `effect.http.result` is the host name (`allowed.example.com`), not
    the dialled address. Low severity, high confidence.

## What held (details in TRIED.md)

- **Session binding**: token + source address, 407 + recorded denials;
  a foreign `Proxy-Authorization` inside an established tunnel cannot
  switch sessions; no network path to another session's CA.
- **Host/port gate**: every CONNECT / SNI / Host / `:authority` /
  absolute-form / plain-URL deviation I tried was refused, including
  suffix/prefix/superstring names, odd ports, IP literals and
  encodings, and h2 `:authority` mismatches. Path dot/`%2e`/`%2f`/
  `%5c`/`%00`/backslash forms were refused. No host or port escape
  through HTTP semantics.
- **Redirects/upgrades**: the broker does not follow redirects; the
  client follow was denied; `Upgrade` is stripped and no tunnel forms.
- **Pipelining**: sequential requests are recorded separately; a body
  containing a second request is consumed as the body.
- **Availability**: no crash, panic or deadlock; 300 idle TLS tunnels
  cost ~49 KiB each (+600 goroutines, +15.1 MiB heap). A policy-glob
  quadratic (two `**`, 120 KiB path = 1.21 s; ~1 MiB ≈ 85 s) exists but
  needs an operator-authored glob and the missing `maxUrlBytes`.

## What I did not get to

- Raw HTTP/2 frames: duplicate pseudo-headers, CONTINUATION, stream
  reuse, pseudo-header ordering. h2 parsing is delegated to
  `net/http`; I only exercised `:authority` mismatches through the stdlib
  client.
- A TLS ClientHello pipelined in the same TCP segment as CONNECT (the
  hijack buffer is discarded; likely a client-only hang).
- Coverage-guided fuzzing of the request line/header/CONNECT parsers.
- M2.4's real ledger wiring and seal/bundle path; the current
  `FileRecordSink` is interim, but finding 02 is in the broker's
  chain/append sequence, not in the sink.
- Credentials, inference/MCP inspection, limits, intents, staging:
  policy fields exist but the controls are later milestones.
- A large dangling-effect/crash test (SIGKILL windows).

## What I would try next

1. A raw h2/h1 differential desync fuzzer against the broker, with an
   upstream that uses a deliberately different parser, focused on
   CL+TE/obs-fold and h2→h1 translation.
2. Fix hypotheses and regression: disable transport replay
   (`GetBody=nil`/non-replayable body), hold the chain lock across the
   sink append, build the outbound request without `URL.String()`
   round-trips, and enforce the 04 §2 step 3 address check with one
   resolve + dial.
3. Check whether the `requires`/credential/limits fields can be rejected
   at load time until their chunks land, so a policy cannot look
   stricter than the broker is.
4. Repeat the DNS address check against `169.254.169.254` and IPv4-mapped
   forms once dial-to-fixture is still possible under a test
   `network: cluster` exemption.
5. Race-detector and fuzz runs over the new repro tests; the record-chain
   fix is the one most likely to move the ordering window rather than
   close it.

## How to run the reproductions

```
go test -tags fixtures ./internal/proxy -run 'TestRTRetryUnrecorded|TestRTRecordOrder|TestRTRequestTarget|TestRTDNSUpstreamBlocked|TestRTSmugglingPrechecks|TestRTUpstreamIP' -count=1 -v
```

All six currently fail; the refusal battery
(`-run TestRTRefusal`) passes. The existing suite minus
`TestC235MemoryBound` (Linux `/proc` only) passes on this host.
