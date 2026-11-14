# M2. Broker data plane

**Goal.** An explicit forward proxy that intercepts TLS with a per-session certificate authority, streams without buffering, and writes evidence **before** anything is forwarded. Runs locally (`csbroker --local`), with one static session and an allow-everything-listed test policy. No credentials, no Kubernetes yet.

**Properties advanced.** P3 (write-ahead completeness). Foundation of P2.

**Normative references.** `02` §3, §6; `03` §4 (effect records, write-ahead rule, deferred bodies); `04` §2 step 1 (pre-checks) and step 3 (upstream address check).

**Expected results.**
- Every request that reaches an upstream has an `effect.http` record that was durable first; killing the broker at any instant never produces an upstream request without one.
- Streams pass through unmodified and unbuffered.
- If the ledger stops, nothing leaves.

**Measurements [T]** (harness of M2.6; paired difference against a direct connection to the same `echo` upstream; 64 kept-alive connections; 1 KiB request and response bodies; 60 s; 5 runs):

| ID | Metric | Target |
|---|---|---|
| MM2.1 | Added latency per request | p50 ≤ 3 ms, p99 ≤ 12 ms (H5) |
| MM2.2 | Added time to first byte on a streamed response | p99 ≤ 5 ms (H5) |
| MM2.3 | Added per-event delay on a 1,000-event stream at 10 ms spacing | p99 ≤ 2 ms; events coalesced ≤ 1% |
| MM2.4 | Throughput per core | ≥ 1,500 requests/s |
| MM2.5 | Resident memory growth while relaying a 1 GiB body, either direction | ≤ 64 MiB |
| MM2.6 | Resident memory with 1,000 idle tunnels | ≤ 300 MiB |
| MM2.7 | New-connection overhead (handshake with freshly minted leaf) | p99 ≤ 20 ms |

**Milestone-wide denied.** Transparent interception. Caching of responses. HTTP/3. Connection pooling tricks beyond the standard library's. Load balancing across upstream addresses. Any retry of upstream requests by the broker. Rewriting of request or response bodies (scrubbing arrives in M3 and nowhere else).

---

## M2.1 Proxy listener and sessions (local mode)

**Build.** `internal/proxy`: listener on port 3128; plain-HTTP proxy requests (absolute-form) and `CONNECT`; `Proxy-Authorization: Basic` (user `cs`, password = session token, as sent by clients from the proxy URL's userinfo); a session table loaded from a local file in `--local` mode (session ID, token, client IP, policy file). Default deny: unknown session → `407` and an `effect.denied` record when a session can be attributed, or a broker log line when it cannot. Hop-by-hop headers stripped; `Proxy-Authorization` never forwarded.

**Checks.**
- C2.1.1 No token, wrong token, right token from the wrong client IP → `407`, reason `NO_SESSION`.
- C2.1.2 Valid session, host not in the test policy → `403`, reason `NO_GRANT`, `effect.denied` or `effect.http` record with `action: deny`.
- C2.1.3 `Proxy-Authorization` and other hop-by-hop headers never reach `echo`.
- C2.1.4 `CONNECT` to a port other than those the grant lists → `PROTOCOL_DENIED`.
- C2.1.5 Plain-HTTP request allowed only when the grant has `scheme: http`.

**Sabotage.** `token-only-no-ip-check`; `forward-proxy-authorization`.

**Denied.** SOCKS. PAC files. Authentication methods other than the bearer token plus source address.

## M2.2 TLS interception

**Build.** Per-session ECDSA P-256 CA created in memory at session open; leaf certificates minted per host name (SAN = requested name, validity 24 h, cached per session); ALPN offering `h2` and `http/1.1` to the client; upstream TLS verified against system roots (plus the test root under the `fixtures` tag), minimum TLS 1.2, upstream ALPN negotiated independently; SNI, `CONNECT` authority and `Host`/`:authority` cross-checked.

**Checks.**
- C2.2.1 A client trusting only the session CA completes requests over HTTP/1.1 and HTTP/2 to `echo`.
- C2.2.2 A client trusting session A's CA rejects a leaf minted for session B.
- C2.2.3 Upstream with an invalid, expired, or wrong-name certificate → `502`, reason `UPSTREAM_TLS`; nothing forwarded.
- C2.2.4 SNI ≠ `CONNECT` authority, or `Host` ≠ authority → `SMUGGLING_SUSPECT`.
- C2.2.5 The CA private key never reaches the client side, the ledger or the logs: a scan of everything the test client received, of the ledger directory and of broker output finds no private-key material. Its only serialization call site is the session-key store interface (static check).
- C2.2.6 Client HTTP/2 with upstream HTTP/1.1, and the reverse, both work.
- C2.2.7 Leaf minting: 1,000 distinct host names in one session complete without error; cache bounded (LRU 4,096).

**Sabotage.** `skip-upstream-verify`; `shared-ca-across-sessions`; `ignore-sni-mismatch`.

**Denied.** Client-certificate (mutual TLS) support toward upstream. Certificate transparency checks. OCSP. TLS session resumption tuning.

## M2.3 Streaming and digests

**Build.** Bodies relayed in both directions without buffering beyond `bufferLimit` for requests; SHA-256 computed on the fly; flush on every upstream write for streamed responses (`text/event-stream`, chunked without length, HTTP/2 data frames); trailers preserved; client disconnect cancels upstream and the reverse.

**Checks.**
- C2.3.1 Byte equality: for bodies of 0, 1, 1 KiB, 1 MiB, 1 MiB + 1 and 1 GiB, the digest seen by `echo` equals the digest sent, and the digest recorded in the result record equals both. Both directions.
- C2.3.2 Server-sent events: 1,000 events at 10 ms spacing arrive as 1,000 separate reads at the client, with MM2.3.
- C2.3.3 Request body ≤ `bufferLimit`: `body_sha256` and `request_digest` present in the write-ahead record. Larger: `body_deferred: true`, digest in the result record.
- C2.3.4 Client aborts mid-download: upstream connection closed within 1 s; result record has `error: client-abort` and the partial byte count.
- C2.3.5 MM2.5 holds for upload and download.

**Sabotage.** `buffer-whole-response`; `digest-computed-after-truncation`; `no-flush-on-sse`.

**Denied.** Decompression (except where M3.4 requires it). Body transformation of any kind.

## M2.4 Write-ahead evidence and fail-closed

**Build.** Wire the broker to `internal/ledger`. Sequence for each request: pre-checks → decision → append `effect.http` (wait for durable ack, timeout 500 ms) → open or reuse upstream → forward → on completion append `effect.http.result`. Ledger failure → `502 LEDGER_UNAVAILABLE`, nothing forwarded. On start, the broker reads the ledger and marks effects without a result as dangling (the verifier reports them).

**Checks.**
- C2.4.1 **Ordering proof.** An instrumented `echo` records the arrival time of each request's first byte; an instrumented ledger records the durable-ack time of each `effect.http`. Over 100,000 requests at mixed concurrency, ack time < first-byte time for every one.
- C2.4.2 **Crash proof.** `SIGKILL` the broker at 200 random instants under load. After each: every request `echo` observed has an `effect.http` record in the recovered ledger. Requests with no result record are exactly those in flight at the kill.
- C2.4.3 Ledger directory made read-only, or the disk filled, or the append artificially delayed past 500 ms: every request gets `502`; `echo` observes zero requests during the fault.
- C2.4.4 Denied requests also produce exactly one record each.
- C2.4.5 Record count equals request count at `echo` plus denied count over a 100,000-request mixed run (exact equality).
- C2.4.6 A session produced by the broker, sealed by a test helper, exports to a bundle that both verifiers accept as `CLEAN_WITH_DENIALS` or `CLEAN`.

**Sabotage.** `forward-before-ack`; `fail-open-on-ledger-error`; `no-record-for-denied`; `result-without-effect-on-error-path`.

**Denied.** An asynchronous or "best effort" evidence mode. A configuration switch to fail open.

## M2.5 Protocol edges and hardening

**Build.** The pre-checks of `04` §2 step 1; upstream address check of step 3 with single resolution (connect to the address that was checked); WebSocket upgrade only with `upgrade: [websocket]` (recorded as `effect.tunnel` with byte counts); `mode: passthrough` tunnels (no interception, SNI recorded, byte counts); per-session limits: 256 concurrent connections, 64 concurrent upstream dials, header block ≤ 64 KiB, idle timeout 120 s. A session exceeding limits is throttled; other sessions are unaffected.

**Checks.**
- C2.5.1 Request-smuggling corpus (`test/vectors/smuggling/`, at least 40 cases: CL+TE, TE obfuscations, duplicate CL, bare LF, line folding, absolute-form with conflicting Host, HTTP/2 pseudo-header conflicts, HTTP/2 → HTTP/1.1 downgrade injections): every case is rejected with `SMUGGLING_SUSPECT` or parsed identically by broker and `echo`. None reaches `echo` as two requests.
- C2.5.2 Path forms of `04` §2 (dot segments, encoded separators, backslash, NUL, in mixed case and double-encoded once) → rejected.
- C2.5.3 Upstream address check: names resolving to loopback, link-local, private, unique-local, cluster ranges, `0.0.0.0`, IPv4-mapped IPv6 forms, and a name whose DNS answer changes between check and connect (rebinding fixture) → `UPSTREAM_BLOCKED`; the address connected to always equals the address recorded.
- C2.5.4 WebSocket without grant → `PROTOCOL_DENIED`; with grant → echo works and byte counts are exact.
- C2.5.5 Passthrough: bytes relayed untouched; record has `kind: passthrough`; no leaf certificate minted.
- C2.5.6 Isolation: session A opening 10,000 connections and sending slow headers does not raise session B's p99 latency by more than 20%.
- C2.5.7 Go fuzzing of the request-line/header path and the `CONNECT` parser, 10 minutes each: no panic.

**Sabotage.** `allow-cl-and-te`; `resolve-twice`; `skip-link-local-block`; `websocket-always-allowed`.

**Denied.** A web application firewall. Header rewriting features. Per-request scripting hooks.

## M2.6 Performance harness

**Build.** `bench/perf`: a Go load generator and the paired-measurement method of `06` §12; scenarios for MM2.1–MM2.7; machine-readable output.

**Checks.**
- C2.6.1 Harness self-test: against a deliberately slowed broker (5 ms sleep injected) it reports an added p50 between 4.5 and 6 ms.
- C2.6.2 MM2.1–MM2.7 recorded and meeting targets.

**Sabotage.** `harness-measures-direct-twice` (the "through broker" arm bypasses the broker; C2.6.1 must fail).

**Denied.** Optimizing past the targets (D18). Benchmarks against other proxies.

---

## Exit

Exit review. No human gate. The review must state the measured numbers for H5 and what dominates the added latency.
