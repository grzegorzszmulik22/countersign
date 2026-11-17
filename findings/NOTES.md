# NOTES — unconfirmed observations, measurements, and known gaps

Everything here is either a measurement or something I did **not** turn
into a numbered finding. The numbered findings are in
`findings/0*/README.md`.

## Known-gap fields accepted by the policy loader (M2.5/M3.2–M3.5/M8/M9 TODO)

`docs/policy-schema.md` says 04 §2 steps 3–6 are later chunks, and
`spec/PROGRESS.md` marks M2.4, M2.5, M2.6, M2.7 and M3.2–M3.5 TODO. The
current data plane accepts these fields at load time but does not
implement them:

| Field / chunk | Observed behaviour | Evidence |
|---|---|---|
| `requires: deny` (04 §1, 05 §2) | GET forwarded, 200, upstream hit | one-off probe `rt_requires_probe` (deleted after measurement); `go test` output: `requires=deny: status=200 upstream_hits=1` |
| `credential`, `placeholderEnv` (M3.2) | no injection; the client's header/placeholder is forwarded as-is, or the inject location is simply absent; no `FOREIGN_CREDENTIAL` / `PLACEHOLDER_MISUSE` | code search: no credential handling in `internal/proxy` outside the record field names |
| `limits.maxRequestBodyBytes`, `maxUrlBytes`, `requestsPerMinute` (M3.5) | ignored | 1 MiB request paths accepted; quadratic glob below |
| `inspect: inference|mcp` (M8/M9) | ignored; no `intent.*` records, no inspection, no window | code search |
| `mode: passthrough` (M2.5) | the grant is still TLS-intercepted and served by the inner HTTP server | code reading: `handleConnect` never looks at `Grant.Mode` |
| `upgrade: [websocket]` (M2.5) | always stripped, so an upgrade can never succeed | `TestRTRefusalRedirectAndUpgrade` |
| `network: cluster` (M2.5) | ignored in both directions | finding 04 |

These are not counted as findings because the milestone table already
says they are not built; a supervisor who treats M2.5/M3.5 as in scope
can promote the `requires` row and finding 05/04 accordingly.

## Measurements

### Idle CONNECT tunnels

300 tunnels to the granted host, TLS handshaken, no request (30 s of
`ReadHeaderTimeout` not yet reached; no idle timeout exists):

```
idle tunnels: 300; goroutines 5 -> 605 (+600);
heap 1,130,496 -> 16,220,160 (+15,089,664 bytes, 49.1 KiB/tunnel)
```

Extrapolation: ~49 MiB per 1,000 idle tunnels (MM2.6's target is
≤300 MiB, so this size passes), ~490 MiB per 10,000. There is no
per-session limit (M2.5's 256-connection cap is not built) and no TLS
handshake deadline or idle timeout, so the cost is held until the client
or the OS closes the socket. To exhaust a 1 GiB heap needs roughly
21,000 tunnels and almost no payload; the practical limit is the OS
handle/port table, not the broker. No crash or deadlock was observed at
300.

### Request buffering

Each in-flight request body is buffered up to `bufferLimit` (1 MiB by
default) before the write-ahead record; larger bodies stream after
1 MiB + 1 buffered. There is no per-session cap on concurrent requests
or streams, so memory scales with concurrency: 1,000 uploaded MiB =
~1 GiB of broker heap. This is the specified buffer design (03 §4.5);
the missing part is M2.5's concurrency limit.

### Quadratic path-glob matching

`matchSegs` backtracks over `**`. A glob with two `**` and a
non-matching long path is quadratic. Direct `policy.Match`, policy
`paths: ["/**/files/**/needle"]`, path of repeated `files` segments
ending in `tail`:

| path bytes | segments | time |
|---|---|---|
| 12,005 | 2,000 | 8.6 ms |
| 30,005 | 5,000 | 56.6 ms |
| 60,005 | 10,000 | 255.7 ms |
| 120,005 | 20,000 | 1.215 s |

The stdlib request-header limit allows ~1 MiB of request target, so one
request is ~85 s of CPU; two concurrent requests occupy both cores
(GOMAXPROCS=2). This needs a policy glob with two `**` and a failing
match; `/ **/files/**/needle` is contrived but `/orgs/**/repos/**/issues`
with no `issues` is the same shape. `maxUrlBytes` (2048 by default, M3.5)
is not enforced. Not a numbered finding because it needs the operator to
write such a glob and depends on a missing limit; if the supervisor wants
a DoS finding, this is the strongest measured one.

### Retry without an idempotency header

GET/HEAD/OPTIONS/TRACE are replayable by method in `net/http`; the same
invisible retry as finding 01 applies to a GET that the upstream received
and answered with a dropped connection. I did not build a separate GET
repro (the POST case is stronger and exercises the same code path).

## Possible issue not reproduced (clearly unconfirmed)

`intercept` serves the tunnel through a `oneConnListener`; when
`deadConn.Read` sees a non-timeout error such as `io.EOF`, `Accept`
returns and `intercept` calls `inner.Close()`. A client that sends a
request and then half-closes its write side (TCP FIN, still expecting the
response) may therefore have its in-flight response force-closed before
the handler/relay finishes. I did not build a deterministic repro and did
not observe a lost result record; the result writer is a defer inside
`forward`. Treat as unconfirmed; worth a targeted test if half-close is a
supported client pattern.

## Not covered

- Raw HTTP/2 frame construction: duplicate `:authority`, pseudo-header
  after a regular header, CONTINUATION fragmentation, stream reuse. The
  broker consumes parsed fields from `net/http`'s h2 server; I exercised
  the h2 client's `:authority` mismatches (denied) and h1↔h2 ALPN, but
  not the frame-level parser. Contract: the stdlib is the parser.
- Raw TLS ClientHello pipelined in the same TCP segment as the CONNECT
  request. `handleConnect` hijacks and passes the raw `net.Conn` to
  `tls.Server`, ignoring bytes already buffered by the hijack's
  `bufio.Reader`; a pipelined ClientHello would be lost and the handshake
  would hang (no handshake deadline). I did not test this; it would be a
  client-only self-DoS, not an exfil path.
- M2.4's real ledger wiring; the current `FileRecordSink` is the interim
  local sink, but finding 02 is in the broker's chain/append sequence, not
  in the sink.
- Coverage-guided fuzzing of the request-line/header/CONNECT parsers.
- The `counter sign.internal` boundary endpoint (not implemented in this
  slice).
- Credential-shape detection, response scrubbing, tapes, worlds,
  staging: later milestones.
