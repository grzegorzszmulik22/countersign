# 01 — The broker silently retries an upstream POST: two effects, one record

**Status:** confirmed, reproducible.

## Property

`spec/milestones/M2-broker-data-plane.md` (Milestone-wide denied):

> **Any retry of upstream requests by the broker.**

`spec/03-evidence-format.md` §4.5:

> **Write-ahead.** `effect.http` is durably appended and acknowledged
> **before** the first byte goes upstream …

`spec/03-evidence-format.md` §4.2 defines one `effect.http` and one
`effect.http.result` per effect. M2.4 C2.4.5 states the accounting
property:

> Record count equals request count at `echo` plus denied count over a
> 100,000-request mixed run (exact equality).

## What I did

One session, one granted host (`allowed.example.com`). The test:

1. sends a warm GET so the broker's shared `http.Transport` has an idle
   keep-alive connection to the upstream;
2. sends a POST with a small buffered body and a client-chosen
   `Idempotency-Key` header;
3. the upstream reads the whole request and records it, then closes the
   TCP connection without writing any response byte — a connection
   failure *after* the upstream applied the effect;
4. repeats for three paths.

The request body is below `bufferLimit`, so `forward` hands
`http.NewRequestWithContext` a `*bytes.Reader`. `net/http` sets
`GetBody` on that request, the client's `Idempotency-Key` header survives
`stripHopByHop`, and `Request.isReplayable` therefore returns true for the
POST. `persistConn.shouldRetryRequest` retries it because the connection
was reused.

`findings/01-retry-unrecorded-effect/repro-rt_retry_unrecorded_test.go.txt`
is a copy; the live test is:

```
internal/proxy/rt_retry_unrecorded_test.go
go test -tags fixtures ./internal/proxy -run TestRTRetryUnrecorded -count=1 -v
```

## What happened

Every iteration:

```
VULNERABLE: /paid-0: client status=200, upstream saw 2 POSTs, broker recorded 1 effect.http
VULNERABLE: /paid-1: client status=200, upstream saw 2 POSTs, broker recorded 1 effect.http
VULNERABLE: /paid-2: client status=200, upstream saw 2 POSTs, broker recorded 1 effect.http
broker retried an upstream POST: upstream requests=[GET /warm POST /paid-0 POST /paid-0 POST /paid-1 POST /paid-1 POST /paid-2 POST /paid-2],
broker POST records=map[/paid-0:1 /paid-1:1 /paid-2:1]
```

The client saw a single `200`. The broker wrote one `effect.http` and one
`effect.http.result` per POST, with the same body digest. The upstream
executed the POST twice. The broker also logged one
`upstream POST allowed.example.com: EOF` before the retry, so it knew the
first attempt had failed, but did not record or surface it.

Control: the identical POST **without** `Idempotency-Key` is not
replayable, gets one upstream request and a `502 upstream failed`.
A GET is replayable regardless of headers.

## What should have happened

No retry, per M2's denied list. One upstream request per effect record;
if the first attempt's outcome is unknown, a result with an error and no
retry (this is the "dangling"/unknown posture of `02` §6). The upstream
request count must equal the `effect.http` count (C2.4.5).

## Impact

- A client can turn one irreversible effect (a payment, an issue, a push
  delivered by POST) into two on the allowed upstream by attaching an
  `Idempotency-Key` and letting an ordinary connection drop; the client
  sees one success and the evidence shows one effect. This is an
  unrecorded upstream request in the sense of goal 2.
- The header is entirely client-controlled; the policy has no header
  allowlist, and M2 does not permit the broker to treat a client-supplied
  idempotency hint as permission to replay.
- A dropped keep-alive connection after a request was received is not
  exotic: load balancers retire connections, servers enforce
  max-requests-per-connection, and networks reset.

## Confidence

High. The reproduction failed identically on two clean runs, three
iterations each; the independent upstream log and the broker's JSONL
disagree in every iteration.

## Fix direction (not applied)

Do not give `net/http` a replayable request: clear `GetBody` on the
outbound request, wrap the body in a non-replayable reader, or use a
transport that refuses retries. Also consider not forwarding
`Idempotency-Key` unless the policy grants it; the milestone denies
broker retries outright.
