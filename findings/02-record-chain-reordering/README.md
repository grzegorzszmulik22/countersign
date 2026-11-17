# 02 — Concurrent requests write one session's record log out of chain order

**Status:** confirmed, reproducible.

## Property

`spec/03-evidence-format.md` §2:

> | `eseq` | uint | Starts at 0 for each (session, emitter); increments by exactly 1 |
> | `eprev` | string | Record hash (§3) of the same emitter's previous record in this session; 64 zeros at `eseq` 0 |
> …
> Informative only: **all ordering decisions use `eseq` and log index, never `ts`**

`spec/03-evidence-format.md` §7:

> | `records.jsonl` | The session's envelopes in log order, byte-identical to the ledger |

`spec/03-evidence-format.md` §6 V5:

> Per emitter: `eseq` contiguous from 0; each `eprev` equals the previous
> record hash; no duplicates → `E_CHAIN`.

`spec/03-evidence-format.md` §5:

> `log/entries.jsonl` — every envelope, in append order; line N is log
> index N

## What I did

One session, one granted host. Three rounds of 120 concurrent GETs
through the broker (HTTP/2 to the broker, all authorised and forwarded to
the same upstream). After each round the test waits for the expected
`effect.http` + `effect.http.result` count and reads the session's JSONL
file, checking that `eseq` increases by exactly 1 on every line in file
order.

```
internal/proxy/rt_record_order_test.go
go test -tags fixtures ./internal/proxy -run TestRTRecordOrder -count=1 -v
```

## What happened

The file is not in chain order. Clean run 1:

```
file order breaks the emitter chain at line 241: eseq 344 after 240 (round 1)
```

Clean run 2:

```
file order breaks the emitter chain at line 3: eseq 122 after 2 (round 0)
```

In an earlier probe with 150 concurrent requests the very first line of
the file was `eseq 130`; the record with `eseq 0` appeared later. Every
round with a break fails V5 at the first offending line (or at
`first eseq is N, want 0` when the head is displaced).

## Cause

`internal/proxy/proxy.go:371` (`appendRecord`):

```go
sess.chainMu.Lock()
rec, err := sess.chain.next(rtype, body, s.emitter, sess.ID)
sess.chainMu.Unlock()
if err != nil { return err }
return s.sink.Append(sess.ID, rec)
```

The `eseq`/`eprev` pair is assigned under `chainMu`, but the durable
append happens after the lock is released. A second handler can assign
the next `eseq` and reach `RecordSink.Append` first; the sink's own mutex
then serialises the two appends in that (wrong) order. No records are
lost — they are swapped in the log.

## What should have happened

The append order must equal the chain order: hold the per-session lock
across the durable append, or have the sink take the record from the
chain in the same critical section, so line N carries `eseq` N and
`eprev` = hash of line N−1.

## Impact

A client can make its own session's evidence fail verification simply by
sending concurrent requests — no malformed input, no privileges. Under
V5 the bundle is `E_CHAIN`, so the session cannot be presented as clean.
This is a denial of evidence (and undermines P3/P6 confidence), not a way
to erase a record: the attacker cannot choose which records move, and
the set is unchanged.

## Confidence

High for the file-order/`eseq` mismatch: two clean runs failed in
different rounds, with the real `FileRecordSink`. The verifier's V5
check (`internal/evidence/chain.go`) folds records in the order it reads
them; a bundle built in file order fails at the first displaced line.

## Fix direction (not applied)

Serialize chain assignment and append under one lock. If append latency
must not block the session chain, the sink must accept a pre-assigned
sequence and buffer/reorder until the durable order matches; a plain
"assign then append" cannot preserve the chain.
