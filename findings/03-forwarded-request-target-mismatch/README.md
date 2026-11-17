# 03 — The forwarded request-target is not the recorded one: paths are re-escaped, `#` truncates the query

**Status:** confirmed, reproducible.

## Property

`spec/04-policy-and-reconciliation.md` §3 (request digest):

> request_digest = SHA-256(
>   "countersign-request-v1\n" ‖
>   METHOD ‖ "\n" ‖
>   scheme ‖ "\n" ‖
>   authority ‖ "\n" ‖            lowercase host, ":port" only if non-default
>   raw-path ‖ "\n" ‖             exactly as received
>   hex(SHA-256(raw-query)) ‖ "\n" ‖   raw query without "?", empty string if none
>   …

`spec/03-evidence-format.md` §4.2 (`effect.http`):

> `request{method, scheme, authority, path, query_sha256, query_len, …}`

`spec/milestones/M2-broker-data-plane.md`:

> Every request that reaches an upstream has an `effect.http` record that was durable first
> … the digest seen by `echo` equals the digest sent

## What I did

Granted one host (`allowed.example.com`), started an independent HTTPS
upstream that records `r.RequestURI`, and sent through an intercepted
tunnel:

- `GET /a%41b`
- `GET /q?x=1#frag`

and through the plain listener:

- `GET http://allowed.example.com/a%41b`

Then compared the upstream's log with the `effect.http` record fields and
the client's original target.

```
internal/proxy/rt_request_target_test.go
go test -tags fixtures ./internal/proxy -run TestRTRequestTarget -count=1 -v
```

## What happened

```
path:  upstream request-target "/a%2541b", broker record path "/a%41b"
query: upstream request-target "/q?x=1", broker recorded path "/q" and query_len 8
plain: upstream request-target "/a%2541b", broker record path "/a%41b"; want /a%41b on both
```

The record's `query_sha256` is SHA-256 of `x=1#frag` and `query_len` is 8;
the upstream received `?x=1` only. The record's `request_digest` is
computed over the original path/query, so it does not describe the bytes
on the wire.

### Cause

`internal/proxy/pipeline.go:257` builds the outbound URL as:

```go
upURL := &url.URL{Scheme: tgt.scheme, Host: dialAuthority,
    Path: tgt.path, RawPath: tgt.path, RawQuery: tgt.rawQuery}
upReq, err := http.NewRequestWithContext(..., upURL.String(), bodyReader)
```

`tgt.path` is an escaped path (`r.URL.EscapedPath()`). Setting `Path` to
that same escaped string makes `RawPath` invalid as an encoding of
`Path` (`unescape(RawPath) != Path`), so `URL.String()` ignores `RawPath`
and escapes `Path` again: every `%` becomes `%25`. Reparsing the string
in `NewRequest` fixes the double escape on the wire. Separately, a raw
`#` in `RawQuery` survives `URL.String()` but a fragment is split off
when the string is parsed again, so the query is truncated at `#`.

The same happens on the plain listener, because both listeners converge
on `forward`.

Related observation (not the core of this finding): an inner
`CONNECT /self` is recorded as method CONNECT with path `/self`, but the
wire request is `CONNECT allowed.example.com:443` — Go's client writes
authority-form for CONNECT and ignores the path. The record again names
a target that was not sent.

## What should have happened

The forwarded request-target must be byte-identical to the raw path and
raw query recorded in the write-ahead effect, so the upstream log, the
record and `request_digest` agree. (If the broker intentionally rewrites
a target, that rewritten target must be what it records; it currently
records the original.)

## Impact

- Goal 2: an allowed request reaches the upstream with a record that
  misstates the path (and, with `#`, the query). A reviewer or an
  auditor comparing the broker's evidence with the upstream's access log
  sees two different requests.
- Functional: any upstream API with percent-encoded segments
  (`/files/a%20b`, signed path URLs, encoded repository names) receives a
  different path and may 404 or route differently. Existing byte-equality
  tests use paths without `%`, so they miss it.
- Policy/effect divergence: `match.paths` is evaluated on the *decoded*
  raw path, but the upstream receives a *re-escaped* path. I did not find
  a host/port escape from this (the over-escaping makes traversal harder,
  and the authority is independent), but authorization and effect are not
  about the same bytes.

## Confidence

High. Two clean runs, both listeners, upstream log compared with the
JSONL record.

## Fix direction (not applied)

Build the outbound URL without a decode/encode round trip: either set
`Opaque`/`RawPath` correctly with an unescaped `Path`, or write the
request line from the recorded raw path and query directly. Reject or
preserve `#` in the raw query rather than letting `URL.String()` reinterpret
it as a fragment.
