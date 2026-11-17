# 05 — Smuggling pre-checks absent: CL+TE, bare LF and obsolete line folding are forwarded

**Status:** confirmed, reproducible. **Scope note:** M2.5 ("Protocol edges
and hardening") is listed TODO in `spec/PROGRESS.md`; this finding records
the current gap and gives it an executable reproduction, as the brief
asks for smuggling attempts.

## Property

`spec/04-policy-and-reconciliation.md` §2, step 1:

> **Pre-checks**, each denying before any grant is consulted:
> - CONNECT authority, TLS SNI and HTTP `Host`/`:authority` must be
>   identical after lowercasing → else `SMUGGLING_SUSPECT`.
> - Reject requests with both `Content-Length` and `Transfer-Encoding`,
>   multiple differing `Content-Length`, obsolete line folding, or bare
>   LF in headers → `SMUGGLING_SUSPECT`.
> - Reject paths containing dot segments (`.`, `..`), `\`, control
>   characters, or the percent-encoded forms `%2e`, `%2f`, `%5c`, `%00`
>   in any letter case → `SMUGGLING_SUSPECT`.
> - Host given as an IP literal → `NO_GRANT` unless a grant lists that
>   literal.

M2.5 C2.5.1:

> Request-smuggling corpus (… CL+TE, TE obfuscations, duplicate CL, bare
> LF, line folding, absolute-form with conflicting Host …): every case
> is rejected with `SMUGGLING_SUSPECT` or parsed identically by broker
> and `echo`. None reaches `echo` as two requests.

## What I did

Plain listener, a grant for `allowed.example.com` on HTTP, an independent
upstream that records every request, and raw request bytes:

1. `Content-Length: 6` together with `Transfer-Encoding: chunked`, body
   `0\r\n\r\n`;
2. a request with bare-LF line endings;
3. a request with an obsolete folded header (`X-A: one` / ` two`).

```
internal/proxy/rt_smuggling_prechecks_test.go
go test -tags fixtures ./internal/proxy -run TestRTSmugglingPrechecks -count=1 -v
```

## What happened

```
cl-and-te: status=200 reason="" upstream_forwarded=true
bare-lf:   status=200 reason="" upstream_forwarded=true
obs-fold:  status=200 reason="" upstream_forwarded=true
```

All three were accepted and reached the upstream. `net/http`'s own
parser made each a single request (it used chunked framing for CL+TE,
accepted LF-only lines, and treated the folded line as a header
continuation), so I did **not** turn them into a second upstream request:
the impact here is the missing refusal, not a demonstrated splitting. The
`Content-Length` header is excluded from Go's outbound header write, and
the broker sets the framing from the body it buffered, so I also did not
get a broker→upstream framing conflict.

For completeness, the same probe found these were already refused by
`net/http`: duplicate differing `Content-Length` (400), space before a
colon in a header name (400), `Transfer-Encoding: identity` and duplicate
chunked/identity (501).

Path pre-checks (dot segments, `%2e/%2f/%5c/%00`, `\`) are implemented
and were refused; see `findings/TRIED.md`.

## What should have happened

`403` with `X-Countersign-Reason: SMUGGLING_SUSPECT` and no upstream
request, for every case in the list. (The reason should also be recorded
as the denial the broker already writes for other `SMUGGLING_SUSPECT`
cases.)

## Impact

Defence in depth. Today the request that reaches the upstream is the one
`net/http` parsed, not necessarily what another parser at the upstream
edge would see; the specification requires the broker to make the edge
uniform. Once an origin/reverse proxy in front of the upstream uses a
different parser (the reason the pre-check exists), CL+TE/LF/folding are
the classic desync surface; the broker is the component that is supposed
to normalise or refuse them.

## Confidence

High for the observed acceptance and forwarding (two clean runs). The
"known missing M2.5" classification is documented in `spec/PROGRESS.md`.

## Fix direction (not applied)

Add the §2 step-1 pre-checks on the raw bytes (a connection wrapper that
sees the header block before `net/http`), or configure a strict parser,
and make sure the denial is written before any upstream byte. The
`SMUGGLING_SUSPECT` plumbing and recording already exist for the
authority-mismatch cases.
