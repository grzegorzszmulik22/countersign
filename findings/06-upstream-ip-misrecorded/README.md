# 06 — `upstream.ip` in the result record is the host name, not the resolved address

**Status:** confirmed, reproducible.

## Property

`spec/03-evidence-format.md` §4.2 (`effect.http.result`):

> `upstream?{ip, port, tls_version?, cert_sha256?}`

`spec/04-policy-and-reconciliation.md` §2, step 3:

> The broker resolves the name once and connects to that address. …
> The resolved address is recorded.

## What I did

One granted host, one GET, then read the `effect.http.result` record for
that request:

```
internal/proxy/rt_upstream_ip_test.go
go test -tags fixtures ./internal/proxy -run TestRTUpstreamIP -count=1 -v
```

## What happened

```
upstream.ip = "allowed.example.com" is not an IP address
```

The rest of the record looks plausible — `port: 443`,
`tls_version: "1.3"`, `cert_sha256` — but `ip` holds the requested
hostname, because `upstreamTransport` fills `UpstreamRecord.IP` from the
`addr` string it was asked to dial (`forward.go:63-69`, `forward.go:71-100`)
rather than from the connected peer's address.

## What should have happened

`upstream.ip` is the resolved/dialled address (e.g. `127.0.0.1` for the
test upstream), with the name already available from
`request.authority` and the certificate. A verifier or auditor can then
compare the record against the address the broker actually dialled — the
property 04 §2 step 3 calls "the address connected to always equals the
address recorded" (M2.5 C2.5.3).

## Impact

Evidence quality. With a name in an IP field, a consumer that parses
`ip` fails, and no one can tell whether two sessions reached the same
peer, whether a name resolved to an unexpected address (finding 04), or
whether DNS changed between sessions. It also makes the record look
address-checked when no check exists.

## Confidence

High; two clean runs. The "resolved address" control itself is M2.5 TODO,
but the field is populated today with a value of the wrong kind, in the
implemented M2.2/M2.3 pipeline.

## Fix direction (not applied)

Populate the record from `net.Conn.RemoteAddr()` of the connection that
`httptrace.GotConn` reports (or from the address the resolver returned
and dialled), keeping the value that was actually connected.
