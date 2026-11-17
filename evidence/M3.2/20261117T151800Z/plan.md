# M3.2 plan — credential store, placeholders, injection

- internal/creds: Store interface + FileStore (YAML `secrets: {name: {key: value}}`) + KubeStore (interface only, M4), placeholder `csph_<8hex sha256(session)>_<grant>_<22 base62>`, header+Basic injection.
- internal/proxy: session entry gains `credentials` path; Session gets placeholder map + store + rate table; pipeline order per 04 §2 — limits (M3.5) -> credential rules (M3.3) -> write-ahead record with decision.credentials -> inject -> upstream -> scrub (M3.4).
- Checks first: check_m32_test.go (C3.2.1 inject w/ placeholder, C3.2.2 absent location, C3.2.3 path outside grant NO_GRANT, C3.2.4 git basic via fakehub, C3.2.5 50k invariant vs match.py, C3.2.6 inject-after-ack) then check-M3.2.sh.
- Sabotages: inject-by-host-only, log-secret-value-in-record, inject-before-ack.
- Docs: docs/credentials.md (one page).
