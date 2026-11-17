# M2.2 plan — TLS interception

Files: `internal/proxy/{ca,intercept,keystore}.go` (replacing the raw CONNECT relay), tests under `internal/proxy` with `fixtures` tag, `test/checks/check-M2.2.sh`, `test/sabotage/M2.2/*.patch`.

Design: per-session ECDSA P-256 CA minted at session open (in memory; keys only ever serialized inside `keystore.go` — the session-key store interface). CONNECT accepted → `tls.Server` with `GetCertificate` minting a leaf for the SNI name (validity 24 h, per-session LRU 4096) and NextProtos [h2, http/1.1]; SNI != CONNECT authority fails the handshake + `effect.denied` SMUGGLING_SUSPECT. Served via `http.Server` over a single-conn listener so stdlib h1+h2 both work. Inner requests get full `policy.Match` (SNI/CONNECT/Host cross-check -> SMUGGLING_SUSPECT / NO_GRANT) then forward over `https` (DialTLSContext records conn info; system roots + test root under fixtures tag; min TLS 1.2; independent ALPN).

Checks: C2.2.1 h1+h2 over session CA, C2.2.2 cross-session leaf rejected, C2.2.3 bad upstream certs -> 502 UPSTREAM_TLS, C2.2.4 SNI/Host mismatch, C2.2.5 key confinement (runtime scan + static call-site grep), C2.2.6 ALPN mix, C2.2.7 1000 names + LRU bound.

Sabotages: `skip-upstream-verify`, `shared-ca-across-sessions`, `ignore-sni-mismatch`.
