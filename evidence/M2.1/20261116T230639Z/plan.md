# M2.1 plan — proxy listener and sessions (local mode)

Files: `internal/proxy/{proxy,session,auth,connect,forward,records,keystore,ca,digest,headers,ulid}.go`, `cmd/csbroker/main.go`, `test/checks/check-M2.1.sh`, `test/sabotage/M2.1/*.patch`.

Design: `proxy.Server` wraps an `http.Server` handler that routes CONNECT vs absolute/origin-form. Session table YAML (`id, token, client_ip, policy`); auth = `Proxy-Authorization: Basic cs:<token>` AND remote IP must equal the session's client_ip (both must agree, 02 §3). Grants evaluated via `internal/policy.Match` (§2 steps 1-2). Records: JSONL `effect.denied`/`effect.http` under `--records-dir` (real ledger lands in M2.4; sink is synchronous append+fsync so write-ahead ordering already holds). CONNECT: grant host+port+scheme check (NO_GRANT / PROTOCOL_DENIED), then raw tunnel relay (TLS interception arrives in M2.2). Hop-by-hop headers stripped; `Proxy-Authorization` never forwarded.

Checks: C2.1.1 auth matrix (407/NO_SESSION + unattributed log line + attributable effect.denied), C2.1.2 NO_GRANT + deny record, C2.1.3 hop-by-hop via raw absolute-form + tunneled client, C2.1.4 CONNECT port, C2.1.5 scheme http. First test written: `TestC211SessionAuth`.

Sabotages: `token-only-no-ip-check`, `forward-proxy-authorization`.
