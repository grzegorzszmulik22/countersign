# M2.7 plan — local runner (cs run)

- `cmd/cs run [--policy F] [--cooperative] -- CMD`: in-process `csledger` file store + `csbroker --local` (proxy.NewServer public API), session token + table, session.open (adds `boundary` field), sink bridge proxy.Record → evidence DSSE → ledger.
- Enforced (default): re-exec `cs __init` with NEWUSER|NEWNS|NEWNET|NEWPID; inside: `lo` up, empty tmpfs over data dir, TCP relay on 127.0.0.1:0 splicing to parent unix socket; parent unix listener dials ONLY the broker loopback. Agent env: proxy vars → relay, trust vars → session CA pem in run dir, NO_PROXY="", placeholder creds.
- Probe: re-exec `cs __probe` attempting the real namespace+tmpfs+lo path; refuses with one-sentence --cooperative message; result recorded to probe.json. `CS_RUN_PROBE_OVERRIDE` test hook.
- Cooperative: same env straight to broker loopback, no namespaces; boundary recorded.
- SIGINT: forward to in-ns init → kills pid-ns tree; parent waits, kills after grace; then seal (session.seal controller emitter) + ExportBundle; exit = command status / 130.
- csverify: VerifyResult gains `boundary` from session.open; prints in every verdict.
- Checks: check-M2.7.sh + internal/runner/check_m27_test.go (-tags fixtures); leak probes TCP/UDP/IPv6/unix/relay-spoof; env -i grandchild; curl/git/python-urllib/node through broker; canary scan env+files+/proc; probe-override; SIGINT tree-kill + csverify + pinned-python reverify; cooperative reachability + boundary. Sabotage patches ×3.
