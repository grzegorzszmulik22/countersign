# TRIED — every attempt, one line each

Status vocabulary: **REFUSED** = broker/refusal held; **ACCEPTED** = the
request reached the granted upstream; **FINDING** = see the folder;
**N/A** = not applicable in this build; **KNOWN-GAP** = field accepted by
policy but the control is a later chunk (M2.5/M3.x TODO).

All tests are in `internal/proxy/rt_*_test.go` (`-tags fixtures`). The
refusal battery is executable: `go test -tags fixtures ./internal/proxy
-run TestRTRefusal -count=1 -v` (passes).

## Session authentication / session confusion
1. No `Proxy-Authorization` → 407 `NO_SESSION`. REFUSED.
2. Wrong token → 407. REFUSED.
3. User other than `cs` → 407. REFUSED.
4. Valid token from the wrong source IP → 407 + `effect.denied{NO_SESSION}` in that session. REFUSED.
5. Valid token from a socket bound to 127.0.0.2 (session bound to 127.0.0.1) → 407. REFUSED.
6. Another session's token in `Proxy-Authorization` *inside* an established tunnel → token ignored for attribution; header stripped before upstream; the other session's records unchanged. REFUSED.
7. Cross-session CA/leaf use → no network path to another session's CA; per-session CA; existing C2.2.2 passes. REFUSED.
8. Token in the URL userinfo instead of `Proxy-Authorization` → not consulted; no session. REFUSED.

## Host / authority / SNI / port
9. CONNECT to an ungranted name (`sink.example.com:443`) → 403 `NO_GRANT`. REFUSED.
10. CONNECT host suffix (`evil.allowed.example.com`) → 403. REFUSED.
11. CONNECT host prefix (`allowed.example.com.evil.net`) → 403. REFUSED.
12. CONNECT superstring (`allowed.example.comm`) → 403. REFUSED.
13. Case/trailing-dot variants of the granted name → accepted as the same name (folded). ACCEPTED (intended).
14. IP literals in CONNECT: `127.0.0.1`, `0x7f000001`, `2130706433`, `127.1`, `[::ffff:127.0.0.1]` → 403 (not listed by the one-host grant). REFUSED.
15. CONNECT to granted host on ports 80, 8443, 0, 65535 → 403 `PROTOCOL_DENIED`; :443 → 200. REFUSED.
16. SNI ≠ CONNECT authority: other name, suffix, prefix, superstring, wildcard literal, port in SNI, empty SNI, name for an IP authority → TLS handshake aborted; nothing dialled. REFUSED.
17. Inner `Host` ≠ CONNECT authority (h1): other name, suffix, prefix, superstring, wrong port, empty → 403 `SMUGGLING_SUSPECT`. REFUSED.
18. Inner `:authority` ≠ CONNECT authority (h2): other name, other name + port, suffix, wrong port → 403 `SMUGGLING_SUSPECT`. REFUSED.
19. Inner absolute-form request to another host (with Host granted or Host of the other host) → 403; no forward. REFUSED.
20. Plain absolute-form to an ungranted URL host, even with a granted `Host:` header → 403 `NO_GRANT` (URL host wins). REFUSED.
21. Plain absolute-form with a granted URL host and an ungranted `Host:` header → forwarded to the granted URL host; the Host header does not move the destination (stdlib ignores it for absolute-form; the broker rewrites Host). No escape. ACCEPTED (safe).
22. Userinfo authority trick `http://allowed.example.com@evil.example.com/` → 403. REFUSED.
23. Scheme-relative/empty-host absolute-form `http:///a` with a granted Host → forwarded to the Host. No host change. ACCEPTED (safe).
24. Path beginning `//sink.example.com/` on the granted host → forwarded to the granted host as a path. No host change. ACCEPTED (safe).
25. Inner `CONNECT <other>:443` → 403; inner path-form `CONNECT /self` with Host = granted → forwarded as `CONNECT granted:443` (same host; record/wire path mismatch noted in finding 03). REFUSED for the other host, ACCEPTED for self.

## Paths, percent-encoding, dot segments
26. `/../`, `/a/../`, literal `.`/`..` segments → 403 `SMUGGLING_SUSPECT`. REFUSED.
27. `%2e%2e`, `%2E%2E`, mixed case, `/..%2f`, `%2f`, `%2F`, `%5c`, `%5C`, `%00`, raw `\` in the path → 403. REFUSED.
28. Double-encoded traversal `%252e%252e` → accepted and forwarded, further escaped on the wire; the sink is not reached (no host change). ACCEPTED; see finding 03 for the path mismatch.
29. Encoded unreserved `%41`/`%20`/`%7E` → policy decodes for matching; upstream receives the path re-escaped (`%2541`…). ACCEPTED; FINDING 03.
30. Raw `#` in the query (`/q?x=1#frag`) → upstream receives `?x=1` (query truncated at the fragment); record/digest hold `x=1#frag`. ACCEPTED; FINDING 03.
31. Trailing `?` (`/q?`) → the empty-query marker is lost on the wire. No security effect. ACCEPTED.
32. Grant glob edges: `*.dom` does not match the apex, does match one or more labels; `**` matches zero segments; `*` stays in one segment — existing M3.1/M3.6 vectors and the policy tests pass (not re-run here). REFUSED/expected.

## HTTP/2
33. h2 `:authority` deviations → 403 (item 18). REFUSED.
34. h2 client → h1 upstream and h1 client → h2 upstream → both work (existing C2.2.6). ACCEPTED.
35. h2 absolute-form `:path` attempted through `URL.Opaque` → rejected by the Go h2 client before it was sent (`invalid request :path`). N/A.
36. Duplicate pseudo-headers, CONTINUATION fragmentation, h2 stream reuse, trailers with conflicting headers → not hand-crafted; the stdlib h2 server is the parser and the broker sees only parsed fields (not-gotten-to).
37. h2 request trailers → not forwarded to the upstream (the broker writes only headers); no effect on routing. N/A.

## Upgrade / WebSocket
38. `Upgrade: websocket` without an upgrade grant → `Connection`/`Upgrade` stripped; upstream received a plain GET; client received no `Upgrade`; no byte tunnel. REFUSED.
39. Upstream answers 101 anyway → the broker relays a normal response (client saw 200 with the body); writes from the client are parsed as new HTTP requests, not tunnelled. REFUSED.
40. Policy `upgrade: [websocket]` is accepted but not implemented (upgrades are always stripped). KNOWN-GAP (M2.5).

## Redirects
41. Granted upstream 302 to the sink; the broker does not follow redirects; a following client is refused at the sink CONNECT; sink saw 0. REFUSED.

## Request smuggling / framing
42. `Content-Length` + `Transfer-Encoding: chunked` → accepted and forwarded (200); must be `SMUGGLING_SUSPECT`. FINDING 05.
43. Bare LF line endings → accepted and forwarded. FINDING 05.
44. Obsolete line folding → accepted and forwarded. FINDING 05.
45. Duplicate `Content-Length`, same value → accepted; differing values → 400 from `net/http`. REFUSED/expected.
46. Space before a header colon → 400; `Transfer-Encoding: identity` and duplicate TE → 501. REFUSED (by the stdlib).
47. CL body containing `GET http://sink/...` → the second request is consumed as the first request's body; one upstream request; no split. REFUSED.
48. Two pipelined requests inside one tunnel write → both parsed, matched and recorded separately (one allowed, one foreign-host request denied). REFUSED/expected.
49. CL/TE headers on the broker→upstream hop → the Transport excludes `Content-Length`/`Transfer-Encoding` from the copied header set and writes framing from the buffered body; no duplicate/conflicting framing observed. N/A.

## Retries / duplicate effects
50. POST with a client `Idempotency-Key`, body buffered, upstream reads it and drops the connection → the broker's transport re-sends it; upstream applied twice, one `effect.http`, client saw one 200. FINDING 01.
51. The same POST without the key → one upstream request, 502, one record. REFUSED (control).
52. GET is replayable by method → same retry path; not separately executed after the POST repro. N/A/inferred.

## DNS / upstream address
53. Granted name with a harness-resolver answer pointing at a loopback sink → canary delivered (200); no `UPSTREAM_BLOCKED`. FINDING 04.
54. Other names (routed to the same fixtures) → refused at the name gate before dialling. REFUSED.
55. Resolve-twice/rebinding race → this build resolves once per dial and performs no address check, so there is no check/connect race to exploit; the missing check is finding 04. N/A.
56. `network: cluster` → accepted by the policy loader but ignored by the data plane. KNOWN-GAP (M2.5).

## Records / evidence
57. Accepted requests had a write-ahead `effect.http` before the upstream hit in every probe (and the retry is the counterexample to the count). CHECKED.
58. `NO_GRANT`, `PROTOCOL_DENIED`, `SMUGGLING_SUSPECT` and `NO_SESSION` denials were recorded on the session (or logged when unattributable). CHECKED.
59. Concurrent requests reorder the JSONL relative to `eseq`/`eprev`; V5 would fail. FINDING 02.
60. `upstream.ip` is the host name, not the dialled address. FINDING 06.
61. Request path/query/digest differ from the forwarded target (percent paths, `#` query). FINDING 03.
62. A malformed request rejected by the stdlib produced no upstream effect and no missing-record case. CHECKED.
63. Sink failure → 502 before forwarding (existing C2.3/C2.4 design; not re-run because M2.4's ledger wiring is TODO). N/A.

## Availability
64. 300 idle TLS tunnels: +600 goroutines, +15.1 MiB heap (~49 KiB/tunnel); no crash or deadlock. Measured (NOTES).
65. No TLS handshake or idle timeout on a CONNECT tunnel; an idle tunnel is held indefinitely. Measured cost only (NOTES).
66. Request bodies up to `bufferLimit` (1 MiB default) are buffered per in-flight request; no per-session concurrency limit. By design + missing M2.5 limits (NOTES).
67. Path glob with two `**` and a non-matching long path: 120 KiB path = 1.21 s in `policy.Match` (quadratic); a ~1 MiB path would be ~85 s, because `maxUrlBytes` is not enforced. Measured (NOTES).
68. No panic found in any of the above; no coverage-guided fuzzing of the request path. N/A.

## Policy fields accepted by the loader but not enforced
69. `requires: deny` (and `intent`/`review`) → request forwarded, 200. KNOWN-GAP (04 §2 steps 3–6; 05 §2).
70. `credential`/`placeholderEnv` → no injection, no `FOREIGN_CREDENTIAL`, no `PLACEHOLDER_MISUSE`, no credential-shape detector, no response scrubbing. KNOWN-GAP (M3.2–M3.4).
71. `limits.maxRequestBodyBytes`, `maxUrlBytes`, `requestsPerMinute` → ignored. KNOWN-GAP (M3.5).
72. `inspect: inference|mcp` → ignored; no intent windows, no inspection. KNOWN-GAP (M8/M9).
73. `mode: passthrough` → still intercepted (the grant is not tunnelled raw). KNOWN-GAP (M2.5).
74. `upgrade: [websocket]` → ignored (item 40). KNOWN-GAP (M2.5).
75. `network: cluster` → ignored (item 56). KNOWN-GAP (M2.5).

**Attempt rows: 75.** Several rows bundle a family (the path-encoding
row covers seven spellings; the CONNECT-edge row covers thirteen
authorities). Failures of the refusal controls: none found.
