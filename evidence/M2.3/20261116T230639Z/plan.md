# M2.3 plan — streaming and digests

Files: `internal/proxy/forward.go` (streaming relay, digests, abort), `digest.go` (04 §3 request_digest), tests `internal/proxy/*_test.go` (fixtures), `test/checks/check-M2.3.sh`, `test/sabotage/M2.3/*.patch`.

Design: request bodies <= grant bufferLimit buffered -> `body_sha256` + `request_digest` in the write-ahead `effect.http`; larger/unknown -> `body_deferred: true`, digest lands in `effect.http.result.request_body`. Responses copied read->write->Flush every write (SSE/chunked/h2), trailers via `Trailer:` + `TrailerPrefix`, request context propagates so client-abort closes the upstream conn (result `error: client-abort` + partial byte count). SHA-256 on the fly both directions.

Checks: C2.3.1 byte equality 0/1/1KiB/1MiB/1MiB+1/1GiB both directions vs streaming digest upstream, C2.3.2 1000 SSE events @10ms separate reads + MM2.3, C2.3.3 write-ahead vs deferred digests, C2.3.4 client abort <=1s, C2.3.5 MM2.5 <=64MiB RSS growth.

Sabotages: `buffer-whole-response`, `digest-computed-after-truncation`, `no-flush-on-sse`.
