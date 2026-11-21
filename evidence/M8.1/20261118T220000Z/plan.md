# M8.1 plan — inspection framework + Anthropic Messages parser

Files to touch:
- `internal/inspect/` (new, lane-owned): `inspect.go` (types, tee/hold writer),
  `sse.go` (incremental SSE event reader), `jsonscan.go` (incremental JSON
  element-boundary scanner for non-streaming bodies), `anthropic.go`
  (tool_use/server_tool_use intent assembly), `openai.go` (M8.2),
  `request.go` + `tracker.go` (M8.3), `preview.go` (M8.5).
- `internal/creds/detect.go`: add exported `RedactNamed` emitting
  `[REDACTED:<shape>]` per span name (reuses findShapes; no shape-table copy).
- `internal/proxy/inspect_hook.go` (new, the one allowed file): session
  inspect state, request-path hook (intent.result, context.observed,
  LIMIT_BODY), response relay tee+hold, seal-close of intent windows.
- `internal/proxy/pipeline.go`: minimal call sites — effective bufferLimit
  (32 MiB default for inspect: inference), inspected-request LIMIT_BODY deny,
  request inspect hook after effect.http write-ahead, inspected relay.
- `internal/proxy/proxy.go`: one call site closing intent windows at Close.
- `test/vectors/transcripts/anthropic/*.json`: response bodies + expected
  intents, built from upstream docs (excerpts in ./upstream/).
- `internal/inspect/*_test.go`, `internal/proxy/check_m81_test.go`.
- `test/checks/check-M8.1.sh`, `test/sabotage/M8.1/*.patch`.

Checks expected: C8.1.1 (MM8.1 transcripts x1000 chunkings), C8.1.2 (ack
precedes completing-byte receipt, 10k blocks), C8.1.3 (MM8.2 digest equality,
MM8.3 delay bounds), C8.1.4 (cut mid-block -> unparsed, bytes exact),
C8.1.5 (unknown types ignored), C8.1.6 (10 min fuzz: no panic/corrupt/
fabricate). First test: feed anthropic/single-tool-call.json through the
parser at many chunkings, expect exactly the declared intent.
