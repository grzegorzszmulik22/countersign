# M8.3 plan — request-side tracking: results, windows, context

Files to touch:
- `internal/inspect/request.go`: ParseRequest for the three endpoints —
  tool_result blocks / function_call_output / role:tool messages →
  intent.result candidates (digest+length+error only); every content block
  → context digest candidates.
- `internal/inspect/tracker.go`: session-scoped Tracker — Declare dedups
  IDs (sandbox opens a window, provider does not), CloseForResult closes
  once, Timeouts ages windows out, Seal closes the rest; Observe dedups
  context blocks by digest with running count and context_sha256.
- `internal/proxy/inspect_hook.go` + pipeline.go call sites: timeout sweep
  then results then context.observed, all durable before forward; 32 MiB
  inference bufferLimit default; sealIntents at Server.Close.
- `test/vectors/transcripts/tracking/`: multi-step scenarios +
  step-indexed ground truth.
- `test/checks/check-M8.3.sh`, `test/sabotage/M8.3/*.patch`.

Checks expected: C8.3.1 (MM8.5 window closure corpus), C8.3.2 (result ack
before carry-forward), C8.3.3 (context dedup, count, digest vs
recomputation over 50 turns), C8.3.4 (LIMIT_BODY), C8.3.5 (no text in
ledger). First test: sequential scenario — declare, result, close once.
