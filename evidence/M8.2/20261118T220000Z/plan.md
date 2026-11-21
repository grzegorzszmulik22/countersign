# M8.2 plan — OpenAI Responses + Chat Completions parsers

Files to touch:
- `internal/inspect/openai.go`: respParser (Responses API: non-streaming
  function_call output items; streaming output_item.added/argument deltas/
  done/output_item.done keyed by output_index) and chatParser (Chat
  Completions: non-streaming tool_calls; streamed deltas indexed by
  choice/tool-call index, name+arguments assembled in fragments).
  Hosted/provider tools → executor provider; done/delta events for unknown
  indexes are parse faults, never silently dropped.
- `internal/inspect/provider.go`: endpoint→parser selection + content type.
- `test/vectors/transcripts/openai/`: wire bodies + Python-reference ground
  truth (upstream excerpts in ./upstream/).
- `test/checks/check-M8.2.sh`, `test/sabotage/M8.2/*.patch`.

Checks expected: C8.2.1 (MM8.1 over both OpenAI sets ×1000 chunkings),
C8.2.2 (interleaved argument fragments assemble by index), C8.2.3
(ordering/byte-exactness/malformed/unknown/fuzz equivalents through the
broker). First test: resp-single-json and chat-single-sse through the
parsers at many chunkings, equal to ground truth.
