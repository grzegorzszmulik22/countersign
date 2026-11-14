# M8. Intent capture

**Goal.** Read what the model asked for directly from the traffic between the unmodified agent and its model provider, and what was asked of MCP servers, and turn each into a signed `intent.*` record that is durable before the sandbox can act on it.

**Properties advanced.** The declared side of P4 and P7. Prior work reads model traffic for observation only (`00` §2 item 6); here it becomes the declared side for enforcement and evidence.

**Normative references.** `04` §5; `03` §4 (`intent.*`, `context.observed`, `mcp.tools`, write-ahead rule); `02` §6 (unparsed fail-safe).

**Expected results.**
- For every tool-use block in a recorded transcript there is exactly one `intent.declared`, written before the block's final bytes reach the client.
- Parsing is independent of how the stream is chunked.
- Inspection changes nothing the client can observe except timing within the stated bounds.

**Measurements [T].**

| ID | Metric | Target |
|---|---|---|
| MM8.1 | Intents extracted vs ground truth over all transcripts × 1,000 random chunkings each | 100% equal (IDs, tools, input digests, order) |
| MM8.2 | Decoded response body digest at client vs at upstream, inspected grants | 100% equal |
| MM8.3 | Added per-event delay from inspection on a streamed model response | p99 ≤ 2 ms; at tool-use block end ≤ 6 ms p99 (one ledger commit) |
| MM8.4 | Malformed-stream corpus: broker panics / traffic corrupted / intents fabricated | 0 / 0 / 0 |
| MM8.5 | Intent windows closed correctly in the tracking corpus | 100% |

**Milestone-wide denied.** Providers other than the two named (D19). Rewriting, filtering or blocking model output. Injecting anything into prompts or responses. Storing prompts or completions. Interpreting natural-language content. Token counting or cost features. Tool-result content inspection beyond digest and length.

---

## M8.1 Inspection framework and Anthropic Messages

**Build.** `internal/inspect`: a tee on the response path of grants with `inspect: inference` that feeds an incremental parser while bytes flow; a hold point that delays only the bytes completing a tool-use block until the `intent.declared` append is acknowledged. Anthropic parser for non-streaming JSON and server-sent events: `tool_use` blocks → executor `sandbox`; `server_tool_use` → executor `provider`. Input captured as digest, length and a redacted preview.

Transcripts in `test/vectors/transcripts/anthropic/`: built from upstream documentation (save excerpts), covering: single tool call; several tool calls in one turn; interleaved text and tool calls; tool input streamed in many small fragments; empty input; very large input (1 MiB); provider-executed tool; unknown event types and unknown block types (must be ignored); error events mid-stream; stream cut mid-block.

**Checks.**
- C8.1.1 MM8.1 for the Anthropic set.
- C8.1.2 Ordering: instrumented client records when it received the last byte of each tool-use block; instrumented ledger records the ack time of the intent; ack precedes receipt in 100% of 10,000 blocks.
- C8.1.3 MM8.2 and MM8.3.
- C8.1.4 Stream cut mid-block: no intent is declared for the incomplete block; `intent.unparsed` written; client sees exactly the bytes upstream sent.
- C8.1.5 Unknown block or event types do not produce intents and do not produce `intent.unparsed`.
- C8.1.6 Fuzzing the parser 10 minutes: no panic; MM8.4.

**Sabotage.** `declare-intent-after-forwarding`; `parser-assumes-one-event-per-read`; `fabricate-intent-on-parse-error`.

**Denied.** Using a provider SDK inside the broker. Buffering whole responses to parse them.

## M8.2 OpenAI Responses and Chat Completions

**Build.** Parsers for Responses API output items of type function call (streaming and not) and Chat Completions `tool_calls` (including the streamed delta form where name and arguments arrive in fragments indexed by position). Provider-hosted tool calls → executor `provider`.

**Checks.**
- C8.2.1 MM8.1 for both OpenAI sets (same coverage list as M8.1, adapted).
- C8.2.2 Streamed argument fragments for two interleaved tool calls are assembled correctly.
- C8.2.3 C8.1.2–C8.1.6 equivalents.

**Sabotage.** `openai-merge-interleaved-fragments-by-arrival` (ignores the index).

**Denied.** Legacy function-calling field. Assistants, batch, realtime or audio endpoints.

## M8.3 Request-side tracking: results, windows, context

**Build.** Parse inference **requests** on inspected grants: find tool results referencing known intent IDs → `intent.result` (closing the window) before the request is forwarded; write one `context.observed` per request (`03` §4) with digests of blocks not seen before in the session and the running `context_sha256`. Timeouts and seal closure. Several conversations in one session are handled without a conversation identifier: intents are keyed by ID, context blocks by digest.

Tracking corpus `test/vectors/transcripts/tracking/`: sequential calls; parallel calls answered in a different order; a result that never arrives (timeout); a result for an unknown ID (ignored, warning); two interleaved conversations; a conversation that is truncated and resent (compaction: earlier blocks disappear); the same tool result resent in every later request (must close once).

**Checks.**
- C8.3.1 MM8.5.
- C8.3.2 `intent.result` is acked before the request carrying the result is forwarded (ordering assertion).
- C8.3.3 `context.observed.new_blocks` lists each block digest exactly once per session across a 50-turn conversation; `block_count` and `context_sha256` match a recomputation from the transcript.
- C8.3.4 Requests larger than `bufferLimit` on an inspected grant are denied with `LIMIT_BODY` unless the grant raises the limit; the default for inference grants is 32 MiB and is stated in the policy defaults.
- C8.3.5 The ledger contains no prompt or completion text: scan for unique marker strings planted in every transcript's text content (only previews of tool input, redacted, may appear, and none when `privacy.previews: false`).

**Sabotage.** `close-window-on-any-request`; `context-records-all-blocks-every-turn`; `store-tool-result-text`.

**Denied.** Reconstructing conversation trees. Detecting prompt injection in context. Any use of block content beyond hashing.

## M8.4 MCP inspection

**Build.** For grants with `inspect: mcp`: parse JSON-RPC over the Streamable HTTP transport at the revision pinned per `06` §8. `tools/call` requests → name, arguments (canonical digest per RFC 8785), request ID. `tools/list` results (JSON or event-stream) → `mcp.tools` with annotations. Other methods are classified as protocol traffic. The matching and enforcement that use these come in M9.

Transcripts in `test/vectors/transcripts/mcp/` built from the specification's examples and from `mcpdemo`: plain JSON responses; event-stream responses; notifications; a `tools/list` with and without annotations; pagination; an error response; a tool name with unusual characters; arguments with nested objects, unicode and numbers that stress canonicalization.

**Checks.**
- C8.4.1 Every `tools/call` in the corpus yields the expected (tool, arguments digest); canonical digests match the Python reference (`ref/python/refreconcile/jcs.py`) on 5,000 random JSON values plus the RFC 8785 test vectors.
- C8.4.2 `mcp.tools` records match the corpus ground truth, including absent annotations recorded as absent (not as false).
- C8.4.3 Byte-exact pass-through and chunk-independence as in M8.1.
- C8.4.4 A request that is not valid JSON-RPC on an `inspect: mcp` grant → denied `SMUGGLING_SUSPECT` (an MCP endpoint should receive only MCP).

**Sabotage.** `jcs-sorts-keys-bytewise` (RFC 8785 requires UTF-16 code-unit order); `annotations-default-false`.

**Denied.** Being an MCP gateway (D2): no tool filtering, no aggregation, no server registry, no authorization flows. The stdio transport. Legacy transports not in the pinned revision.

## M8.5 Privacy and redaction

**Build.** Preview generation (≤ 256 bytes), credential-shape redaction (`04` §4.4), policy switch `privacy.previews`.

**Checks.**
- C8.5.1 Tool inputs containing each credential shape: previews show `[REDACTED:<shape>]`; the digest is of the original bytes.
- C8.5.2 With previews disabled, no preview field is present in any record.
- C8.5.3 Previews never split a multi-byte UTF-8 character and never exceed 256 bytes.
- C8.5.4 Whole-ledger scan after the M8 suite: zero canary secrets, zero planted marker strings outside previews.

**Sabotage.** `preview-before-redaction`.

**Denied.** Configurable redaction rules. Encryption of previews.

---

## Exit: none (gate G4 follows M9)

Freeze `test/vectors/transcripts/**`. The exit review states, for each provider format, which documented shapes are **not** covered.
