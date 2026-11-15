# Upstream check: Anthropic Messages API (06-agent-loop.md §8)

Checked 2026-11-14 against https://docs.anthropic.com/en/api/messages-streaming
(redirects to platform.claude.com docs; "status: stable").

## Streaming event names (SSE `event:` + JSON `type` match)

`message_start` (Message object with empty `content`), `content_block_start`
(`index` + `content_block`), `content_block_delta`, `content_block_stop`,
`message_delta` (top-level changes incl. `stop_reason`, cumulative `usage`),
`message_stop`, `ping`, `error`.

## Tool-use block shapes

- Non-streaming/streamed block: `{"type":"tool_use","id":"toolu_01T1x1fJ34qAmk2tNTrN7Up6","name":"get_weather","input":{...}}`.
- `content_block_start` carries the block with empty `input: {}`; input arrives
  as deltas `{"type":"input_json_delta","partial_json":"{\"location\":"}` —
  partial JSON *strings*; final `input` is an object.
- Provider-executed tools: `{"type":"server_tool_use","id":"srvtoolu_014h...",
  "name":"web_search","input":{}}` — same delta mechanism.
- `stop_reason: "tool_use"` in `message_delta` when the turn ends for tools.
- `error` events may appear mid-stream; stream may be cut mid-block.

## Request side

`POST /v1/messages` body: `{model, max_tokens, messages:[{role, content}],
stream?}`. Tool results sent back as user-role content blocks
`{"type":"tool_result","tool_use_id":"toolu_...","content":...}` — this is what
mockllm validates per incoming turn.
