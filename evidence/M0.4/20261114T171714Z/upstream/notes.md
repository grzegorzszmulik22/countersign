# Upstream checks for M0.4 (06-agent-loop.md §8)

Reused from evidence/M0.3/20261114T162406Z/upstream/ (fixtures lane,
checked 2026-11-14):

- `mcp.md` — MCP current revision is **2026-07-28**: stateless (no
  initialize handshake), `server/discover` mandatory, every request
  carries `_meta.io.modelcontextprotocol/protocolVersion` and
  `Mcp-Method` header (`Mcp-Name` on tools/call). scriptagent's MCP
  client implements exactly this transport.
- `anthropic.md` — Messages API: tool_use blocks `{id,name,input}` with
  `input_json_delta` partial-JSON streaming; tool results are user-role
  `tool_result` blocks keyed by `tool_use_id`.
- `openai.md` — Responses `function_call` items (`call_id`,
  string `arguments`); Chat Completions `tool_calls[].function` with
  finish_reason `tool_calls`; results via `function_call_output` /
  `role:"tool"` messages.

## Sandbox base image pin (ARM64 consequence, 06 §11)

`ubuntu:24.04` manifest list inspected 2026-11-14; linux/arm64 image
manifest digest `sha256:c92376659a7f14cc1f51615d73c9f4b7d8e18d59f370e02b4ed683ab4485c66c`
(pinned in test/fixtures/scriptagent/Dockerfile). `docker manifest
inspect ubuntu:24.04` output captured in this folder's output.log
records the arm64 entry.
