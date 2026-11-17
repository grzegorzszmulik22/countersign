# Upstream check: Model Context Protocol (06-agent-loop.md §8)

Checked 2026-11-14 against https://modelcontextprotocol.io/.

## Current revision

`specification/versioning` states the **current** protocol version is `2026-07-28`
(spec says "current revision ... at the revision pinned per §8" → pin `2026-07-28`).

Note: this differs from older revisions the milestone text was probably written
against (2025-03-26/2025-06-18). Changelog for 2026-07-28 (upstream excerpts):

- "Remove protocol-level sessions and the `Mcp-Session-Id` header from the
  Streamable HTTP transport."
- "Make MCP stateless: remove the `initialize`/`notifications/initialized`
  handshake. Every request now carries its protocol version and client
  capabilities in `_meta` (`io.modelcontextprotocol/protocolVersion`,
  `io.modelcontextprotocol/clientCapabilities`)."
- "Add `server/discover`: servers MUST implement this RPC to advertise their
  supported protocol versions, capabilities, and identity."
- "Replace the HTTP GET endpoint ... with `subscriptions/listen`."
- "All results now carry a required `resultType` field: `"complete"` ...
  `"input_required"`."
- "Remove SSE stream resumability and message redelivery (the `Last-Event-ID`
  header and SSE event IDs)."
- "Require standard MCP request headers (`Mcp-Method`, `Mcp-Name`) on
  Streamable HTTP POST requests."
- "Require `ttlMs` and `cacheScope` fields on results returned by `tools/list`,
  ... via a new `CacheableResult` interface."

## Streamable HTTP transport (2026-07-28)

- Single endpoint path supporting POST only (GET removed).
- Client MUST send `Accept: application/json, text/event-stream`.
- Notification POSTs: 202 Accepted, no body. Request POSTs: `application/json`
  single object or `text/event-stream` scoped to that request.
- Required headers: `MCP-Protocol-Version` (MUST match
  `_meta.io.modelcontextprotocol/protocolVersion`, else 400 HeaderMismatch
  -32020), `Mcp-Method` (all requests), `Mcp-Name` (tools/call, resources/read,
  prompts/get; Base64 sentinel encoding `=?base64?...?=` when not ASCII-safe).
- Unsupported version → 400 + `UnsupportedProtocolVersionError` (-32022)
  listing supported versions. Unknown method → 404 + JSON-RPC -32601.
- Server MUST validate `Origin` (403 on invalid).

## tools/list, tools/call, annotations (schema.ts @ 2026-07-28)

- `ListToolsResult extends PaginatedResult, CacheableResult { tools: Tool[] }`
- `CallToolRequest.params`: `{name, arguments?, _meta}`; result
  `{resultType:"complete", content:[...], isError?, structuredContent?}`.
- `ToolAnnotations` still present: `title`, `readOnlyHint` (default false),
  `destructiveHint` (default true), `idempotentHint` (default false),
  `openWorldHint` (default true).
- `server/discover` → `{resultType:"complete", supportedVersions: string[],
  capabilities, instructions?, ttlMs, cacheScope}`.
- `RequestParams._meta` requires `io.modelcontextprotocol/protocolVersion`
  and `io.modelcontextprotocol/clientCapabilities`; SHOULD have
  `io.modelcontextprotocol/clientInfo`. Results SHOULD carry
  `_meta.io.modelcontextprotocol/serverInfo`.
- Content types: text/image/audio/resource_link/resource; text:
  `{type:"text", text}`.
- `x-mcp-header` schema annotation → `Mcp-Param-{name}` request headers.
