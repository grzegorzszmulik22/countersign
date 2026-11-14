# M0.4 plan — scripted agent

Chunk: `scriptagent` — minimal agent loop in a non-root sandbox image
(git, curl, Python, pip, Node, npm). Anthropic Messages + OpenAI
Responses + Chat Completions shapes; tools Bash, WebFetch, Read, Write
and MCP tools through a real MCP client (Streamable HTTP, revision
2026-07-28: server/discover, tools/list, tools/call with
`_meta.io.modelcontextprotocol/protocolVersion` and Mcp-Method/Mcp-Name
headers). Rogue switches `--rogue=extra-effect` (one extra credentialed
request) and `--rogue=undeclared-mcp` (one extra tools/call). Flags
`--subagent`, `--wrap-commands`, `--stream`, bounded 5xx retry (E18).

## Files to touch

- `test/fixtures/scriptagent/{agent,model,tools,mcp}.go`, `stub.go`,
  `Dockerfile`
- `test/fixtures/cmd/scriptagent/{main,stub}.go`
- `test/checks/check-M0.4.sh`
- `test/vectors/transcripts/m04-*.scenario.json` (new vectors; adding is
  allowed by 06 §7)
- `test/sabotage/M0.4/agent-ignores-tool-result.patch`
- `docs/scriptagent.md`, `spec/progress/agent.md`

## Check strategy (this host has Docker, no cluster)

- Fixtures run as containers on a dedicated docker network with
  `--network-alias` matching the realistic host names
  (api.anthropic.com → mockllm, github.com/api.github.com → fakehub,
  echo.example.com → echo, mcp.example.com → mcpdemo). Fixture binaries
  run inside the sandbox image userland (git is present there).
- Shared test CA is generated once on the host via the fixture binary
  (EnsureCA semantics) and mounted into every container; the agent
  container trusts it through the standard CA env vars (SSL_CERT_FILE,
  GIT_SSL_CAINFO, NODE_EXTRA_CA_CERTS, ...).
- `scriptagent` runs inside the sandbox image as the non-root `agent`
  user; one container per check, `docker exec`ed per replay so request
  bodies stay byte-identical across replays (hostname constant).
- C0.4.1: three replays of `reference.scenario.json`; ordered
  (fixture,method,host,path,body_sha256) lists must be identical.
- C0.4.2: turn with two WebFetch calls to `echo /sse` (timed); overlap
  proven by agent-reported tool-call intervals + both requests observed
  at echo.
- C0.4.3: one mockllm, alternating-expectation transcript (main/sub);
  __observed turn order and bodies prove M,S,M,S interleave.
- C0.4.4: baseline vs `--rogue` runs; exactly one extra credentialed
  request / one extra tools/call.
- C0.4.5: `go list -deps` has no `internal/` (and no `test/fixtures/fx*`)
  packages; source grep has no `COUNTERSIGN_`.
- Sabotage `agent-ignores-tool-result`: agent sends no tool_result →
  mockllm 400s → C0.4.1 red.

## First test

check-M0.4.sh failing on "no scriptagent binary" before implementation.
