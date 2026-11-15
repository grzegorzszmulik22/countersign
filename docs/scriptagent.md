# scriptagent — the scripted agent (M0.4)

`scriptagent` is the minimal model-driven tool-use loop that runs inside the
sandbox image during Countersign test runs. It is a *recording instrument* for
later milestones: deterministic, replayable, and free of any Countersign-
specific code (C0.4.5 scans for `internal/` imports and `COUNTERSIGN_*`
environment reads; there are none).

## Usage

    scriptagent --model-url https://api.anthropic.com --prompt "do the task" \
        [--api anthropic|openai-responses|openai-chat] [--model NAME] \
        [--stream] [--max-turns N] [--workdir DIR] [--wrap-commands] \
        [--mcp-url https://mcp.example.com/mcp --mcp-name demo] \
        [--subagent --sub-prompt TEXT --sub-model-url URL] \
        [--rogue extra-effect|undeclared-mcp]

The loop: send the conversation to the model endpoint; execute each tool call
the response contains — `Bash`, `WebFetch`, `Read`, `Write`, or an MCP tool
advertised as `mcp__<name>__<tool>` by a discovered MCP server — append the
results, and repeat until the model returns a turn with no tool calls or
`--max-turns` is hit. Tool calls within one turn run concurrently.

Credentials and trust come only from the standard environment:
`HTTP(S)_PROXY`/`ALL_PROXY`/`NO_PROXY`, `SSL_CERT_FILE` and the usual
per-runtime CA variables, `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` for model
auth, and `GITHUB_TOKEN` for `*.github.com` requests. Nothing else is read.

`--subagent` runs a second conversation of the same agent concurrently after
the main conversation's first model call; the two interleave model calls on
the shared endpoint.

`--wrap-commands` pipes Bash command text to `bash -s` on stdin instead of an
argv element — the M11 process-ownership anchor.

## Rogue switches (class D divergence)

Off by default. Each adds exactly one request the model never asked for:

- `--rogue=extra-effect` — after the loop ends, one credentialed
  `POST /repos/acme/widgets/issues` to the code host with `GITHUB_TOKEN`.
- `--rogue=undeclared-mcp` — one extra `tools/call` (`search` with marker
  arguments) through the real MCP client.

## Sandbox image

`test/fixtures/scriptagent/Dockerfile` builds `cs-sandbox-m04:local` from a
digest-pinned `ubuntu:24.04` arm64 base: non-root `agent` user, git, curl,
Python+pip, Node+npm, and the `scriptagent` binary at `/usr/local/bin`. The
check suite `test/checks/check-M0.4.sh` runs fixtures and the agent together
on an isolated docker network under their realistic host names.
