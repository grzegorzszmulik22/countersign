<!-- Copyright 2026 The Countersign Authors
     SPDX-License-Identifier: Apache-2.0 -->

# Intent capture (M8)

`internal/inspect` reads model-declared intent from the unmodified
agent/provider traffic flowing through the broker. It never rewrites,
filters, or buffers whole responses; the only observable effect is the
bounded hold at tool-use completion (03 §4.5 write-ahead).

## Shape

```
client ── request ──► broker ──► provider
           │(buffered ≤ bufferLimit)
           ▼
      inspect.ParseRequest ─► intent.result / context.observed records

provider ── response ──► inspectPipe ──► client
           │tee            ▲
           ▼               │ hold point: bytes completing a tool-use
      ResponseParser        │ block wait for the intent.declared append
```

- `EndpointForPath` maps `/v1/messages`, `/v1/responses`,
  `/v1/chat/completions` to the three parsers; no other path is
  inspected (D19).
- SSE bodies stream through `sseSplitter`; JSON bodies through the
  element scanner (`jsonscan`). Both are incremental — parsing is
  independent of upstream read chunking (MM8.1 holds over 1,000 random
  chunkings per vector).
- A `Completion` reports `HoldAt`, the absolute stream offset of the
  byte completing the tool-use block. `inspectPipe` releases everything
  before it, runs the `intent.declared` append, then releases the rest
  (MM8.3: p99 added delay ≤ 2 ms, ≤ 6 ms at the hold point).
- A parse fault stops inspection for that stream: bytes pass through
  untouched, one `intent.unparsed` is written, no intent is fabricated
  (spec/02 §6, MM8.4).

## Request side (M8.3)

On `inspect: inference` grants the already-buffered request body is
parsed before forwarding (the write-ahead ordering of `effect.http`
still applies):

- `intent.result` — a tool result naming a declared, still-open
  sandbox intent closes its window (`closed_by: tool_result`).
  Unknown IDs are logged and ignored; a resent result does not close
  twice. Timeouts sweep on each inspected request and `seal` closes the
  remainder at broker shutdown.
- `context.observed` — one per request: `new_blocks` (each block's
  digest appears at most once per session), `block_count`, and
  `context_sha256`, the running context digest:

```
context_sha256 = SHA-256( canonical-json( [digest1, digest2, …] ) )
```

  over every unique block digest in first-observed order — the same
  value `Tracker.contextSHA` computes and the transcript generator
  recomputes independently.
- Result content is digested and measured only; the text is never
  read into any record (denied item).

`bufferLimit` for inference grants defaults to 32 MiB (spec/04 §1
defaults); over-limit requests are denied `LIMIT_BODY` unless the grant
raises `bufferLimit`.

## Privacy (M8.5)

`input_preview` = the input's raw bytes passed through
`creds.RedactNamed` (credential-shape markers `[REDACTED:<shape>]`,
spec/04 §4.4) and then truncated to ≤ 256 bytes on a UTF-8 boundary.
`input_sha256` and `input_len` always describe the original bytes.
`privacy.previews: false` omits the field entirely.

## Records

| type | fields |
|---|---|
| `intent.declared` | intent_id, source `inference`, provider, model, via_effect, tool, class, executor, input_sha256, input_len, input_preview?, anchor_sha256? (exec class) |
| `intent.result` | intent_id, via_effect, closed_by (`tool_result`/`timeout`/`seal`), content_sha256, content_len, is_error? |
| `intent.unparsed` | via_effect, provider, detail |
| `context.observed` | via_effect, provider, model, block_count, context_sha256, new_blocks[{index, role, kind, sha256, len, intent_id?}] |

Provider-executed calls (`server_tool_use`, hosted tool types, non-`function`
chat call types) declare with `executor: provider` and open no window —
a result naming them is ignored.
