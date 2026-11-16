<!-- Copyright 2026 The Countersign Authors
     SPDX-License-Identifier: Apache-2.0 -->

# Reference reconciler and abstract trace corpus (M9.1)

`ref/python/refreconcile` is the executable specification of spec/04 §5–§7
(intents, reconciliation levels, expectation rules, MCP server contracts)
plus the class and condition rules of spec/05 §1–§2 and §12, written ahead of
the Go engine so the semantics are pinned by two independent
implementations. It uses the Python standard library only and reads nothing
under `internal/` or `cmd/`; `match.py` (M3.1) is untouched.

## Abstract trace format

The corpus does not depend on the M1 bundle format. A trace file is JSONL:
the first line is a `trace.meta` object and every later line is one record
body (spec/03 type strings: `session.open`, `intent.declared`,
`intent.result`, `mcp.call.begin`, `mcp.call.end`, `mcp.tools`,
`effect.http`, `effect.tunnel`, `effect.denied`, `session.seal`, ...).

`trace.meta` carries the scenario inputs and the hand-derived expectations:

- `policy` — a SessionPolicy-like object (`mode`, `autonomy`, `grants`,
  `toolClasses`, `commandField`, `mcpNaming`).
- `contract` (or `contracts`) — an `McpContract` for `kind: mcp-server`
  sessions.
- `expect` — `{effects: {id: {level, intents, action, reason, class,
  condition, grant, would_deny?}}, findings: [{code, effect}], verdict}`,
  derived by reasoning from the spec, never by running either
  implementation (the derivation note is in the file's `derivation` field).

Requests are abstract objects `{method, scheme, authority, path, query,
sni?, connect?, websocket?, mcp?}` where `authority` is `host[:port]` and an
MCP `tools/call` rides as `request.mcp = {method, server, tool, arguments}`.

## Semantics encoded

- **Log order only** (04 §5.3). An intent is open from its `intent.declared`
  record to its `intent.result` record or the session seal; provider-
  executed intents never open; only `exec`, `http`, `mcp` and `other`
  classes authorize network effects — `local` cannot. Timestamps are used
  for exactly one thing: the §7.1 startup-grace duration.
- **Levels** (04 §6.1/§6.3): `CONTROL` (inference traffic and MCP protocol
  messages), `EXACT` (a §6.2 expectation matches, or a §6.3 tools/call
  matches an unconsumed intent's server/tool/canonical-argument digest),
  `WINDOW` (an open intent remains but nothing exact-matched), `STANDING`
  (`requires: none`), `NONE`. `intentMatch: window` accepts
  `EXACT`/`WINDOW`/`CONTROL`; `exact` accepts `EXACT`/`CONTROL`.
- **Expectation packs** (04 §6.2): `internal/reconcile/packs/*.json` are
  data — `when` clauses (`argv0`, `argv_prefix`, `argv0_prefix`, `argv_eq`,
  `url_arg_count`, `input_has`, `forbid` tokens/prefixes, `tool`,
  `tool_class`) and `bind`/`expect` forms (`http`, `git` shapes; binds
  `first-arg-url`, `single-url-arg`, `curl-method`, `input-field`,
  `literal`). Commands containing shell operators the grammar does not
  cover produce no expectation (never a wrong one).
- **Class and condition** (05 §1–§2): control / safe / staged /
  compensable / irreversible, then the strictest of `autonomy[class]` and
  the grant's `requires`.
- **Modes** (04 §6.4): `enforce` decides; `audit` allows and records
  `would_deny`; `learn` allows everything not denied by a grant.
- **MCP server sessions** (04 §7): contract checks in §7.3 order — startup
  grace (`F_CONTRACT_STARTUP`), idle outside a call
  (`EFFECT_OUTSIDE_CALL`/`F_CONTRACT_IDLE`), in-flight pattern and
  `maxEffects` (`CONTRACT_VIOLATION`/`F_CONTRACT_PATTERN`/
  `F_CONTRACT_MAX_EFFECTS`), then the independent read-only-annotation
  check (`ANNOTATION_VIOLATION`/`F_CONTRACT_ANNOTATION`). Path templates
  interpolate `{arguments.x}` per segment and cannot be steered by `/`,
  `..`, `%2f` or unicode (percent-encoded comparison; §2 smuggling rules
  apply to the wire path first). Without a contract the 05 §12 default
  denies everything but safe/control outside a call.
- **Offline comparison** (04 §6.5): the recorded broker `class`,
  `requires`, `attribution` and `decision` are recomputed and any
  disagreement is a finding (`F_CLASS_MISMATCH`, `F_ATTRIBUTION_MISMATCH`,
  `F_DECISION_MISMATCH`, `F_CREDENTIAL_SCOPE`); an allowed level-`NONE`
  effect under an intent condition is `F_UNATTRIBUTED`. An effect record
  with no broker claim is evaluated but compared against nothing.
- **Verdict** (03 §10): `UNSEALED` > `VIOLATIONS` > `LEARN` >
  `CLEAN_WITH_DENIALS` > `CLEAN`.

## Layout

| module | role |
|---|---|
| `canon.py` | RFC 8785 canonical JSON + SHA-256 argument digests (§6.3) |
| `grants.py` | grant selection incl. smuggling pre-checks (§2), class (05 §1), condition (05 §2) |
| `expect.py` | §6.2 command splitting, rule matching, expectation instantiation and matching |
| `packs.py` | expectation-pack document validation |
| `reconcile.py` | the engine: agent sessions (§5–§6) and mcp-server sessions (§7) |
| `trace.py` | JSONL trace loader |
| `corpus.py` | corpus runner, coverage measurement (child-interpreter `sys.settrace`), random-run CLI |
| `randgen.py` | seeded random trace generator (no expectations written — C9.1.3 only) |

CLI: `python -m refreconcile.corpus {trace,corpus,coverage,randgen,packcheck}`.

## Corpus

`test/vectors/reconcile/` holds 198 hand-written traces (spec floor: 80)
covering every required row of the M9.1 matrix — each level under each
`requires`/`intentMatch` combination, all four window edges plus closure by
seal and timeout and timestamp/log-order inversions, `local` intents alone
and mixed with `exec`, provider-executed intents, parallel intents and two
conversations, every §6.2 pack row positive and negative (compound `git add
-A && git commit -m x && git push`, pipes, explicit URLs outside the
grant), the §6.3 exact/mismatch/repeat/name cases, every §7.3 check
including grace, idle, in-flight pattern and `maxEffects`, two calls in
flight and annotation violations, and `enforce`/`audit`/`learn` on the same
records.

Checks: `test/checks/check-M9.1.sh` (C9.1.1 corpus, C9.1.2 coverage ≥ 95%
with uncovered lines listed, C9.1.3 10,000 random traces). Sabotages under
`test/sabotage/M9.1/`: `window-uses-timestamps` (intent windows computed
from `ts` instead of log order) and `local-class-authorizes-network`; each
fails C9.1.1.
