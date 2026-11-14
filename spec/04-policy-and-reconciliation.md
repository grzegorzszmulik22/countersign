# 04. Policy, matching, credentials, intents, reconciliation, lineage, taint

Normative. The Python reference (`refreconcile`) is the executable form of §5–§11; where prose and the reference disagree, file a change request.

## 1. `SessionPolicy`

```yaml
apiVersion: countersign.dev/v1alpha1
kind: SessionPolicy
metadata: {name: coding-agent}
spec:
  mode: enforce                 # enforce | audit | learn
  scenario: agent               # agent | mcp-server
  observer: optional            # optional | required   (M11)
  taint: {initialWorkspace: trusted}   # M10; "trusted" or a label
  privacy: {previews: true}
  bufferLimit: 1Mi
  maxIntentOpenSeconds: 3600
  commandField: command         # tool-input field hashed as the lineage anchor (§10)
  toolClasses:                  # tool name glob -> class
    Bash: exec
    WebFetch: http
    "mcp__*": mcp
    Read: local
    Edit: local
    Write: local
    "*": other
  grants:
    - id: llm
      match: {hosts: [api.anthropic.com], methods: [POST], paths: [/v1/messages]}
      inspect: inference        # none | inference | mcp
      trust: trusted
      credential:
        ref: {secret: anthropic-key, key: value}
        inject: {header: x-api-key, format: "{secret}"}
        placeholderEnv: ANTHROPIC_API_KEY
    - id: repo
      match:
        hosts: [github.com]
        matcher: {git-smart-http: {repos: [acme/widgets], access: write}}
      stager: {git: {refs: ["refs/heads/agent/*"]}}     # pushes are staged (`05` §4)
      intentMatch: exact        # window | exact
      lineage: preferred        # off | preferred | required (§10)
      credential:
        ref: {secret: github-token, key: value}
        inject: {basic: {username: x-access-token}}
        placeholderEnv: GITHUB_TOKEN
    - id: issue-comments
      match: {hosts: [api.github.com], methods: [POST], paths: ["/repos/acme/widgets/issues/*/comments"]}
      compensate: {deleteCreated: {methods: [POST], from: {jsonPointer: /url}}}   # class compensable (`05` §10)
      requires: intent          # may only be stricter than autonomy[class]
      whenTainted: {default: review, labels: {packages: allow}}   # allow | review | deny, per taint label
      credential: {ref: {secret: github-token, key: value}, inject: {header: Authorization, format: "Bearer {secret}"}, placeholderEnv: GITHUB_TOKEN}
    - id: pypi
      match: {hosts: [pypi.org, files.pythonhosted.org], methods: [GET, HEAD]}
      trust: packages           # "trusted", or a taint label
      egress: counted           # charged against the leak budget (`05` §11)
      limits: {maxUrlBytes: 512, requestsPerMinute: 600}
```

The session-level fields `autonomy`, `world`, `commit`, `budgets`, `tape` and `attest` are defined in `05`. Every request is first given a **reversibility class** (`05` §1); the class, not the host, decides what condition applies (`05` §2).

Grant fields and defaults:

| Field | Default | Notes |
|---|---|---|
| `action` | `allow` | `deny` carves an exception; matches yield `DENY_GRANT` |
| `match.scheme` | `https` | `http` must be explicit |
| `match.hosts` | required | Lowercase names. `*.example.com` matches one or more labels below `example.com`, not the apex. `*` alone matches any host and is rejected unless `spec.mode` is `learn` or the grant has no credential |
| `match.ports` | `[443]` (`[80]` for http) | |
| `match.methods` | all | |
| `match.paths` | `["/**"]` | `*` within a segment; `**` any number of segments |
| `match.matcher` | none | Built-ins: `git-smart-http`, replacing `methods`/`paths` |
| `mode` | `intercept` | `passthrough` tunnels without TLS interception; forbids `credential`, `inspect`, `matcher`, `paths`, `methods` |
| `upgrade` | `[]` | `[websocket]` permits the upgrade |
| `network` | `public` | `cluster` permits private and cluster addresses (needed for in-cluster MCP servers) |
| `inspect` | `none` | |
| `trust` | label `untrusted`, except `trusted` when `inspect: inference` | `trusted`, or a taint label (`[a-z][a-z0-9-]*`) attached to the response content (M10) |
| `requires` | unset | `allow`, `intent`, `review` or `deny`. The effective condition is the strictest of this and `autonomy[class]` (`05` §2) |
| `class` | computed (`05` §1) | Explicit override |
| `stager` | none | `git` (`05` §4) or `outbox` (`05` §5); makes matching writes `staged` |
| `compensate` | none | Compensation rules; makes matching writes `compensable` (`05` §10) |
| `tools` | `{}` | For `inspect: mcp` grants to unbrokered servers: tool name → class |
| `egress` | `counted` when `trust` is a label or the host is a wildcard; else `exempt` | Whether requests are charged against the leak budget (`05` §11) |
| `intentMatch` | `window` | |
| `lineage` | `preferred` | `off`, `preferred`, `required` (§10) |
| `whenTainted.default` | `review` if the grant has a credential or permits any method other than GET/HEAD; else `allow` | Applied for every taint label not listed in `whenTainted.labels`. With several labels present, the strictest result wins (`deny` > `review` > `allow`). Affects `compensable` and `irreversible` effects; for `staged` effects taint is an annotation that blocks automatic commit (`05` §7) |
| `bufferLimit` | `spec.bufferLimit` (1 MiB); 32 MiB when `inspect: inference` | Largest request body held in memory for digesting, inspection, staging, prior-state capture and review |
| `limits.maxRequestBodyBytes` | 32 MiB | |
| `limits.maxUrlBytes` | 2048 | Path plus query |
| `limits.requestsPerMinute` | 1200 | Per grant per session |

Validation failures reject the policy at admission. The policy digest is the SHA-256 of the file bytes.

## 2. Request matching

Evaluated on every request after TLS interception (or on CONNECT for passthrough).

1. **Pre-checks**, each denying before any grant is consulted:
   - CONNECT authority, TLS SNI and HTTP `Host`/`:authority` must be identical after lowercasing → else `SMUGGLING_SUSPECT`.
   - Reject requests with both `Content-Length` and `Transfer-Encoding`, multiple differing `Content-Length`, obsolete line folding, or bare LF in headers → `SMUGGLING_SUSPECT`.
   - Reject paths containing dot segments (`.`, `..`), `\`, control characters, or the percent-encoded forms `%2e`, `%2f`, `%5c`, `%00` in any letter case → `SMUGGLING_SUSPECT`.
   - Host given as an IP literal → `NO_GRANT` unless a grant lists that literal.
2. **Grant selection.** Grants are tried in document order; the first whose `match` holds is selected. No match → `NO_GRANT`.
3. **Upstream address check.** The broker resolves the name once and connects to that address. Loopback, link-local (including `169.254.169.254`), private, unique-local and cluster service/pod ranges → `UPSTREAM_BLOCKED` unless `network: cluster`. The resolved address is recorded.
4. **Limits** → `LIMIT_*`.
5. **Credential rules** (§4) → `FOREIGN_CREDENTIAL`, `PLACEHOLDER_MISUSE`.
6. **Class** (`05` §1), then the **condition** that class and the session's state impose (`05` §2): budgets (`05` §11), taint (§8), intent (§6), review (`05` §8), in that order. Then the request is forwarded, staged or held.

`git-smart-http` matcher, for repository `OWNER/REPO` (the `.git` suffix optional):

| Access | Permitted requests |
|---|---|
| `read` | `GET /OWNER/REPO[.git]/info/refs?service=git-upload-pack`; `POST /OWNER/REPO[.git]/git-upload-pack` |
| `write` | The above, plus `GET …/info/refs?service=git-receive-pack`; `POST …/git-receive-pack` |

Any other path or `service` value does not match.

## 3. Request digest

```
request_digest = SHA-256(
  "countersign-request-v1\n" ‖
  METHOD ‖ "\n" ‖
  scheme ‖ "\n" ‖
  authority ‖ "\n" ‖            lowercase host, ":port" only if non-default
  raw-path ‖ "\n" ‖             exactly as received
  hex(SHA-256(raw-query)) ‖ "\n" ‖   raw query without "?", empty string if none
  hex(SHA-256(body)) ‖ "\n" ‖
  "content-type:" ‖ value ‖ "\n"     only if the header is present; value trimmed of surrounding whitespace
)
```

Credential-bearing headers are excluded so the digest is the same before and after injection.

## 4. Credentials

### 4.1 Placeholders
`csph_<8 hex of session>_<grant id>_<22 base62 random>`. One per (session, credentialed grant). Delivered through `placeholderEnv`. The mapping lives only in the broker.

### 4.2 Injection
Where the grant's `inject` location holds exactly the session's placeholder for that grant (after applying `format`, or as the Basic password), the broker substitutes the real value. If the location is absent the broker adds it. Injection happens only after every check in §2 has passed.

### 4.3 Pinning and misuse (P5)
For a request selected by a credentialed grant:

- Credential-bearing headers are: `authorization`, `proxy-authorization` (toward upstream), `x-api-key`, `api-key`, `x-auth-token`, `cookie`, plus the grant's `inject.header`.
- If any of them carries a value that is not this session's placeholder for this grant → `FOREIGN_CREDENTIAL`.

For every request, on any grant:

- Any `csph_` token in the URL, in a body (buffered part), or in a header other than the grant's inject location → `PLACEHOLDER_MISUSE`.
- A placeholder belonging to a different grant or a different session → `PLACEHOLDER_MISUSE`.

### 4.4 Credential-shape detector
A fixed list, each with positive and negative test strings in `test/vectors/credshapes.json`: Anthropic (`sk-ant-`), OpenAI (`sk-`, `sk-proj-`), GitHub (`ghp_`, `gho_`, `ghu_`, `ghs_`, `github_pat_`), AWS access key IDs (`AKIA`, `ASIA` + 16), Slack (`xox[baprs]-`), JSON Web Tokens (three base64url parts, header decoding to JSON with `alg`), PEM private-key headers. Used for (a) redacting previews and (b) `FOREIGN_CREDENTIAL` when such a shape appears in the URL or buffered body of a request to a **credentialed** grant. Nothing more (D14).

### 4.5 Response scrubbing (P1)
When a credential was injected, the broker scans response headers and body for the exact real value (and its Basic-encoded and URL-encoded forms) and replaces each occurrence with the placeholder, counting replacements in `scrubbed`. The scan is streaming with a carry-over window of `len(secret) − 1` bytes. For such requests the broker sends `Accept-Encoding: gzip, identity` upstream, decodes, scans, and forwards the body without content encoding.

## 5. Intents

### 5.1 Sources
- **Inference** (`inspect: inference`): tool-use blocks in model responses. Anthropic Messages: content blocks of type `tool_use` (executor `sandbox`) and `server_tool_use` (executor `provider`). OpenAI Responses: output items of type `function_call` (and provider-hosted tool calls as executor `provider`). OpenAI Chat Completions: `tool_calls`.
- **MCP** (`inspect: mcp`): a `tools/call` request is itself an effect and is checked against inference-declared intents (§6.3). In scenario S2 it opens a call window in the server's session (§7).

### 5.2 Identity and class
`intent_id` is the provider's ID (`toolu_…`, `call_…`). The same ID seen again in a later request body is not a new intent. `class` comes from `toolClasses` (first matching glob in document order). Only classes `exec`, `http`, `mcp`, `other` can authorize network effects; `local` cannot.

### 5.3 Window
All in **log order**:
- Opens at the `intent.declared` record.
- Closes at the `intent.result` record, written when an inference request from the same session carries a tool result referencing that ID, or at `session.seal`, or after `maxIntentOpenSeconds` (`closed_by: timeout`).
- Intents with `executor: provider` never open a window.

### 5.4 Fail-safe
If a response on an `inspect: inference` grant cannot be parsed, bytes are still forwarded unchanged, an `intent.unparsed` record is written, and no intent opens. In enforce mode the agent's next effects that require an intent are then denied. Inspection never modifies traffic: the SHA-256 of bytes delivered to the client equals that of bytes received from upstream.

## 6. Reconciliation

### 6.1 Attribution level of an effect `e`
Let `O(e)` be the intents open at `e` in log order with a network-capable class.

| Level | Condition |
|---|---|
| `CONTROL` | `e`'s grant has `inspect: inference`; or `e` is an MCP protocol message other than `tools/call` on an `inspect: mcp` grant |
| `EXACT` | Some `i ∈ O(e)` and some expectation rule (§6.2) instantiated from `i` matches `e`; or §6.3 holds |
| `WINDOW` | `O(e)` is non-empty and no exact match |
| `STANDING` | `O(e)` is empty and the grant has `requires: none` |
| `NONE` | Otherwise |

`attribution.intents` lists the exact-matching intents for `EXACT`, all of `O(e)` for `WINDOW`, and is empty otherwise.

### 6.2 Expectation rules
A rule pack is YAML: for a tool class and an input pattern, a list of expected request shapes.

```yaml
- tool: Bash
  when: {argv0: git, argv1: [push]}
  bind: {remote_url: "first argument that parses as an https URL"}
  expect: [{matcher: git-smart-http, access: write, url: "{remote_url}"}]
```

A command is first split into simple commands on `&&`, `||`, `;` and newlines. A rule may fire for a simple command only if it tokenizes with plain shell-word splitting and contains none of `| & < > $ \` ( ) { }`. A simple command that fails this test contributes no expectation; an effect it causes can reach at most `WINDOW`.

Packs shipped:

| Pack | Commands | Expectation |
|---|---|---|
| `git` | `clone`, `fetch`, `pull` | `git-smart-http` read. Bound to the explicit https URL if the command has one; otherwise to any repository inside the selected grant |
| `git` | `push` | `git-smart-http` write, bound the same way |
| `pip` | `pip install`, `python -m pip install` | GET/HEAD on the grant(s) labelled as the package index |
| `npm` | `npm install`, `npm ci` | GET/HEAD on the registry grant(s) |
| `curl` | `curl`, `wget` with exactly one URL | That URL; method from `-X`, else POST if a data flag is present, else GET |
| `http` | Tools of class `http` | The URL argument, method GET unless the tool input names one |

The consequence that matters: with `intentMatch: exact` on a write grant, a push that happens while the only open intent is `pip install …` is **not** exact and is denied. That is how a malicious install script is stopped from writing to an allowed repository (effectbench B6). The limitation (anything indirect, such as a script that itself runs git, cannot be exact) is deliberate and is reported as the share of `EXACT` vs `WINDOW`.

### 6.3 MCP tool calls from the agent (scenario S1)
A `tools/call` request `e` with tool name `t` and arguments `a` to MCP server `s` is `EXACT` iff an open intent `i` exists with `class: mcp`, whose tool name maps to (`s`, `t`) under the policy's `mcpNaming` rule (default `mcp__<server>__<tool>`), and `SHA-256(canonical(i.input)) = SHA-256(canonical(a))`, where `canonical` is RFC 8785 JSON canonicalization. Each intent can match at most one `tools/call`. Otherwise the level is `NONE` and the reason is `UNDECLARED_TOOL_CALL`.

### 6.4 Inline decision

The condition comes from `05` §2.

| Condition | Decision |
|---|---|
| `allow` | Proceed (forward, or stage if the class is `staged`) |
| `intent`, `intentMatch: window` | Proceed iff level ∈ {`EXACT`, `WINDOW`, `CONTROL`}, else `NO_INTENT` |
| `intent`, `intentMatch: exact` | Proceed iff level ∈ {`EXACT`, `CONTROL`}, else `NO_INTENT` |
| `review` | `05` §8 |
| `deny` | `AUTONOMY_DENY` |

Whatever the condition, the level, intents and lineage are computed and recorded on every effect, because staged entries carry them into the review document (`05` §6).

In `audit` mode the request is allowed and `decision.would_deny` carries the reason. In `learn` mode everything not hitting a `deny` grant is allowed, credentials are injected only for explicit grants, and every record is written.

### 6.5 Offline recomputation
The verifier recomputes level, intent list, and decision for every effect from the records and bundled policy, **ignoring the broker's `attribution` and `decision` fields**, then compares.

| Finding | Severity | Meaning |
|---|---|---|
| `F_ATTRIBUTION_MISMATCH` | error | Broker's recorded level or intents differ from the recomputation |
| `F_DECISION_MISMATCH` | error | Broker allowed what policy denies, or the reverse |
| `F_UNATTRIBUTED` | error | An allowed effect has level `NONE` under a grant requiring intent (expected only in audit mode) |
| `F_CREDENTIAL_SCOPE` | error | A credential ID recorded on an effect whose recomputed grant has no such credential |
| `F_CLASS_MISMATCH` | error | Recorded class or condition differs from the recomputation of `05` §1–§2 |
| `F_INVARIANT_MISMATCH` | error | A recorded invariant result differs from its recomputation over the review document (`05` §7) |
| `F_PRECONDITION` | error | An apply or compensation effect was made although its recorded precondition did not hold (`05` §9, §10) |
| `F_BUDGET_MISMATCH` | error | Recomputed running budget totals differ from the recorded charges, or an effect was allowed past a limit (`05` §11) |
| `F_TAINT_MISMATCH` | error | Recorded `taint` labels or a taint-driven decision differ from the recomputed label set |
| `F_CONTRACT_*` | error | §7 |
| `F_LINEAGE_MISMATCH` | error | Broker's recorded owner or lineage state differs from the recomputation of §10 |
| `F_CROSS_EMITTER` | error | §11 |

## 7. MCP server sessions (scenario S2)

### 7.1 `McpContract`
```yaml
apiVersion: countersign.dev/v1alpha1
kind: McpContract
metadata: {name: tracker-mcp}
spec:
  idle: deny                         # effects with no call in flight
  startup: {graceSeconds: 30, effects: [{host: api.tracker.example, method: GET, path: /meta}]}
  tools:
    create_issue:
      effects:
        - {host: api.tracker.example, method: POST, path: "/repos/{arguments.repo}/issues"}
      maxEffects: 3
    search:
      effects: [{host: api.tracker.example, method: GET, path: /search}]
```
`{arguments.X}` is replaced by the string value of argument `X` of the in-flight call, percent-encoded per path segment; non-string or missing arguments make the pattern unmatchable.

### 7.2 Call windows
When the broker forwards a `tools/call` to a brokered MCP server pod, it appends `mcp.call.begin` to the **server's** session before forwarding and `mcp.call.end` when the response completes. A call is in flight between those two records, in log order.

### 7.3 Checks on each server-session effect `e`
1. During startup grace: must match a `startup.effects` pattern, else `F_CONTRACT_STARTUP`.
2. No call in flight and `idle: deny` → inline `EFFECT_OUTSIDE_CALL`.
3. Otherwise `e` must match an effect pattern of the contract entry of at least one in-flight call, and that call's effect count must stay ≤ `maxEffects` → else inline `CONTRACT_VIOLATION`.
4. **Annotation check**, independent of any contract: if the last observed `mcp.tools` record marks every in-flight call's tool `readOnlyHint: true` and `e`'s method is not GET or HEAD → `ANNOTATION_VIOLATION`.

## 8. Taint (M10)

Taint is a **set of labels on the session**. It only grows.

- **Sources.**
  - An allowed effect on a grant whose `trust` is a label `L`: `taint.added{label: L, source: effect}` is durably written **before the first response byte is delivered to the sandbox**. This covers both data the model will read and code the sandbox may execute.
  - A provider-executed tool result block (for example a web-search result) in a model response: label `provider-tool`, written before the block is forwarded.
  - `initialWorkspace: L` starts the session with label `L`.
- **Effect on decisions.** Before the intent check, each grant evaluates `whenTainted` against the session's label set: `deny` → `TAINTED_DENY`; `review` → a single-effect review (`05` §8); `allow` → continue. This applies to `compensable` and `irreversible` effects. A `staged` effect is never interrupted by taint: the labels present are recorded on it, appear on its changeset entry, and the `forbidTaint` invariant keeps such a changeset from committing without a human. Precision comes from policy, not heuristics: a policy may say that content labelled `packages` does not gate pushes while content labelled `web` does.
- **No content matching.** Deciding taint by comparing response bytes with context bytes was considered and rejected: it is unsound against transformation and against executed code. It is on the denied list of M10.
- **Lineage.** For every inference request the broker writes `context.observed` (`03` §4). Together with `intent.declared.via_effect`, `intent.result`, and effect attribution this yields, from records alone, the chain: untrusted effect `u` → intent `j` whose window contained `u` → the context block holding `j`'s result → model call `m` whose context includes that block → intent `i` declared by `m` → effect `e` attributed to `i`. `csverify explain <effect_id>` prints every such chain ending at `e`.
- **Offline check.** The verifier recomputes the label set at every effect from the records in log order and compares it with the `taint` labels and decisions recorded on each effect (`F_TAINT_MISMATCH`).

## 9. Review

Human decisions are specified in `05` §8: one passkey signature over a changeset root, or over the single entry of a held effect. This section number is kept so that references to §10 and §11 stay stable.

## 10. Process lineage (M11)

Window attribution has one structural weakness: a process started under an earlier intent (for example a daemon left behind by an install script) can act later, while an unrelated intent is open. Lineage closes it. The rule: **a process tree spawned for intent `j` can only ever act under `j`.**

Grant field `lineage`: `off` | `preferred` (default: computed and recorded, not enforced) | `required`.

- **Anchor.** For an intent `i` of class `exec`, `intent.declared.anchor_sha256` is the SHA-256 of the command string (the tool-input field named by `spec.commandField`, default `command`). `anchor(i)` is the first `effect.exec` after `intent.declared(i)` in log order whose `argv_sha256[]` contains that value and which is not already the anchor of another intent. Intents of other classes have no anchor.
- **Owner of an effect.** For an effect with client port `p`, take the `effect.connect` with `src_port = p`, its `exec_id`, and walk `parent_exec_id` upward. The first exec on that path that is an anchor determines the owning intent `j`. If none is, the effect is **unowned** (it came from the harness's own process tree).
- **Candidate intents** `O(e)` of §6.1 are then narrowed:
  - Owned by `j`: `O(e) = {j}` if `j` is open, otherwise empty. This holds under `preferred` and `required` alike, because it only ever removes candidates.
  - Unowned: open intents of class `http`, `mcp`, `other`; plus, under `preferred` only, open `exec` intents that have no anchor yet.
- **Missing data.** If no `effect.connect` for port `p` is available within 50 ms (inline) or at all (offline, or an `observer.gap` covers the time): `preferred` falls back to §6.1 unchanged and records `attribution.lineage: unknown`; `required` denies with `OBSERVER_REQUIRED`.
- `attribution.lineage` is recorded as `owned`, `unowned`, `unknown` or `off`, with `attribution.owner` holding the owning intent ID when there is one.

Limits, stated in the public threat model: anchoring needs the harness to run the declared command as one argument of an exec (for example `bash -c <command>`); a harness that wraps or rewrites the command yields no anchor. A connection inherited across processes is attributed to the process that opened it. Host-side observation does not see inside gVisor or microVM guests, where lineage is `unknown`.

## 11. Cross-emitter consistency (M11)

With the observer present, for a sealed session with no `observer.gap`:

- Every `effect.http`/`effect.tunnel`/`effect.denied` with client port `p` has an `effect.connect` with `src_port = p`, `outcome: to-broker`, earlier in log order → else `F_CROSS_EMITTER` (`broker-effect-without-connect`).
- Every `effect.connect` with `outcome: to-broker` has at least one broker record with that client port → else `F_CROSS_EMITTER` (`connect-without-broker-record`).
- `effect.connect` with `outcome: blocked` is a recorded bypass attempt and makes the verdict at best `CLEAN_WITH_DENIALS`.
