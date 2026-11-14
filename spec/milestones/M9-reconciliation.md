# M9. Reconciliation

**Goal.** Join the declared side to the observed side. Offline, the verifier recomputes every attribution and decision from records alone. Inline, the broker refuses effects that have no qualifying intent. For MCP servers, declared tool behaviour is checked against observed egress.

**Properties advanced.** P7 (soundness), P4 (intent condition), and the detection results H13 and H14. From here on, every staged entry carries the reason it exists.

**Normative references.** `04` §5–§7, §6.5 findings; `03` §10 step V16; `05` §2, §6, §7, §12.

**Expected results.**
- A harness or MCP server doing something nobody declared is stopped inline and provable offline.
- Two independent reconcilers agree on every trace.
- Writing a first policy takes one command (`policy learn`).

**Measurements [T].**

| ID | Metric | Target |
|---|---|---|
| MM9.1 | Go engine vs Python reference on random traces: identical per-effect level, intent set, decision, and session verdict | 100% of ≥ 10,000 traces |
| MM9.2 | Planted unattributed effects detected (offline, audit-mode traces) | 100% of ≥ 500 (H13) |
| MM9.3 | Benign effects wrongly flagged or denied over the M9 benign flows | ≤ 1% (H13); report the list |
| MM9.4 | Inline (broker) vs offline (verifier) agreement over every session produced by the M9 end-to-end suite | 100%; zero `F_*_MISMATCH` |
| MM9.5 | Added p50 latency of inline reconciliation | ≤ 0.2 ms |
| MM9.6 | Share of effects at `EXACT` / `WINDOW` per tool class over the benign flows | reported |
| MM9.7 | `policy learn` output replayed in `enforce` mode against the flows it was learned from | 100% of those flows succeed; 0 grants broader than the observed host set |

**Milestone-wide denied.** Any statistical, learned or LLM-based matching (D1). Parsing shell beyond `04` §6.2. Timestamps in any ordering decision. Semantic judgement of whether an intent is "reasonable". Contract inference for MCP servers that claims completeness. A user interface for findings.

---

## M9.1 Reference reconciler (Python) and trace corpus

**Build.** `ref/python/refreconcile`: the executable specification of `04` §5–§7, operating on a bundle (or on an abstract trace file, one JSON object per record body, for fast tests). Written from `04`, before the Go engine.

Corpus `test/vectors/reconcile/`: at least 80 hand-written traces, each with expected per-effect level, intents, decision, findings and session verdict, **derived by reasoning from `04` and reviewed by reading**. Required coverage:

- Each level (`CONTROL`, `EXACT`, `WINDOW`, `STANDING`, `NONE`) under each `requires`/`intentMatch` combination.
- Window edges: effect at the log index immediately before `intent.declared`, immediately after, immediately before and after `intent.result`; closure by seal and by timeout.
- Classes: only a `local` intent open; a `local` and an `exec` intent open together; provider-executed intent only.
- Parallel intents; two conversations.
- Every rule pack row of `04` §6.2, positive and negative (including the compound command `git add -A && git commit -m x && git push`, a command with a pipe, an explicit URL outside the grant).
- §6.3: exact match; different arguments; same call twice against one intent; name-mapping mismatch.
- §7: effect before any call, during startup grace, in flight and matching, in flight and not matching, `maxEffects` exceeded, two calls in flight with only one matching, annotation violation with and without a contract.
- Modes: the same trace under `enforce`, `audit`, `learn`.

**Checks.**
- C9.1.1 The reference produces the expected result for every corpus trace.
- C9.1.2 Statement coverage of the reference by the corpus ≥ 95%; every branch that encodes a rule of `04` is hit (list uncovered lines in evidence).
- C9.1.3 A seeded random trace generator produces structurally valid traces accepted by the reference without exception (10,000 traces).

**Sabotage.** (on the reference) `window-uses-timestamps`; `local-class-authorizes-network`. Each must fail C9.1.1.

**Denied.** Deriving expected corpus results by running either implementation.

## M9.2 Go engine and offline verification

**Build.** `internal/reconcile` and step V16 in `csverify --reconcile`: recompute per `04` §6.5, emit findings, compute the session verdict. `csverify explain <effect_id>` prints the attribution of one effect (lineage is added in M10).

**Checks.**
- C9.2.1 Corpus: identical to expected.
- C9.2.2 MM9.1 (differential on ≥ 10,000 random traces).
- C9.2.3 MM9.2: the generator plants effects with no qualifying intent into audit-mode traces; each yields `F_UNATTRIBUTED`.
- C9.2.4 Tampering with the broker's recorded `attribution` or `decision` in a re-signed test bundle yields `F_ATTRIBUTION_MISMATCH` / `F_DECISION_MISMATCH` (the verifier does not trust the broker's own claim).
- C9.2.5 Verdict lattice of `03` §10 respected on constructed cases.

**Sabotage.** `verifier-trusts-broker-attribution`; `exact-match-ignores-access-level` (a `git fetch` intent matches a push); `mcp-intent-reusable` (one intent matches two calls).

**Denied.** Sharing code or generated tables between the Go engine and the Python reference.

## M9.3 Inline enforcement

**Build.** The broker keeps, per session, the set of open intents (from its own appended records, in append order) and applies `04` §6.4 before releasing credentials. `audit` and `learn` modes per §6.4. The `attribution` and `decision` it records are what it actually used.

End-to-end flows `test/e2e/m6/` (scripted agent on kind): ten benign flows (clone, push, install, API call, MCP call, parallel calls, subagent, compound command push, `curl` exact, no-network task) and the rogue variants.

**Checks.**
- C9.3.1 Benign flows complete in `enforce` mode; MM9.3.
- C9.3.2 `scriptagent --rogue=extra-effect` on a grant with `requires: intent`: denied `NO_INTENT`; the fixture observes nothing; in `audit` mode it is allowed and the verifier raises `F_UNATTRIBUTED`.
- C9.3.3 An install script that pushes to the granted repository during a `pip install` intent, write grant `intentMatch: exact`: denied `NO_INTENT` (scenario B6 in miniature). The same push with `intentMatch: window`: allowed, level `WINDOW`. Both recorded.
- C9.3.4 Race: an effect arriving on another connection while the intent's block-end bytes are being held is evaluated consistently with log order (the intent is open iff its record precedes the effect's record), over 10,000 trials.
- C9.3.5 MM9.4 and MM9.5.
- C9.3.6 `intent.unparsed` (forced by a malformed transcript): subsequent intent-requiring effects are denied; inference traffic itself still flows.

**Sabotage.** `inline-allows-when-no-intent-open`; `inline-uses-wall-clock-window`; `audit-mode-drops-would-deny`.

**Denied.** A grace period that allows effects shortly before or after a window. Caching decisions across requests.

## M9.4 Expectation rule packs

**Build.** The packs of `04` §6.2 as data files under `internal/reconcile/packs/`, loaded identically by Go and Python (the pack **data** is shared; the interpreters are separate). Command splitting and tokenization per §6.2.

**Checks.**
- C9.4.1 Tokenizer vectors (`test/vectors/reconcile/shellwords.json`, at least 120 commands with expected splitting or "no rule may fire"): Go and Python agree with the expected column.
- C9.4.2 Each pack row: at least 5 positive and 5 negative traces in the corpus.
- C9.4.3 Hostile commands never produce `EXACT` for something they did not literally state: quoting tricks, `git -c` options changing the URL, `--upload-pack`, `curl --next`, `curl -K`, `@file` data, environment-variable prefixes, aliases, command substitution. For each, either no rule fires or the expectation matches what the command really requests (enumerated list of at least 40 in the vectors).
- C9.4.4 MM9.6 reported.

**Sabotage.** `tokenizer-ignores-quotes`; `git-push-rule-fires-with-upload-pack-option`.

**Denied.** More packs than listed. A plugin mechanism for packs. Executing or sandboxing commands to see what they do.

## M9.5 MCP: undeclared calls and server contracts (scenario S2)

**Build.** §6.3 enforcement on `inspect: mcp` grants. Sessions with `scenario: mcp-server`: `mcp.call.begin`/`end` written into the server's session around each forwarded `tools/call`; `McpContract` loading and digesting; the checks of `04` §7.3 inline and offline; annotation check from the latest `mcp.tools`.

**Checks.**
- C9.5.1 `scriptagent --rogue=undeclared-mcp`: extra call denied `UNDECLARED_TOOL_CALL`; altered-arguments call denied; `mcpdemo` observes neither.
- C9.5.2 `mcpdemo` normal: `create_record` succeeds; server-session bundle verdict `CLEAN`.
- C9.5.3 `mcpdemo --idle-phone-home`: denied `EFFECT_OUTSIDE_CALL`; `sink`/`fakehub` observe nothing.
- C9.5.4 `mcpdemo --extra-post`: the extra request during the call is denied `CONTRACT_VIOLATION`; the legitimate request succeeds.
- C9.5.5 `mcpdemo --lying-annotation`: POST during a `readOnlyHint: true` tool call → `ANNOTATION_VIOLATION`, with no contract loaded.
- C9.5.6 Two overlapping calls of different tools: each effect is accepted only if it matches one of the in-flight calls' contract entries; template substitution uses the right call's arguments; a path built from the **other** call's arguments does not match.
- C9.5.7 Argument values with `/`, `..`, `%2f`, unicode: template matching cannot be steered outside the intended path segment.
- C9.5.8 The server-session bundle verifies on its own, without the caller's bundle.

**Sabotage.** `contract-any-inflight-tool-any-args`; `annotation-check-requires-contract`; `call-end-written-before-response-complete`.

**Denied.** Building a gateway (D2). Rewriting MCP messages. Scanning tool descriptions for poisoning. Tool allow-lists per user.

## M9.6 Policy and contract learning

**Build.** `csctl policy learn <bundle…>` and `csctl contract learn <bundle…>`: from `learn`-mode sessions, emit the narrowest `SessionPolicy`/`McpContract` that admits the observed effects: exact hosts, observed methods, paths generalized only where a segment varied across observations (replaced by `*`), `git-smart-http` grants where the pattern fits, `requires: intent` everywhere except inference, credentials left as named placeholders for the human to bind. Output is a reviewable YAML file with a comment on each grant citing the effects it came from.

**Checks.**
- C9.6.1 MM9.7.
- C9.6.2 Learned policy never contains `*` hosts, never a `**` path unless three or more distinct deeper paths were observed under that prefix, never a credential on a grant whose observed requests carried no placeholder.
- C9.6.3 Learning from a session that contains an attack (scenario A1 traffic in `learn` mode) produces a policy that includes the attacker host **with a warning comment** flagging it as never having followed a declared intent; the tool exits non-zero unless `--accept-warnings` is passed.
- C9.6.4 Deterministic output for the same input.

**Sabotage.** `learn-generalizes-to-host-wildcard`; `learn-silently-includes-unattributed-hosts`.

**Denied.** Automatic application of learned policies. Continuous learning. Any learning in `enforce` or `audit` sessions.

## M9.7 Intent annotations on changesets

**Build.** Every effect, staged ones included, records its attribution level and intents. Entry annotations per `05` §6, worst case over squashed pushes. The `requireIntent` invariant and the autonomy condition `intent` become valid for every class. The review page shows, per entry, the declaring tool call (tool name, input digest, redacted preview).

**Checks.**
- C9.7.1 A push following the model's own `git push` tool call yields an entry with attribution `EXACT`; with `requireIntent: exact` the changeset is auto-eligible and commits.
- C9.7.2 **Scenario B6 in miniature, transactional.** An install script pushes to the granted branch while `pip install` is the only open intent, `autonomy.staged: allow`: the push is staged (the agent is not interrupted), the entry's attribution is below `exact`, `requireIntent` fails, nothing reaches `fakehub`, and the review document flags the entry.
- C9.7.3 Squashing keeps the worst case in both orders: a legitimate push then a rogue push to the same ref, and the reverse, each yield a flagged entry.
- C9.7.4 With `autonomy.staged: intent`, the rogue push of C9.7.2 is refused at staging time with `NO_INTENT`.
- C9.7.5 Go and Python agree on entry annotations for 2,000 random journals.
- C9.7.6 An entry whose annotations are `null` (signal unavailable) never satisfies `requireIntent`.

**Sabotage.** `squash-keeps-last-annotation-only`; `requireintent-passes-on-null`.

**Denied.** Scoring or ranking entries. Hiding entries that pass.

## M9.8 Transaction propagation into MCP servers

**Build.** `05` §12: serialized calls to a brokered server with `calls: serialized`; during a call, the server session's write effects are handled in the **caller's** world under the caller's autonomy (`stage.entry` in the caller's session with `via_session` and `via_record_hash`; prior states into the caller's vault; a `review` condition holds the server's request and therefore the tool call); outside a call the server's writes are denied.

**Checks.**
- C9.8.1 `mcpdemo.create_record`, whose POST to `fakehub` has an outbox stager in the server's policy: the caller's changeset contains one `http` entry attributed to that tool call; `fakehub` observes nothing until the caller commits; afterwards the record exists.
- C9.8.2 Aborting the caller's world leaves `fakehub` unchanged.
- C9.8.3 Two callers invoking the server concurrently, 100 trials: calls are serialized and every entry lands in the right caller's world.
- C9.8.4 A server-side effect under condition `review`: the tool call is held; after `holdSeconds` the caller receives a JSON-RPC error carrying the problem document; after a signature, an identical retry succeeds exactly once.
- C9.8.5 Verifying the caller's bundle together with the server's bundle checks every `via_record_hash`. Without the server's bundle the verifier reports `W_CROSS_SESSION_UNVERIFIED` and still verifies everything else.
- C9.8.6 A write by the server outside any call is denied (`AUTONOMY_DENY`) in addition to the contract finding of M9.5.
- C9.8.7 A `compensable` effect made by the server during a call is undone by the caller's undo, through the server policy's grants; `fakehub` is restored.

**Sabotage.** `propagation-uses-server-world`; `calls-not-serialized`; `server-idle-writes-allowed`.

**Denied.** Propagation into unbrokered servers. Parallel calls with guessed attribution. Propagation across more than one hop (a brokered server calling another brokered server is treated as that server's own session).

---

## Exit: human gate G4

Freeze `test/vectors/reconcile/**`. The exit review must contain: MM9.6 with a plain statement of how much real traffic reaches `EXACT`; the list from MM9.3; and the reviewer question, "is there an effect class an attacker can route through `WINDOW` that matters?"
