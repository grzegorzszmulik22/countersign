# 03. Evidence format

Normative. Two independent implementations (Go `csverify`, Python `refverify`) must agree on every vector in `test/vectors/`.

## 1. Envelope

Each record is a **DSSE v1 envelope** whose payload is an **in-toto Statement v1**.

```json
{"payloadType":"application/vnd.in-toto+json",
 "payload":"<standard base64 of the statement bytes>",
 "signatures":[{"keyid":"<32 hex>","sig":"<standard base64 of 64-byte Ed25519 signature>"}]}
```

- Signed bytes: `PAE = "DSSEv1 " + len(payloadType) + " " + payloadType + " " + len(payload) + " " + payload`, lengths in ASCII decimal, `payload` being the decoded statement bytes.
- Exactly one signature. `keyid` = first 16 bytes of SHA-256 of the raw 32-byte public key, lowercase hex.
- Stored as one line of JSON terminated by `\n`. **The stored line (without the newline) is the Merkle leaf data and is never re-serialized.**

```json
{"_type":"https://in-toto.io/Statement/v1",
 "subject":[{"name":"countersign:session:<session>","digest":{"sha256":"<hex sha256 of the UTF-8 session ID>"}}],
 "predicateType":"https://countersign.dev/record/v1",
 "predicate":{ ...common fields..., "body":{ ...type-specific... } }}
```

## 2. Common predicate fields

| Field | Type | Rule |
|---|---|---|
| `v` | int | `1` |
| `type` | string | One of §4 |
| `id` | string | ULID, unique per record |
| `session` | string | ULID of the session |
| `emitter` | string | `<role>/<instance>`; role ∈ `broker`, `controller`, `world`, `observer`; instance is a ULID generated at process start |
| `eseq` | uint | Starts at 0 for each (session, emitter); increments by exactly 1 |
| `eprev` | string | Record hash (§3) of the same emitter's previous record in this session; 64 zeros at `eseq` 0 |
| `ts` | string | RFC 3339 UTC, nanoseconds. Informative only: **all ordering decisions use `eseq` and log index, never `ts`** |
| `body` | object | Per type |

Unknown predicate fields, unknown body fields and unknown `type` values are rejected (`E_SCHEMA`). The format evolves by bumping `v`.

## 3. Hashes

| Name | Definition |
|---|---|
| **Record hash** | `SHA-256(PAE)` |
| **Leaf hash** | RFC 6962: `SHA-256(0x00 ‖ stored line bytes)` |
| **Node hash** | RFC 6962: `SHA-256(0x01 ‖ left ‖ right)` |
| **Policy digest** | SHA-256 of the exact policy file bytes in the bundle |
| **Request digest** | `04` §3 |
| **Entry digest** | SHA-256 of the RFC 8785 canonical form of a changeset entry object (`05` §6) |
| **Changeset root** | RFC 6962 Merkle root whose leaves are the canonical entry objects, in journal order (`05` §6) |
| **Review digest** | SHA-256 of the review document bytes in the bundle (`05` §6) |

## 4. Record types

`E` = emitter role. Digests are lowercase hex SHA-256. `?` = may be null.

### 4.1 Session and world lifecycle

| Type | E | Body |
|---|---|---|
| `session.open` | controller | `kind` (`agent`\|`mcp-server`\|`undo`\|`replay`), `parent_session?`, `parent_seal_hash?`, `principal{subject, issuer, method}`, `sandbox{namespace, pod, pod_uid, node, runtime_class?, image_digest}`, `mode` (`enforce`\|`audit`\|`learn`), `policy_digest`, `contract_digests[]`, `ca_cert_sha256`, `log_origin`, `world{id, group?}`, `start{workspace?}`, `tape{enabled, recipient_key_id?}`, `replay?{source_session, mode}` |
| `sandbox.terminated` | controller | `reason`. The pod is gone; the world may still be open for review |
| `world.rewound` | world | `to_journal_seq`, `dropped_entries[]`, `undo_id?` |
| `world.closed` | world | `outcome` (`committed`\|`aborted`\|`partial`\|`superseded`\|`expired`\|`empty`), `commits[]` |
| `session.seal` | controller | `reason`, `emitters[]{emitter, final_eseq, head_hash, clean}`, `counts{effects, intents, denials, entries, commits}`. Written only after `world.closed` |
| `emitter.seal` | any | `final: true`. The last record an emitter writes for the session |

### 4.2 Effects

| Type | E | Body |
|---|---|---|
| `effect.http` | broker | `effect_id`, `actor` (`sandbox`\|`world`), `purpose?` (actor `world` only: `sync`\|`apply`\|`prestate`\|`poststate`\|`compensate`\|`probe`), `for?` (the entry or effect ID it serves), `conn_id`, `client{ip, port}`, `request{method, scheme, authority, path, query_sha256, query_len, header_names[], body_sha256?, body_len?, body_deferred}`, `request_digest?`, `class` (`control`\|`safe`\|`staged`\|`compensable`\|`irreversible`), `decision{action, reason, requires, grant?, credentials[], would_deny?}`, `attribution{level, intents[], lineage, owner?}`, `taint[]` (labels present at decision time), `budget{leak_bytes, writes}` (charged by this effect), `inspect` (`none`\|`inference`\|`mcp`) |
| `effect.http.result` | broker | `effect_id`, `served_by` (`upstream`\|`world`\|`boundary`\|`replay`), `status?`, `response{header_names[], body_sha256, body_len}`, `request_body{sha256, len}`, `upstream?{ip, port, tls_version?, cert_sha256?}`, `timing{total_ms, ttfb_ms}`, `scrubbed`, `error?` |
| `effect.tunnel` / `effect.tunnel.result` | broker | Passthrough or WebSocket: `effect_id`, `authority`, `sni?`, `kind`, `decision{…}`; then `bytes_up`, `bytes_down`, `duration_ms`, `error?`. Class `irreversible` unless the grant declares one |
| `effect.denied` | broker | Rejected before a full HTTP request existed: `conn_id`, `client`, `authority?`, `reason`, `detail` |
| `effect.exec` | observer | `exec_id`, `parent_exec_id?`, `pid`, `binary`, `argv_sha256[]` (each argument, at most 64), `argv_truncated`, `uid` |
| `effect.connect` | observer | `exec_id`, `pid`, `dst{ip, port}`, `src_port`, `proto`, `outcome` (`to-broker`\|`blocked`) |
| `observer.gap` | observer | `from`, `to`, `reason` |

`decision.action` ∈ `allow`, `deny`, `hold`, `stage`. `decision.requires` ∈ `allow`, `intent`, `review`, `deny`: the condition the policy imposed (`05` §2).

### 4.3 The world

| Type | E | Body |
|---|---|---|
| `stage.entry` | world | `entry_id`, `journal_seq`, `via_effect`, `via_session?`, `via_record_hash?` (set when the staging effect belongs to a brokered MCP server's session, `05` §12), `entry` (the canonical entry object, `05` §6), `entry_sha256`, `supersedes?` (an earlier entry this one replaces after squashing) |
| `prestate.captured` | world | `for_effect`, `for_session?`, `when` (`before`\|`after`), `via_effect` (the read that fetched it), `status`, `state_sha256`, `len`, `etag?` |
| `commit.requested` | world | `commit_id`, `trigger` (`agent`\|`operator`\|`session-end`\|`barrier`\|`held-effect`), `entries[]`, `changeset_root`, `review_sha256`, `invariants[]{name, pass, detail}`, `auto_eligible`, `expires_at` |
| `commit.decision` | world | `commit_id`, `decision` (`commit`\|`reject`\|`timeout`), `by` (`auto`\|`human`\|`delegate`), `selected[]`, `selected_root`, `review_sha256`, `expires_at`, `probation?{until, on_expiry}` (`on_expiry` ∈ `keep`\|`revert`), `webauthn?{key_id, authenticator_data, client_data_json, signature}` (required when `by` is `human`), `delegate?{key_id, signature}` (required when `by` is `delegate`) |
| `commit.applied` | world | `commit_id`, `entry_id`, `outcome` (`applied`\|`conflict`\|`failed`\|`unknown`), `via_effect?`, `precondition{kind, expected, observed}`, `id_map?` (provisional → real) |
| `commit.closed` | world | `commit_id`, `outcome` (`committed`\|`partial`\|`rejected`\|`expired`\|`rolled-back`) |
| `probation.ratified` | world | `commit_id`, `webauthn{…}` |
| `undo.requested` | world | `undo_id`, `scope` (`session`\|`commit`\|`effect`), `targets[]`, `trigger` (`operator`\|`probation-expired`\|`probation-revoked`\|`group-superseded`\|`commit-failure`\|`rewind`), `webauthn?{…}` (required when the trigger is `operator`) |
| `undo.applied` | world | `undo_id`, `target`, `outcome` (`restored`\|`conflict`\|`not-compensable`\|`failed`), `via_effect?`, `precondition{expected, observed}` |
| `undo.closed` | world | `undo_id`, `restored`, `conflicts`, `not_compensable`, `failed` |
| `attestation.issued` | world | `commit_id`, `entry_id`, `subject{kind, name, digest}`, `statement_sha256` |

### 4.4 Meaning

| Type | E | Body |
|---|---|---|
| `intent.declared` | broker | `intent_id`, `source` (`inference`\|`mcp`), `provider`, `model?`, `via_effect`, `tool`, `class`, `executor` (`sandbox`\|`provider`), `input_sha256`, `input_len`, `input_preview?`, `anchor_sha256?` (`04` §10) |
| `intent.result` | broker | `intent_id`, `via_effect`, `closed_by` (`tool_result`\|`seal`\|`timeout`), `content_sha256?`, `content_len?`, `is_error?` |
| `intent.unparsed` | broker | `via_effect`, `provider`, `detail` |
| `context.observed` | broker | One per inference request: `via_effect`, `provider`, `model?`, `block_count`, `context_sha256`, `new_blocks[]{index, role, kind, sha256, len, intent_id?}` |
| `taint.added` | broker | `label`, `source` (`effect`\|`provider-tool`\|`initial`), `source_effect?`, `source_grant?` |
| `mcp.call.begin` / `mcp.call.end` | broker | Written into the **MCP server's** session: `call_id`, `caller_session`, `caller_world`, `caller_effect`, `tool`, `arguments_sha256`, `contract_args{…}`; then `call_id`, `is_error`, `result_sha256` |
| `mcp.tools` | broker | Observed `tools/list` result: `server`, `tools[]{name, annotations{…}, schema_sha256}` |
| `replay.divergence` | broker | Replay sessions only: `position`, `expected?{effect_id, request_digest}`, `observed{method, authority, path, request_digest?, class}`, `policy_decision` |

### 4.5 Ordering rules that matter

- **Write-ahead.** `effect.http` is durably appended and acknowledged **before** the first byte goes upstream or to the world service. `intent.declared` is durable **before** the bytes completing that tool-use block reach the sandbox. `taint.added` is durable **before** the first byte of the tainting response reaches the sandbox.
- **Stage before answer.** `stage.entry` is durable before the agent receives the success response for the staged request.
- **Prior state before write.** `prestate.captured{when: before}` is durable before a `compensable` request is forwarded.
- **Decision before apply.** `commit.decision` is durable before any `effect.http{purpose: apply}` of that commit. `commit.applied` follows the result of its apply effect.
- **Deferred bodies.** Request bodies up to the grant's `bufferLimit` are buffered so that `body_sha256` and `request_digest` are in the write-ahead record. Larger bodies stream, with the digest in the result. A request that is staged, held for review, captured for undo, or inspected must fit in the buffer, otherwise `LIMIT_BODY`. Git pack data is exempt: it streams to the shadow remote and is identified by the resulting object IDs.

## 5. Ledger storage

```
ledger/
  log/entries.jsonl          every envelope, in append order; line N is log index N
  log/hashes.bin             32-byte leaf hashes, index-aligned
  log/checkpoints/<size>.txt signed checkpoints
  sessions/<session>.idx     log indices of the session, ascending
```

Single writer; group commit with an `fsync` at most every 2 ms; an append returns only once durable. A checkpoint is issued on every `session.seal`, every `commit.closed`, and at least every 10 seconds while entries are pending. Files are append-only.

## 6. Checkpoints and proofs

C2SP `tlog-checkpoint` in a signed note, signed by the `log` key, origin `countersign.dev/log/<log ID>`. Inclusion and consistency proofs per RFC 6962 §2.1. **External oracle:** our checkpoints verify with `golang.org/x/mod/sumdb/note`, and our proofs with an independent Merkle library; the Python reference implements both from the RFC text.

## 7. Bundle

A deterministic tar archive (entries sorted by name, zeroed mtime/uid/gid):

| Entry | Content |
|---|---|
| `manifest.json` | `{"bundle_version":1,"session":"…","log_origin":"…","created":"…"}` |
| `keys.json` | Key manifest: `[{key_id, role, public_key, not_before, not_after?}]`; roles `emitter:broker`, `emitter:controller`, `emitter:world`, `emitter:observer`, `log`, `attestor`, `reviewer` (with `rp_id` and `origins`), `reviewer:delegate`, `witness` |
| `records.jsonl` | The session's envelopes in log order, byte-identical to the ledger |
| `index.json` | Per record: `log_index`, `inclusion_proof[]` |
| `checkpoint.txt` | A checkpoint covering `session.seal` |
| `policy.yaml`, `contracts/*.yaml` | Bytes matching the declared digests |
| `reviews/<commit_id>.json` | Each review document, matching `review_sha256` |
| `attestations/<n>.json` | Each issued statement (DSSE), matching `statement_sha256` |
| `cosignatures.txt` | Optional witness cosignatures (format specified, not implemented in this plan) |

Trust input: the bundle plus a **trusted key manifest supplied out of band** (`--keys`).

The bundle never contains staged bodies, prior states or tape. Those stay in the world service's encrypted stores and are referenced by digest.

## 8. What the ledger must not contain

- No credential values. A test greps the ledger for every canary.
- No request or response bodies; no prior-state bodies; no git objects. Digests and lengths only.
- Previews are capped at 256 bytes, pass the credential-shape redactor, and can be disabled per policy.
- Query strings as digest and length only.
- Review documents list changed file **paths** and line counts, never file content. `privacy.reviewPaths: false` replaces paths with their digests in the bundled copy.

## 9. Reason codes

| Code | Meaning |
|---|---|
| `OK` | Allowed |
| `STAGED` | Routed to the world; nothing sent to the real destination |
| `NO_SESSION` / `NO_GRANT` / `DENY_GRANT` | Identification and grant selection |
| `AUTONOMY_DENY` | The class's autonomy level is `deny` |
| `NO_INTENT` / `UNDECLARED_TOOL_CALL` | Intent conditions |
| `REVIEW_REQUIRED` / `REVIEW_REJECTED` / `REVIEW_TIMEOUT` | Held for, or refused by, a signed review |
| `BARRIER` | A non-staged write arrived while staged entries exist and policy forbids proceeding |
| `TAINTED_DENY` | The grant denies when a present label applies |
| `FOREIGN_CREDENTIAL` / `PLACEHOLDER_MISUSE` | Credential rules |
| `LIMIT_BODY` / `LIMIT_URL` / `LIMIT_RATE` | Limits |
| `BUDGET_LEAK` / `BUDGET_WRITES` | A session budget is exhausted |
| `REF_NOT_ALLOWED` | A git ref update outside the grant's ref rules |
| `PROTOCOL_DENIED` / `SMUGGLING_SUSPECT` / `UPSTREAM_BLOCKED` / `UPSTREAM_TLS` | Protocol and upstream checks |
| `LEDGER_UNAVAILABLE` / `WORLD_UNAVAILABLE` / `OBSERVER_REQUIRED` | Fail-closed |
| `WORLD_CLOSED` / `GROUP_SUPERSEDED` | The world no longer accepts writes |
| `CONTRACT_VIOLATION` / `EFFECT_OUTSIDE_CALL` / `ANNOTATION_VIOLATION` | Scenario S2 |
| `REPLAY_DIVERGENCE` | Replay: the request is not on the tape |

## 10. Verifier algorithm

`csverify <bundle> --keys keys.json [--reconcile]`. Output is JSON: `{"verdict", "world", "errors", "warnings", "findings", "stats"}`. Exit code 0 only for `CLEAN` and `CLEAN_WITH_DENIALS`.

| Step | Check | Failure |
|---|---|---|
| V1 | Archive well-formed; required entries present; none extra | `E_BUNDLE` |
| V2 | Every line is a DSSE envelope with one signature; payload and schema valid | `E_SCHEMA` |
| V3 | Signature verifies under a trusted key whose role matches the emitter role and whose validity covers `ts` | `E_SIG`, `E_KEY` |
| V4 | Subject digest matches `session`; every record's `session` equals the manifest's | `E_SESSION` |
| V5 | Per emitter: `eseq` contiguous from 0; each `eprev` equals the previous record hash; no duplicates | `E_CHAIN` |
| V6 | Checkpoint signed by a `log` key that is no emitter or attestor key; origin matches | `E_CHECKPOINT` |
| V7 | Every inclusion proof verifies; `log_index` strictly increasing | `E_INCLUSION` |
| V8 | First record is `session.open`; policy and contracts match their digests | `E_OPEN`, `E_POLICY` |
| V9 | `world.closed` exists, then `session.seal` as the last controller record. Otherwise verdict `UNSEALED` | (verdict) |
| V10 | For each emitter in the seal: `final_eseq` and `head_hash` equal the chain's head; no emitter missing from the seal; nothing after a sealed head | `E_SEAL` |
| V11 | Structure: each result follows its effect, at most one per effect; each `stage.entry`, `prestate.captured`, `commit.*`, `undo.*`, `intent.result` refers to earlier records of the right type; the ordering rules of §4.5 hold in log order | `E_STRUCTURE` |
| V12 | Each `commit.requested`: `changeset_root` recomputed from the entries' canonical objects; the bundled review document hashes to `review_sha256` and lists exactly those entries. Each `commit.decision`: `selected ⊆ entries`, `selected_root` recomputed; for `by: human` the WebAuthn assertion verifies (`05` §8); for `by: delegate` the Ed25519 signature verifies under a `reviewer:delegate` key and the acceptance conditions of `05` §8 hold; for `by: auto` every recorded invariant passed and `auto_eligible` is true | `E_COMMIT` |
| V13 | Each `effect.http{purpose: apply}` belongs to a commit whose decision is `commit`, serves an entry in `selected`, follows the decision, and no entry has two apply effects with a result. No apply effect exists for an unselected entry | `E_COMMIT` |
| V14 | Each bundled attestation verifies under an `attestor` key, matches its `statement_sha256`, and names an entry with outcome `applied` | `E_ATTEST` |
| V15 | Warnings: effects without a result (`W_DANGLING`); emitters sealed unclean (`W_UNCLEAN_EMITTER`); `observer.gap` (`W_OBSERVER_GAP`); `intent.unparsed` (`W_UNPARSED`); a commit closed `partial` (`W_PARTIAL_COMMIT`); an apply outcome `unknown` (`W_APPLY_UNKNOWN`); an undo with conflicts (`W_UNDO_CONFLICT`) | (warnings) |
| V16 | With `--reconcile`: recompute classes, autonomy decisions, attribution, lineage, taint, budgets, invariants, preconditions and undo guards from the records and the bundled policy (`04` §6–§11, `05`), and compare with what was recorded | findings |

Verdicts, most severe first: `INVALID` (any `E_*`) → `UNSEALED` → `LEARN` → `VIOLATIONS` (any error-severity finding) → `CLEAN_WITH_DENIALS` → `CLEAN`. The `world` field reports the world's outcome separately.

**A bundle with no seal can never be `CLEAN`.** A session is not sealed until its world is closed.

## 11. Mutation classes (M1.6, H4)

| # | Class | Expected |
|---|---|---|
| 1 | Flip one bit in a payload | `E_SIG` |
| 2 | Flip one bit in a signature | `E_SIG` |
| 3 | Delete one non-final record | `E_CHAIN` or `E_INCLUSION` |
| 4 | Swap two records | `E_CHAIN` or `E_INCLUSION` |
| 5 | Truncate the last k records, with and without substituting an older genuine checkpoint | `E_SEAL`, `E_INCLUSION`, or `UNSEALED`; never `CLEAN*` |
| 6 | Replace a record with a genuine one from another session | `E_SESSION` or `E_CHAIN` |
| 7 | Modify a record and re-sign with a key absent from the trusted manifest, or with the wrong role | `E_KEY` |
| 8 | Alter the checkpoint, or sign it with an emitter key | `E_CHECKPOINT` or `E_INCLUSION` |
| 9 | Duplicate a record | `E_CHAIN` |

Directed extras: altered `policy.yaml` → `E_POLICY`; a result moved before its effect → `E_STRUCTURE`; bundled keys differing from the trusted manifest → `E_KEY`; a review document altered → `E_COMMIT`; an attestation altered → `E_ATTEST`. Commit-specific mutations are in M6.9.
