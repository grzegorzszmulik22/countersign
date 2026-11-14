# 05. Transactions: classes, worlds, commit, undo, time, provenance

Normative. Python references (`refclassify`, `refcommit`, `refwhatif`) are the executable form of §1, §2, §6–§11 and §13.1. Where prose and reference disagree, file a change request.

Policy fields introduced here extend the `SessionPolicy` of `04` §1:

```yaml
spec:
  autonomy: {safe: allow, staged: allow, compensable: intent, irreversible: review}
  world:
    onSessionEnd: hold            # hold | abort
    reviewTtl: 24h
    group: {mode: exactly-one, losers: undo}     # used when pods share the label countersign.dev/world-group
  commit:
    auto: {enabled: true, invariants: { ... §7 ... }}
    barrier: commit-first         # deny | commit-first | independent
    onFailure: stop               # stop | compensate
    probation:
      human: {duration: 0s}
      auto: {duration: 24h, onExpiry: keep}        # keep | revert
      delegate: {duration: 24h, onExpiry: keep}
    delegate: {enabled: false, minProbation: 1h, forbidTaint: [web, provider-tool],
               hardInvariants: [git.refs, git.noCredentialShapes, budgetsWithin]}
    review: {ttl: 24h, holdSeconds: 50, userVerification: preferred}
  budgets:
    leak: {bytes: 4096}
    writes: {maxResources: 50, maxDeletes: 5}
  tape: {enabled: false, grants: all, onFailure: deny}
  attest: {enabled: true, gitNotes: false}
```

## 0. Related work

Nothing in this document is new as an idea (`00` §2; `reports/Prior art check.md`). The work to read and cite:

| Topic | Work | Relation |
|---|---|---|
| Reversibility classes, branches where one commits | Atomix (ICLR 2026); "Revisable by Design" (arXiv 2604.23283) | Same lattice, applied by tool adapters inside the agent framework |
| Shadow state, effect outbox, atomic commit | Cordon (arXiv 2606.17573) | The closest design; intercepts at tool dispatch and excludes opaque tools |
| Undo of model-driven actions | GoEx (2024); STRATUS; Rubrik Agent Rewind | No guard against overwriting later changes |
| One review of staged changes | YoloFS; GitLab issue 591235 | Filesystem only; unbuilt |
| Approval bound to an action's hash, consumed once | draft-schrock-ep-authorization-receipts | §8 follows this pattern for single effects |
| Apply, then revert unless confirmed | Junos `commit confirmed` | The model for probation with `onExpiry: revert` |
| Bounding unpredictable request bytes | Borders & Prakash (2008–2009); Metere (arXiv 2605.20734); OCELOT (arXiv 2606.12341) | §11 |
| Network-layer replay; first-divergence reports | agrepl (arXiv 2607.16200); AgentCheck (arXiv 2607.11098); Docker cagent; ZenML Kitaru; Docent | §13 |
| Agent-authored commit statements | in-toto attestation PR #603; yuma-agent-git #58; Git AI | §14 |
| Rules mined from review history | Hedwig (arXiv 2605.11495) | §13.4 |

What this design adds is where it sits: below the agent, on one signed ledger, checkable by outsiders.

## 1. Reversibility classes

Every request selected by a grant gets exactly one class. The procedure is ordered; the first rule that applies wins.

| # | Condition | Class |
|---|---|---|
| 1 | Grant has `inspect: inference`; or the host is the boundary endpoint; or an MCP protocol message other than `tools/call` | `control` |
| 2 | Grant declares `class:` explicitly | that class (`staged` is valid only with a stager; a declared `safe` on a non-GET method, a tunnel or a WebSocket is flagged `declared_safe` in every review) |
| 3 | Grant has `mode: passthrough`, or the request is a WebSocket upgrade | `irreversible` |
| 4 | Grant has a stager and the request is one the stager stages (§4, §5) | `staged` |
| 5 | Git smart-HTTP read (`upload-pack`, its `info/refs`) | `safe` |
| 6 | Method is GET, HEAD or OPTIONS | `safe` |
| 7 | MCP `tools/call` to a **brokered** server with `calls: serialized` (§12) | `control` |
| 8 | MCP `tools/call` to any other server | per-tool class from the grant's `tools:` map; default `irreversible`. Tool annotations from the server are never trusted for this |
| 9 | Grant has a `compensate` rule that applies to this method (§10) | `compensable` |
| 10 | Otherwise | `irreversible` |

`control` effects are the agent talking to its model or to its own boundary. They are never staged, held or undone.

## 2. Autonomy

`autonomy` maps a class to a condition: `allow` < `intent` < `review` < `deny`.

The condition actually imposed on an effect is the **strictest** of:

1. `autonomy[class]`
2. the grant's own `requires`, if set
3. the grant's `whenTainted` outcome for the labels present (`04` §8); applies to `compensable` and `irreversible` only
4. `deny` if a budget is exhausted (§11)

| Condition | `safe` | `staged` | `compensable` | `irreversible` |
|---|---|---|---|---|
| `allow` | forward | stage | capture prior state, forward | forward |
| `intent` | forward iff `04` §6.4 holds | stage iff it holds | as `allow`, iff it holds | forward iff it holds |
| `review` | hold for a single-effect review (§8) | stage; the entry may **not** be committed automatically | hold for a single-effect review | hold for a single-effect review |
| `deny` | `AUTONOMY_DENY` | `AUTONOMY_DENY` | `AUTONOMY_DENY` | `AUTONOMY_DENY` |

`intent` is available once M9 is built. Before that, a policy using it is rejected at validation.

Design consequence: for `staged` effects taint and missing intents never interrupt the agent. They are recorded as annotations on the entry and decide whether the changeset may commit without a human.

## 3. Worlds

A **world** is one session's private overlay on reality.

- **One world per session**, created at `session.open`. It owns a staging journal (ordered entries), stager state, a prior-state vault, and optionally a tape. All content at rest is encrypted with the world data key.
- **States.** `open` → `committing` → `open` (a world can commit several times; each commit empties the applied entries) → `closed` with an outcome.
- **The world outlives the sandbox.** When the pod ends: `sandbox.terminated` is recorded. With `onSessionEnd: hold` the world stays open for review until `reviewTtl`, then closes `expired` and discards its entries. With `abort` it closes `aborted` at once. A world with no entries closes `empty`.
- **The session is sealed only after its world is closed.**
- **Abort** discards every pending entry and deletes the stager state. Effects that were applied directly (`compensable`, `irreversible`) are not touched by abort; undo is a separate, explicit act (§10).
- **Rewind** (`csctl world rewind <session> --to <entry>`): drops pending entries with a later `journal_seq`, restores stager state to that point (the git stager keeps every staged ref value), and requests undo of `compensable` effects applied after that point.
- **World groups.** Pods created with the same `countersign.dev/world-group` label start from the same state and race. With `group.mode: exactly-one`, the first world in the group whose commit closes `committed` wins. Every other world in the group is closed `superseded`: pending entries discarded, later writes denied `GROUP_SUPERSEDED`, and, with `losers: undo`, directly applied `compensable` effects are undone. Two commits racing are serialized by the world service; the loser's `commit.decision` is recorded as `reject`.
- Worlds are not shared, merged or nested (D23). Worlds fork only at session start (D13).

## 4. The git stager

Enabled per grant:

```yaml
- id: repo
  match: {hosts: [github.com], matcher: {git-smart-http: {repos: [acme/widgets], access: write}}}
  stager: {git: {refs: ["refs/heads/agent/*"], allowDelete: false, allowNonFastForward: false, maxPackBytes: 512Mi}}
  credential: { ... }
```

**Storage.** Per (remote, credential): a read-only **mirror** holding upstream objects. Per (world, remote): a **shadow repository** whose object store borrows from the mirror. Staged objects exist only in the shadow. Aborting deletes the shadow.

**Every git request from the sandbox on this grant is answered by the world service, never by upstream.**

- **Read path** (`info/refs`, `upload-pack`). The world service first syncs the mirror from upstream, through the broker, as `actor: world, purpose: sync`, using the session's own credential. A sync result is reused for at most 5 seconds. If the sync fails, the request fails; a stale view is never served. It then serves an **overlay**: for each ref, the staged value if the world has a pending entry for it, otherwise the upstream value.
- **Write path** (`receive-pack`). The pack is received into the shadow. A pre-receive check enforces the stager's rules: ref name matches `refs`; deletions and non-fast-forward updates only if allowed; pack size within `maxPackBytes`. A violation is reported to the git client as a normal remote rejection naming `REF_NOT_ALLOWED`. Each accepted ref update becomes a staged entry (§6). The client sees a successful push. **The real remote receives nothing.**
- **Read-your-writes.** A later fetch or `ls-remote` sees the staged refs.
- **Squashing.** A second push to a ref with a pending entry replaces that entry (`supersedes`), keeping its `base`.

Served with `git http-backend`. Not supported, and rejected clearly: Git LFS, push options, signed pushes, the dumb HTTP protocol.

## 5. Deferred sends and provisional identifiers

For write APIs whose response is simple and whose effect can wait:

```yaml
- id: notify
  match: {hosts: [chat.example], methods: [POST], paths: [/api/messages]}
  stager:
    outbox:
      respond: {status: 200, contentType: application/json,
                body: '{"ok": true, "id": "{provisional}", "channel": "{request.json./channel}"}'}
      idMap: {provisional: /id, real: /id}
      idempotencyHeader: Idempotency-Key
```

- The request is stored encrypted in the world, a `stage.entry` is recorded, and the agent receives the synthetic response. Template variables: `{provisional}` (a fresh `csid_<26-char ULID>`), `{request.json.<pointer>}`, `{request.header.<name>}`. Nothing else.
- **Provisional identifiers.** Until the entry is applied, any later request whose URL, headers or buffered body contains a provisional ID is itself **dependent**: it must be `staged` (it then records a dependency on that entry) or it is a barrier (§9).
- At apply, the real response is read, `idMap` extracts the real ID, and the mapping is recorded. Later pending entries containing the provisional ID are rewritten byte-for-byte before they are applied. For the rest of the session, requests from the sandbox containing an already-mapped provisional ID are rewritten by the broker.
- An outbox entry is not `compensable` unless the grant also has a `compensate` rule.

## 6. Changesets and the review document

**Entry objects** (canonicalized with RFC 8785):

| Type | Fields |
|---|---|
| `git-ref` | `type`, `grant`, `remote`, `ref`, `base` (upstream value when first staged, or null), `new` (staged value, or null for deletion), `commits`, `fast_forward` |
| `http` | `type`, `grant`, `method`, `authority`, `path`, `request_digest`, `body_len`, `provisional[]`, `depends_on[]` |
| `held` | `type`, `grant`, `effect_id`, `request_digest`, `class` |

Because `new` is a git object ID, signing a `git-ref` entry commits the signer to the exact content.

**Changeset.** The pending entries of a world in `journal_seq` order, after squashing. `changeset_root` is the RFC 6962 Merkle root over their canonical bytes. A reviewer may select a subset; `selected_root` is computed the same way over the selected entries in the same order. A subset is valid only if it contains every entry that a selected entry `depends_on`.

**Review document.** One deterministic JSON file per commit request, stored in the bundle and hashed as `review_sha256`:

```
{ v, session, world, commit_id, trigger, created,
  entries: [ { entry_id, entry, entry_sha256,
               annotations: { class, declared_safe, intents[], attribution, lineage, owner, taint[] },
               facts: { … } } ],
  invariants: [ { name, pass, detail } ],
  taint: { labels[], sources[ { label, effect } ] },
  budgets: { leak: {used, limit}, writes: {resources, deletes, limits} },
  applied_directly: [ { effect_id, class, method, authority, path, undo } ] }
```

- `facts` for `git-ref`: commit IDs; changed paths with added and deleted line counts; binary files with sizes; count of credential-shaped strings in added lines, by path; whether it is a fast-forward of `base`. For `http`: method, authority, path, content type, body length. File content and request bodies are never in the document; the review page fetches them from the world service for display.
- `annotations` come from the records: each staging effect carries `attribution`, `taint` and lineage. For a squashed entry they are the **worst case over every staging effect that contributed to it**, superseded ones included: the lowest attribution level, `owned` only if all were owned by an attributed intent, and the union of taint labels. Fields whose milestone is not built yet are `null`.
- `applied_directly` lists `compensable` and `irreversible` effects already made real in this session, with whether an undo exists. They are context, not part of the root.

## 7. Invariants and automatic commit

A fixed vocabulary (D3). Each evaluates to pass or fail with a detail string.

| Invariant | Passes when |
|---|---|
| `maxEntries: n` | The changeset has at most `n` entries |
| `git.refs: [glob]` | Every `git-ref` entry's ref matches |
| `git.paths: {allow: [glob], deny: [glob]}` | Every changed path matches an `allow` glob and no `deny` glob |
| `git.maxChangedFiles: n`, `git.maxAddedLines: n` | Totals across the changeset |
| `git.maxBinaryBytes: n` | No added binary file larger than `n` |
| `git.noCredentialShapes: true` | Zero credential-shaped strings in added lines (`04` §4.4) |
| `git.fastForwardOnly: true` | Every `git-ref` entry is a fast-forward of its `base` |
| `http.hosts: [..]`, `http.maxBodyBytes: n` | For `http` entries |
| `noHeld: true` | No `held` entries |
| `noDeclaredSafe: true` | No effect in the session used a grant-declared `safe` on a non-GET method |
| `forbidTaint: [labels]` | No listed label is in any entry's `taint` (available from M10) |
| `requireIntent: exact \| window` | Every entry's attribution is at least that level (from M9) |
| `requireOwnership: true` | Every entry's lineage is `owned` by one of its attributed intents (from M11) |
| `budgetsWithin: true` | No budget is exhausted |

A changeset is **auto-eligible** iff `commit.auto.enabled`, every configured invariant passes, and no entry was staged under condition `review`. An invariant that needs a signal the deployment does not produce is a policy validation error.

**Commit triggers:** the agent asks (`POST /v1/commit` on the boundary, §15); an operator asks (`csctl commit`); the session ends with `onSessionEnd: hold`; a barrier with `commit-first` (§9); a held effect (§8). On a trigger, the world service records `commit.requested`. If auto-eligible, it records `commit.decision{by: auto}` and applies. Otherwise the request waits for a reviewer, human or delegated (§8), until `review.ttl`.

## 8. Signed review

A review decision is a signature over this challenge:

```
SHA-256( "countersign-review-v1\n" ‖ session ‖ "\n" ‖ commit_id ‖ "\n" ‖ selected_root_hex ‖ "\n" ‖
         review_sha256_hex ‖ "\n" ‖ expires_at ‖ "\n" ‖ probation_until_or_empty ‖ "\n" ‖ on_expiry_or_empty ‖ "\n" ‖ decision )
```

with `decision` ∈ `commit`, `reject`. The same construction with other prefixes signs a ratification (`countersign-ratify-v1`, fields: session, commit_id) and an operator undo (`countersign-undo-v1`, fields: session, undo_id, Merkle root over the target IDs).

**Who may sign.**

- A **human reviewer** signs with a passkey: the WebAuthn assertion's challenge is the value above.
- A **delegated reviewer**, only when `commit.delegate.enabled`: a separate service holding an Ed25519 key with role `reviewer:delegate`, which signs the same value. It may be a program or a model. It is **outside** Countersign. It is assumed to be fallible and open to prompt injection through the content it reads. Its signature is accepted only if all of the following hold, and the world service and both verifiers recompute them:
  1. the changeset has no `held` entry (a delegate never authorizes anything `irreversible`);
  2. every invariant named in `delegate.hardInvariants` passed;
  3. no selected entry carries a label listed in `delegate.forbidTaint`;
  4. the decision is `reject`, or `commit` with probation of at least `delegate.minProbation`.
- A delegate can never ratify, revoke or undo, and never signs a single-effect review.
- The decision records `by: human` or `by: delegate`. The distinction is carried into attestations (§14) and can be required by the gate.

The reason for the role: the major agent platforms already put a model reviewer at the permission boundary, and by their own figures it catches far more than people do, while still missing about one dangerous action in nine. Bounded this way, a delegate's miss lands on something reversible, inside a window in which a person can revoke it, with the miss on the record.

The single-effect binding follows the pattern of draft-schrock-ep-authorization-receipts (the challenge is the hash of the action context; the approval is consumed once at the executor). M6.3 compares against the current revision.

**Verification** (inline by the world service; offline by both verifiers; `E_COMMIT` on failure): the challenge is recomputed from the record. For `by: delegate`: the Ed25519 signature verifies under a `reviewer:delegate` key, and the four acceptance conditions are recomputed. For `by: human`: `clientDataJSON.type` is `webauthn.get`; its `challenge` matches; its `origin` is among the reviewer key's origins in the trusted manifest; the RP ID hash matches; user-present is set (user-verified too if `userVerification: required`); the signature verifies under a `reviewer` key; `commit.decision` precedes every apply effect; the decision time is ≤ `expires_at`.

**Single-effect review** (an effect under condition `review` that is not staged):

1. The request must fit the buffer. The broker records `effect.http{action: hold}` and asks the world service for a one-entry changeset of type `held`.
2. It holds the connection up to `holdSeconds`. If undecided it answers `403` with a problem document (§15) naming the commit ID. The request stays reviewable until `expires_at`.
3. On `commit` within the hold, the broker forwards **the held bytes**. After a pending answer, the next request in the session with an identical `request_digest` before `expires_at` is the apply. Exactly once.
4. `reject` → `REVIEW_REJECTED`; expiry → `REVIEW_TIMEOUT`.

## 9. Apply, conflicts, barriers

**Apply.** For each selected entry in journal order, the world service makes the real request through the broker as `actor: world, purpose: apply`. Grants, credentials and write-ahead recording apply as for any request.

| Entry | Request | Precondition | Outcome mapping |
|---|---|---|---|
| `git-ref` | `git push --force-with-lease=<ref>:<base>` of `new` (or a deletion) | Upstream ref equals `base` | accepted → `applied`; lease rejected → `conflict`; else `failed` |
| `http` | The stored request, provisional IDs rewritten, with the configured idempotency header set to the entry ID | The entries it depends on are `applied` | 2xx → `applied`; 409 or 412 → `conflict`; other 4xx/5xx → `failed` |
| `held` | Release of the held bytes, or the identical retry | `expires_at` not passed | as `http` |

- **At most once.** An entry with a recorded apply effect is never applied again, except an `http` entry with an idempotency header, which may be retried up to three times on a connection error.
- **Crash.** An apply effect with no result after a restart yields outcome `unknown`. It is reported and never retried automatically.
- **On the first `conflict` or `failed`:** with `onFailure: stop`, later entries stay pending and the commit closes `partial`. With `compensate`, already-applied entries of this commit are undone (§10) and it closes `rolled-back`, or `partial` if an undo conflicts.
- **No automatic conflict resolution** (D24). The agent, if still running, sees the new upstream state on its next fetch and can restage.

**Barriers.** A request that is not `safe`, `control` or `staged`, arriving while the world has pending entries, is a barrier, as is any non-staged request containing an unmapped provisional ID.

| `commit.barrier` | Behaviour |
|---|---|
| `commit-first` (default) | A commit of the pending entries is triggered. If it closes `committed`, the request proceeds under its own class rules. Otherwise the request is denied `BARRIER` |
| `deny` | Denied `BARRIER` |
| `independent` | The request proceeds without a commit. Not allowed for requests containing a provisional ID |

## 10. Undo and probation

**Compensation rules** (per grant):

```yaml
compensate:
  restore: {methods: [PUT, PATCH]}                       # put the prior representation back
  deleteCreated: {methods: [POST], from: location}       # or: {from: {jsonPointer: /url}} or {urlTemplate: "/repos/acme/widgets/issues/comments/{json./id}"}
  stateDigest: {ignore: [/updated_at, /etag]}             # fields excluded when comparing states
```

**Capture.** For a `compensable` effect the world service, through the broker (`purpose: prestate`), GETs the resource before the write and records `prestate.captured{when: before}`; after the write it GETs the resource again (`purpose: poststate`) and records `when: after`. For `deleteCreated` the resource is the created URL, and only the post state exists. Bodies go to the encrypted vault; the ledger holds digests. State digests are computed over the RFC 8785 canonical form of the JSON body with `stateDigest.ignore` pointers removed, or over raw bytes for non-JSON.

**Undo** (`csctl undo <session> [--commit id | --effect id]`, signed by a reviewer). Targets are processed in reverse order. For each:

1. **Guard.** GET the resource now (`purpose: probe`). If its state digest differs from the recorded post state → outcome `conflict`; write nothing.
2. **Compensate** (`purpose: compensate`): `restore` → PUT the prior body (DELETE if the prior state was "absent"); `deleteCreated` → DELETE the created URL; an applied `git-ref` entry → push `base` back with a lease on `new`.
3. Anything with no rule → `not-compensable`, reported.

If the session is already sealed, the undo runs in a new session of kind `undo` that names its parent and the parent's seal hash, and produces its own bundle.

**Probation.** Every commit decision carries `probation{until, on_expiry}` (possibly empty), fixed inside the signed challenge. Defaults come from `commit.probation` by who decided:

| Decided by | Default | Why |
|---|---|---|
| `human` | none | A person looked at the whole change |
| `auto` | 24 h, `keep` | No reviewer saw it |
| `delegate` | 24 h, `keep`; never shorter than `delegate.minProbation` | The reviewer is fallible and injectable |

- **`on_expiry: keep`** (an undo window). The commit stands. The world closes and the session seals as usual. Until `until`, the review service lists the commit as revocable, and a reviewer's signed `csctl revoke <commit>` runs the undo of §10 with `trigger: probation-revoked`. After the window the same act is an ordinary operator undo.
- **`on_expiry: revert`** (ratify or lose it). The commit's applied entries and the session's directly applied `compensable` effects revert at `until` unless a human signs `csctl ratify` first (`trigger: probation-expired`). The world stays open, so the session is not sealed, until ratification or the end of the automatic undo.
- `irreversible` effects are outside probation and are listed as such in the review document.
- A reviewer may choose a longer window or the stricter mode when signing; never a shorter window than policy sets.

## 11. Budgets

- **Leak budget** (P13). Each request that is allowed or staged on a grant with `egress: counted` is charged
  `len(path) + len(raw query) + body_len + Σ len(value)` over request headers not in the standard list (`test/vectors/budget/standard-headers.json`).
  Default `egress`: `counted` when the grant's `trust` is a label (untrusted content) and for any wildcard host; `exempt` when `trust: trusted` or `inspect: inference`.
  A request whose `METHOD authority path?query` hash is in the session **manifest** (an optional list supplied at session creation, for example derived from a lockfile) is charged 0 the first time and in full on repetition.
  When the sum would exceed `budgets.leak.bytes`, the request is denied `BUDGET_LEAK`.
  The guarantee: explicit request content reaching counted destinations in a session is at most the budget. Timing and ordering are not covered.
  The idea of capping the bytes of a request that are not predictable from trusted context is Borders & Prakash's (2008–2009), and a patent family around US 8,515,918 exists. Whether this budget may be used commercially is a human decision recorded at M14.6; the implementation agent does not assess it.
- **Write budget.** `maxResources`: distinct `(authority, path)` values written, plus distinct `(remote, ref)` staged. `maxDeletes`: DELETE requests plus ref deletions. Exceeding either → `BUDGET_WRITES`.
- Charges are recorded on each effect (`budget`), so the verifier recomputes the running totals.

## 12. Transaction propagation into MCP servers (scenario S2)

For a brokered MCP server whose policy has `calls: serialized`:

- The broker forwards at most one `tools/call` to that server pod at a time; others queue.
- While a call from caller session `C` is in flight, every write effect of the server session is classified by the **server's** grants and then handled in **`C`'s world under `C`'s autonomy**: `staged` effects are journalled in `C`'s world (`stage.entry` in `C`'s session, with `via_session` and `via_record_hash` naming the server-side effect); `compensable` effects have their prior state captured into `C`'s vault; a `review` condition holds the server's request, which holds the tool call.
- Outside a call, the server has only its own world, with `autonomy` forced to `deny` for everything but `safe` and `control`, apart from its declared startup effects (`04` §7).
- The caller's changeset therefore contains what its tools did on its behalf.

## 13. Time

### 13.1 Policy what-if
`csverify whatif --policy new.yaml [--contracts …] <bundle>…` re-evaluates recorded sessions under another policy, using records only. For each session it walks the sandbox's effects in log order, recomputing class, autonomy condition, taint labels, budgets and decision. The first effect whose decision differs from the recorded one is the **divergence point**. Everything after it is reported as `hypothetical`, because the agent would have behaved differently. Output per session: `same` or `diverges{effect_id, old, new}`; and totals by reason code. Deterministic; implemented in Go and Python.

### 13.2 Tape
With `tape.enabled`, the full request and response bodies of the selected grants are written to the world service's tape store, encrypted in 64 KiB chunks with AES-256-GCM under a per-session key, itself wrapped to the operator's X25519 recipient key (ephemeral-static X25519, HKDF-SHA-256). The format is documented in `api/tape.md` and decrypted independently by the Python reference. The tape is never part of a bundle. Its integrity is checked against the ledger: each decrypted body must hash to the digest in the corresponding effect records.

### 13.3 Replay
`csctl replay --bundle … --tape … --tape-key … --mode exact|model|intervene` starts a session of kind `replay` from the recorded `image_digest` and `start.workspace`, with the broker in replay mode for that session:

- A request is answered with the tape response of the earliest not-yet-consumed recorded effect with the same grant and `request_digest` (for bodies too large to buffer, such as git packs: same grant, method and path, and the same body digest once fully received).
- This includes requests the world service answered in the original session (git fetches and staged pushes, deferred sends). No world, stager or vault takes part in a replay.
- A session that began with a pre-populated workspace records `start.workspace.archive_sha256`; the same archive must be supplied to the replay.
- **The replay broker has no upstream dialer** for any grant, except the model endpoint in `model` and `intervene` modes (P12).
- A request with no match records `replay.divergence` and is answered with a problem document (`REPLAY_DIVERGENCE`); `--on-divergence stop|continue`.

| Mode | Model calls | Purpose |
|---|---|---|
| `exact` | From tape | Reproduce a session; must yield the same effect sequence |
| `model` | Live, to `--model-endpoint` | Effect-level regression: where does another model's behaviour first differ, in which class, and would policy have allowed it; over `--samples n` runs |
| `intervene` | Live | Causal attribution: `--replace-response <effect_id>=<file>` substitutes the tape response of one effect (for example the fetch that returned untrusted content) and reports which later effects disappear, over `--samples n` runs |

`--policy new.yaml` may be combined with any mode. The report (`replay-report.json`) lists divergences and the difference between original and replayed effect sets by class.

**A tape is stale after the first divergence.** Once the replayed agent does something the original did not, the recorded responses describe a world it is no longer in. Everything after the first divergence is labelled `beyond-divergence` and never counted. `--on-divergence continue` exists for debugging only. Replay locates first differences; it is not a release gate, and the documentation says so.

**Repetition.** Live models are not deterministic. `model` and `intervene` modes take `--samples n` (default 1 for the scripted test doubles; at least 30 is recommended for a real model) and report, for each position, in how many samples the first divergence fell there. A report always states `n`.

### 13.4 Earned autonomy
`csctl autonomy suggest <bundle>…` finds changeset **shapes** (entry types, ref globs, path prefixes, which invariants passed, taint labels present) that humans reviewed at least `--min n` times, always with decision `commit`, with no subset edits and no later undo or probation expiry. It prints `commit.auto.invariants` that would have committed exactly those automatically, with the counts behind each line. It never applies anything.

## 14. Attested outputs and the gate

At each `commit.applied` with outcome `applied`, when `attest.enabled`:

- For a `git-ref` entry: one in-toto Statement whose subjects are the new commits (at most 500, otherwise the tip only), each as `{"name": "<remote>@<ref>", "digest": {"gitCommit": "<id>"}}`. For an `http` entry: subject digest is the `request_digest`, name is the created resource URL when known.
- Predicate type `https://countersign.dev/attestation/agent-work/v1`:
  `session`, `world`, `commit_id`, `entry_sha256`, `selected_root`, `policy_digest`, `principal`, `models[]` (provider and model names observed in the session's inference traffic), `taint[]` (the entry's labels), `attribution`, `lineage`, `review{by, reviewer_key_id?, probation{until, on_expiry}?}`, `evidence{log_origin, checkpoint_size, checkpoint_root}`.
- Signed (DSSE) by the attestor key. Recorded as `attestation.issued`, placed in the bundle, and, with `attest.gitNotes: true`, attached to the commit under `refs/notes/countersign` (that notes update is itself an entry of the changeset).

**Gate.** `csverify attest <statement> --keys … [--require-review human|delegate|any] [--forbid-taint web] [--require-policy <digest>] [--subject <git commit>]` exits 0 only if the statement verifies and meets the requirements. Shipped with it: a `pre-receive` hook and a pipeline step that refuse commits by the agent's identity lacking a passing statement.

## 15. The readable boundary

**Problem documents.** Every denial, hold and pending answer carries an RFC 9457 `application/problem+json` body:

```json
{"type": "https://countersign.dev/problems/NO_GRANT", "title": "No grant covers this request", "status": 403,
 "detail": "POST https://api.github.com/repos/other/repo/issues is outside this session's grants.",
 "countersign": {"reason": "NO_GRANT", "class": null, "effect_id": "…",
                 "hint": "Allowed for api.github.com: GET, POST under /repos/acme/widgets/issues/**",
                 "boundary": "http://countersign.internal/v1/boundary"}}
```

`detail` and `hint` are produced from fixed templates per reason code. They never include credential values or content from other sessions.

**Boundary endpoint.** The host `countersign.internal`, served by the broker for the calling session, recorded as `control` effects:

| Method and path | Returns |
|---|---|
| `GET /v1/boundary` | Mode, the autonomy table, each grant's id, hosts, methods, paths, class and condition, budgets remaining, taint labels present |
| `GET /v1/world` | Pending entries (type, ref or path, annotations), commit history, world state |
| `POST /v1/commit` | Triggers a commit request; returns its ID, whether it was automatic, and its state |
| `GET /v1/commit/{id}` | State and per-entry outcomes |

Nothing here grants authority (D27). An injected instruction to "commit" still meets the invariants or a human.

## 16. Horizon (not in this plan)

Recorded so the design leaves room: data references in place of values inside the sandbox (D26); forking a running world together with a filesystem snapshot (D13); stagers for object stores and databases (D21); shared and mergeable worlds (D23); external witnessing of checkpoints and hardware attestation of the broker (D9).
