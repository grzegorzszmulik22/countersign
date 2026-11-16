# M5. Worlds and staging

**Goal.** Give every session a private world. Classify every write by how reversible it is. Make git pushes land in a shadow remote that the agent can read back from, while the real remote receives nothing. Prove that aborting leaves the outside world exactly as it was.

**Properties advanced.** P9 (staging isolation). P3 extended to requests the system makes on a session's behalf.

**Normative references.** `05` §1–§4; `03` §4.1–§4.3, §4.5; `02` §1–§3, §6.

**Read first.** Cordon (arXiv 2606.17573) and Atomix (ICLR 2026) are the closest prior work on staged agent effects. Save a one-page comparison to `evidence/M5/prior-work.md` before M5.3: what each stages, where it intercepts, and anything in their failure handling that this design has missed. A missed case is a change request.

**Expected results.**
- An unmodified `git` client clones, commits, pushes and re-fetches as usual. `fakehub` records zero writes.
- Abort, and every fixture's state digest equals its digest before the session.
- Anything the classifier cannot place is `irreversible`.

**Measurements [T].**

| ID | Metric | Target |
|---|---|---|
| MM5.1 | Classification and autonomy decision table; Go vs Python on random inputs | 100% of ≥ 250 rows; 100% of 10,000 |
| MM5.2 | Write requests observed by `fakehub` while pushes are staged | 0 |
| MM5.3 | Outside-state digest after abort vs before the session, over all M5 flows | equal in 100% |
| MM5.4 | Overlay served vs a reference model, on generated ref histories | 100% of 2,000 |
| MM5.5 | Wall-clock through the stager vs direct: clone of a 200 MiB repository (cold mirror, warm mirror); push of a 50 MiB pack | ≤ 1.6×, ≤ 1.2×; ≤ 1.3× |
| MM5.6 | Broker latency with the ledger as a service (re-measure MM2.1, MM2.2) | still within H5 |
| MM5.7 | Plaintext marker strings found on the world service's volume | 0 |

**Milestone-wide denied.** Reimplementing any part of the git protocol or pack format. Git LFS, push options, signed pushes. Stagers other than git (D21). Emulating the code host's REST API for staged branches (D22). Automatic rebasing or merging (D24). Sharing a shadow repository between worlds. Forking a running world (D13). Garbage-collection tuning. A user interface.

---

## M5.1 Ledger as a service

**Build.** `cmd/csledger`: the M1 ledger behind mutual-TLS gRPC. A client certificate is bound to one emitter role and may append only envelopes signed by a key of that role whose `emitter` field has that role. The broker and controller become clients; `world` is added as a role. Group commit and write-ahead semantics unchanged.

**Checks.**
- C5.1.1 Every M1 ledger check passes against the service.
- C5.1.2 A client with the `world` role cannot append a record whose emitter role is `broker` or `controller` (rejected and logged).
- C5.1.3 MM5.6.
- C5.1.4 Ledger unavailable → the broker fails closed (C2.4.3 again).
- C5.1.5 Crash-consistency (C1.4.1) with three concurrent emitters.

**Sabotage.** `ledger-accepts-any-role`; `broker-continues-when-ledger-down`.

**Denied.** Replication. A read API beyond bundle export. Per-tenant ledgers.

## M5.2 Reversibility classes and autonomy

**Build.** `internal/classify` and `ref/python/refclassify` implementing `05` §1 and §2 (conditions `allow`, `review`, `deny`; `intent` is rejected at validation until M9). Policy schema additions: `autonomy`, grant `class`, `requires`, `stager`, `tools`. The broker records `class` and `decision.requires` on every effect. Before M6 exists, a `review` condition is answered with a denial `REVIEW_REQUIRED`.

Decision table `test/vectors/policy/classes.yaml` (≥ 250 rows, expected column **derived by reading `05` §1–§2**): every rule of §1 in order, including the cases where an earlier rule shadows a later one; every method; git read vs write; WebSocket; passthrough; explicit `class`; a declared `safe` on POST (flagged); MCP calls to brokered and unbrokered servers with and without a `tools` entry; each class under each autonomy condition; the grant's `requires` stricter and (invalid) looser than autonomy.

**Checks.**
- C5.2.1 MM5.1.
- C5.2.2 A request matching no rule is `irreversible`. A grant with an unknown stager or a `staged` class without a stager fails validation.
- C5.2.3 A grant `requires` looser than `autonomy[class]` has no effect (strictest wins), asserted on 20 rows.
- C5.2.4 `declared_safe` is recorded on the effect and survives into the session's records.
- C5.2.5 All merged M2–M4 suites (in the slice: M2.1–M2.4, M2.7, M3.1, M3.2, M3.6) pass with the default autonomy table.

**Sabotage.** `unclassified-defaults-to-safe`; `grant-requires-overrides-autonomy-downward`; `post-treated-as-safe`.

**Denied.** Inferring reversibility from response codes, host reputation or API documentation. Per-user autonomy.

## M5.3 World service and lifecycle

**Build.** `cmd/csworld`: world objects per `05` §3 (journal, states, `onSessionEnd`, `reviewTtl`); encrypted at-rest stores under a per-world data key; emitter role `world`; the proxy-client identity of `02` §3 (world token over mutual TLS, `actor: world`). Controller: `sandbox.terminated`, and `session.seal` only after `world.closed`. Broker: routes requests of class `staged` to the world service; denies all writes with `WORLD_UNAVAILABLE` when it is down.

**Checks.**
- C5.3.1 Lifecycle golden bundles: empty world (`empty`); world aborted at session end (`abort`); world held then expired (`expired`); each verifies and reports the right `world` outcome.
- C5.3.2 No `session.seal` precedes `world.closed` (ordering asserted; sabotage below).
- C5.3.3 World service down: `safe` and `control` requests succeed; a staged push, a POST and a DELETE are each denied `WORLD_UNAVAILABLE`; nothing reaches the fixtures.
- C5.3.4 A request by the world service to an upstream is recorded as `effect.http{actor: world}` **before** it is sent (write-ahead assertion as C2.4.1) and is matched against the session's grants: a world request outside the grants is denied like any other.
- C5.3.5 The world token cannot be used from a sandbox (a pod in cluster mode; the `cs run` namespace in local mode) (wrong certificate, wrong source) → `NO_SESSION`.
- C5.3.6 MM5.7: planted marker strings in staged content and file names do not appear in plaintext anywhere on the volume.
- C5.3.7 World service restart: journal and state are rebuilt from the ledger plus its stores; pending entries intact.

**Sabotage.** `seal-before-world-closed`; `world-requests-bypass-broker`; `writes-continue-when-world-down`; `stores-unencrypted`.

**Denied.** A database. Cross-world indexes. World state in Kubernetes objects beyond a status summary.

## M5.4 Git stager: read path

**Build.** Mirrors per (remote, credential) and shadow repositories per (world, remote), as `05` §4. Sync through the broker (`purpose: sync`) with a 5-second reuse window. Overlay served by `git http-backend`. Verify upstream that the pinned git version supports what is needed (`06` §8).

**Checks.**
- C5.4.1 Real `git clone`, `fetch`, `ls-remote`, shallow clone and partial fetch through the stager return the same refs and objects as directly from `fakehub`.
- C5.4.2 Each agent fetch triggers at most one upstream sync within 5 seconds, recorded as a world effect; with `fakehub` unreachable the fetch fails and nothing stale is served.
- C5.4.3 A session whose credential cannot read the repository gets a failed fetch even when another session's mirror already holds the objects.
- C5.4.4 Upstream ref moves between two agent fetches (third party pushes to `fakehub`): the second fetch sees the new value.
- C5.4.5 Two worlds on the same remote cannot see each other's staged objects: world B requesting an object ID that exists only in world A's shadow is refused.
- C5.4.6 MM5.5 (clone).

**Sabotage.** `serve-stale-on-sync-failure`; `mirror-shared-across-credentials`; `shadow-alternates-point-to-other-world`.

**Denied.** See milestone list.

## M5.5 Git stager: write path

**Build.** `receive-pack` into the shadow; pre-receive enforcement of `refs`, `allowDelete`, `allowNonFastForward`, `maxPackBytes`; one `stage.entry` per accepted ref update with the entry object of `05` §6 (`base` taken from the last sync); squashing with `supersedes`; `stage.entry` durable before the client receives the result; read-your-writes in the overlay.

**Checks.**
- C5.5.1 MM5.2 across pushes of new branches, updates, multiple refs in one push, tags inside the allowed pattern.
- C5.5.2 After a staged push, `git ls-remote` and `git fetch` through the stager show the staged value; the same commands directly against `fakehub` (from the test harness) show the old value.
- C5.5.3 Push to a ref outside `refs`, a deletion, a non-fast-forward, an oversized pack: each rejected with the normal git remote-rejection output naming `REF_NOT_ALLOWED`; no entry recorded; the shadow unchanged.
- C5.5.4 Three pushes to one ref yield one pending entry whose `base` is the original upstream value and whose `new` is the last value; earlier entries are superseded.
- C5.5.5 MM5.4: a generator produces random sequences of upstream pushes, agent pushes and agent fetches; the overlay returned at each step equals a 50-line Python reference model.
- C5.5.6 Ordering: `stage.entry` acknowledged before the push result reaches the client (instrumented).
- C5.5.7 The entry's `new` is the object ID actually present in the shadow, and `commits` equals the number of commits reachable from `new` and not from `base`.
- C5.5.8 MM5.5 (push).

**Sabotage.** `receive-pack-forwarded-to-upstream`; `entry-base-is-staged-value`; `ack-push-before-entry-durable`; `ref-rules-not-enforced`.

**Denied.** Server-side hooks supplied by the agent. Rewriting commits. Scanning content at push time (facts are computed at review, M6).

## M5.6 Abort, rewind, and the world-unchanged proof

**Build.** `csctl world abort|rewind|show`. Abort deletes the shadow and closes the world `aborted`. Rewind per `05` §3 (the undo part is wired in M7). The harness's **world oracle**: every fixture's `GET /__state` returns a deterministic digest of all its externally visible state; the oracle compares digests before a session and after.

**Checks.**
- C5.6.1 MM5.3 over: a benign clone-commit-push flow; ten pushes across four refs; the attack miniatures that involve pushes (A2, B3), under `cs run` in enforced mode (and in cluster mode once M4 is merged).
- C5.6.2 Oracle self-test: one direct write to `fakehub` changes its digest; a read does not.
- C5.6.3 Rewind to the second of five entries: entries three to five are dropped, the overlay shows the second entry's state, `world.rewound` lists the dropped entries, and a later commit (M6) would apply only what remains.
- C5.6.4 After abort the shadow directory is gone and the world's data key is destroyed (the encrypted stores can no longer be read).
- C5.6.5 A write arriving after the world is closed → `WORLD_CLOSED`.

**Sabotage.** `abort-leaves-shadow`; `rewind-keeps-later-refs`; `oracle-ignores-refs` (C5.6.2 must fail).

**Denied.** Rewinding files or processes inside the sandbox (D13). Partial abort by entry type.

---

## Exit

Exit review. No human gate. It must show MM5.2 and MM5.3 with the fixture observations, and answer: which write paths in the benign flows are **not** staged, and why.
