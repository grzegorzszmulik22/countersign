# M11. Process observer

**Goal.** A second, independent emitter. Tetragon reports which process ran and which process opened each connection; `csobserver` signs those facts into the same ledger. This gives three things the broker alone cannot: evidence of bypass **attempts**, cross-checking of the broker's own account, and process-lineage ownership of effects.

**Properties advanced.** P2 and P3 strengthened by an independent witness; P7 strengthened by lineage (`04` §10); H15.

**Normative references.** `04` §10, §11; `03` §4 (`effect.exec`, `effect.connect`, `observer.gap`); `02` §6 (observer failure behaviour).

**Expected results.**
- Every escape attempt that the network policy silently dropped in M4 now leaves a signed record.
- A broker that omitted an effect would be contradicted by the observer's records.
- A process spawned for one intent cannot act under another (scenario B7).

**Measurements [T].**

| ID | Metric | Target |
|---|---|---|
| MM11.1 | Escape-matrix rows (M4.3) blocked at the network that now have an `effect.connect … blocked` record | 100% of the TCP/UDP rows; ICMP and raw-socket rows reported as covered or not |
| MM11.2 | Broker effects with a matching observer connect event, and the reverse, over ≥ 10,000 flows with no observer gap | 100% both ways |
| MM11.3 | Time from the kernel event to the durable observer record | p99 ≤ 100 ms |
| MM11.4 | Added p99 latency on new connections for grants with `lineage: required` | ≤ 60 ms; kept-alive requests unaffected |
| MM11.5 | Lineage recomputation, Go vs Python, on random traces with process trees | 100% of ≥ 5,000 |
| MM11.6 | Benign flows of M9 completing with `lineage: required` on write grants | 10 of 10 with the scripted agent |
| MM11.7 | CPU cost of the observer on a node running the perf workload | ≤ 5% of one core; reported |

**Milestone-wide denied.** Writing eBPF programs (D12). Forking or patching Tetragon. Observation inside gVisor or microVM guests. File-access tracing, syscall-level policies, seccomp profile generation. Killing processes as an enforcement action (enforcement stays at the broker and the network policy). Process-memory inspection. Recording environment variables or full command lines.

---

## M11.1 Observer on the ledger service

**Build.** Add the emitter role `observer` to the ledger service of M5.1, with its own client certificate. The observer buffers up to 10,000 events while the ledger is unreachable and writes `observer.gap` on reconnect if any were dropped.

**Checks.**
- C11.1.1 The observer's credentials cannot append a record with emitter role `broker`, `controller` or `world`.
- C11.1.2 MM2.1 and MM2.2 still hold with four emitters appending (re-measure).
- C11.1.3 Ledger unavailable for 5 s under load: no event lost and no gap. Unavailable long enough to overflow the buffer: exactly one gap covering the loss.
- C11.1.4 Crash-consistency (C1.4.1) with four concurrent emitters.

**Sabotage.** `observer-may-append-any-role`; `observer-drops-silently-on-overflow`.

**Denied.** A second ledger for observer events.

## M11.2 Tetragon deployment and tracing policy

**Build.** Pin a Tetragon release (verify chart, tracing-policy schema and event format upstream, `06` §8). A tracing policy scoped to pods carrying the Countersign label: process exec and exit; TCP connect with source and destination address and port; UDP send; raw-socket creation. Node preflight (BTF present) and a clear `SKIPPED-ENV` path.

**Checks.**
- C11.2.1 In a protected pod: `curl` through the proxy, a direct TCP attempt, a UDP send, a raw-socket attempt, and a three-level process tree each produce the expected Tetragon events (asserted on Tetragon's own export, before any Countersign code).
- C11.2.2 The source port in the connect event equals the port the broker sees for that connection (1,000 connections).
- C11.2.3 Pods without the label produce no events from this policy.
- C11.2.4 Parent links are complete: every exec event's parent is present or is the container's first process.

**Sabotage.** `policy-not-scoped-to-label` (C11.2.3 fails); `policy-omits-udp`.

**Denied.** See milestone list.

## M11.3 `csobserver`

**Build.** DaemonSet reading Tetragon's event stream on its node. Maps pod to session (from `Session` objects); emits `effect.exec` (with `argv_sha256[]`, never the arguments themselves), `effect.connect` (`outcome: to-broker` when the destination is the broker, else `blocked`), and `observer.gap` whenever events may have been lost (Tetragon restart, buffer overflow, own restart). Liveness lease per node renewed every second; the broker treats a lease older than 5 s as "observer unhealthy" for sessions on that node.

**Checks.**
- C11.3.1 Records for the C11.2.1 activity are in the session's ledger, signed by the observer key, chain intact; the bundle verifies.
- C11.3.2 MM11.3.
- C11.3.3 Kill the observer for 10 s during activity: an `observer.gap` covering the outage is written; the verifier reports `W_OBSERVER_GAP`; no cross-emitter error is raised for effects inside the gap.
- C11.3.4 With `observer: required` in the policy and the observer down: new connections for that session are denied `OBSERVER_REQUIRED` within 5 s; they resume when it returns.
- C11.3.5 The ledger contains no argument text: scan for marker strings passed as process arguments.
- C11.3.6 An event for a pod with no session (unlabelled) is dropped, not recorded.

**Sabotage.** `observer-no-gap-on-restart`; `observer-records-argv-text`; `broker-ignores-observer-lease`.

**Denied.** Enriching events with Kubernetes metadata beyond the session mapping. Exporting to other sinks.

## M11.4 Bypass evidence and cross-emitter consistency

**Build.** Verifier and reference: `04` §11. Flip C4.3.2: network-blocked escape attempts must now have records.

**Checks.**
- C11.4.1 MM11.1 over the escape matrix.
- C11.4.2 MM11.2.
- C11.4.3 A test bundle from which one broker effect has been removed **and the broker chain re-signed with the broker key** (simulating a dishonest broker) → `F_CROSS_EMITTER: connect-without-broker-record`. This is the case hash chains alone cannot catch.
- C11.4.4 A test bundle with a fabricated broker effect that has no connect event → `F_CROSS_EMITTER: broker-effect-without-connect`.
- C11.4.5 A session containing a blocked connect has verdict at best `CLEAN_WITH_DENIALS`.
- C11.4.6 Go and Python agree on all of the above.

**Sabotage.** `cross-check-skipped-when-any-gap-exists` (must only excuse effects inside the gap); `blocked-connect-not-a-denial`.

**Denied.** Alerting pipelines. Automatic session termination on bypass attempts (recorded and visible in the verdict; killing sessions is a policy feature for later).

## M11.5 Process lineage and ownership

**Build.** `04` §10 in the Python reference first, then Go, offline and inline. Inline: on a new connection for a grant whose `lineage` is not `off`, the broker waits up to 50 ms for the connect event of that source port, resolves the owner, and narrows candidate intents. The broker records `attribution.lineage` and `attribution.owner`. `intent.declared.anchor_sha256` is filled for `exec`-class intents.

Trace corpus additions (`test/vectors/reconcile/lineage/`, at least 30): effect from a descendant of the anchor; from the anchor itself; from a sibling tree; from a process whose anchor's intent has closed; from an unowned (harness) process with an `http` intent open; with only an `exec` intent open under `preferred` and under `required`; two intents with identical command strings (first exec anchors the first intent, second the second); an attacker process that runs the same command string **before** the declaration (must not anchor); deep trees; a missing connect event; an observer gap.

**Checks.**
- C11.5.1 Corpus: reference and Go both equal the expected results; MM11.5.
- C11.5.2 **Scenario B7 in miniature.** An install script leaves a background process; later the scripted agent's own `git push` intent opens; the background process pushes to the granted repository. With `lineage: required`: denied `NO_INTENT`, `fakehub` records only the agent's own push. With `lineage: off`: the rogue push is allowed. Both outcomes are asserted, so the mechanism's contribution is isolated.
- C11.5.3 MM11.6 and MM11.4.
- C11.5.4 Connect event arrives late (delay injected at 40 ms and at 80 ms): at 40 ms the request proceeds with lineage resolved; at 80 ms `required` denies `OBSERVER_REQUIRED` and `preferred` proceeds with `lineage: unknown`.
- C11.5.5 Offline recomputation matches inline for every session in the suite; tampering with `attribution.owner` in a re-signed bundle → `F_LINEAGE_MISMATCH`.
- C11.5.6 A harness that wraps the command (the scripted agent run with `--wrap-commands`) yields no anchor: under `preferred` flows complete with `lineage: unowned`; under `required` exec-driven writes are denied. The limitation is asserted, not hidden, and stated in the docs.

- C11.5.7 **Ownership on changesets.** Entry annotations carry `lineage` and `owner`; the `requireOwnership` invariant becomes valid. Scenario B7 under the transactional policy: the background process's push is staged without interrupting the agent, the squashed entry is not `owned`, `requireOwnership` fails, nothing reaches `fakehub`, and the review flags the entry. With the observer disabled the entry's lineage is `unknown` and the invariant also fails (fail-closed).

**Sabotage.** `anchor-may-precede-declaration`; `owned-by-closed-intent-falls-back-to-window`; `lineage-required-proceeds-on-missing-event`.

**Denied.** Substring or fuzzy matching of commands to processes. Storing command text. Guessing the owner from timing.

---

## Exit

Exit review must include: the MM11.1 table per escape row; the B7 pair of outcomes; the measured cost MM11.4 and MM11.7; and a plain statement of which runtime classes have no lineage.
