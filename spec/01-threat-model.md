# 01. Threat model, limits and the global denied list

## 1. Actors and trust

| Actor | Trusted? | Notes |
|---|---|---|
| **Model output** | No | May be steered by prompt injection. What it declares is an *intent*, never an *authorization* |
| **Agent harness and all code in the sandbox** | No | May be compromised or running attacker-supplied code, with root inside the sandbox |
| **Content fetched from the network** | No | Pages, issue comments, package contents, tool results |
| **Third-party MCP server** (S2) | No | May be malicious from the start or change behaviour later |
| **Broker, controller, ledger, world service, observer, review service** | Yes | The trusted computing base, outside the sandbox pod, in its own namespace |
| **Kubernetes control plane, node kernel, CNI** | Yes | Escapes are out of scope (§3) |
| **Cluster operator** | Trusted for enforcement, **not** for rewriting history | Can turn the system off. Must not be able to alter a sealed session undetected (P6), nor apply at commit something other than what was signed without it showing (P10) |
| **Reviewer** | Trusted for the one changeset they sign | Their passkey never reaches Countersign |
| **Delegated reviewer** | **No.** Its signature is one input that policy may accept | A separate service, possibly a model. Assumed fallible and open to injection through what it reads. May authorize only reversible changes, on probation, that passed the hard invariants and carry no forbidden label (`05` §8) |
| **Tape key holder** | Trusted with recorded content | Only they can read an encrypted tape |
| **Upstream services** | Trusted to be themselves once TLS verifies | |
| **Other writers to the same upstream resources** | Honest but concurrent | People and other agents change the world between stage and commit, and between commit and undo |

## 2. Attacker goals in scope

| ID | Goal | Example |
|---|---|---|
| G1 | Obtain a real credential | Read a token from the environment and send it anywhere |
| G2 | Use a credential outside its granted scope | Push to another repository on the same host |
| G3 | Move data to a destination the policy does not allow | POST a file to an attacker host; DNS tunnelling; raw TCP |
| G4 | Move data through a credentialed destination under the attacker's own account | Upload to the model provider's file endpoint with the attacker's key |
| G5 | Act without leaving evidence | Bypass the proxy; act between records; crash the ledger |
| G6 | Alter or remove evidence afterwards | Edit, reorder, delete or truncate records |
| G7 | Make the harness or an MCP server do what the model never asked, unnoticed | Extra tool calls; a server that phones home |
| G8 | Turn untrusted content into a write on an allowed destination | An injected instruction posts secrets to an allowed tracker |
| G9 | Reuse or stretch a human signature | Replay it; obtain it for one set and apply another |
| G10 | Make something real before review | Find a write path that is not staged; trigger an automatic commit that should not qualify |
| G11 | Corrupt the staging area between review and apply | Replace a staged commit after the reviewer signed |
| G12 | Hide a harmful entry inside a large or misleading changeset | Bury a secret-bearing commit among many; make the review show less than what is applied |
| G13 | Abuse undo or abort to destroy other people's work | Trigger a compensation that overwrites a later human edit |
| G14 | Escape replay | Cause a real effect while a session is being replayed |
| G15 | Exceed a budget through an uncounted path | Leak through request parts that are not charged |
| G16 | Obtain a valid attestation for work that should not have one | A statement for a commit that was not reviewed as recorded |
| G17 | Steer a delegated reviewer into signing | Content in a staged change instructs the reviewing model to approve it |

## 3. Out of scope

Each appears on the public limits page (M14.4).

1. **Kernel, hypervisor or container-runtime escape.** Countersign assumes the sandbox boundary holds and is agnostic to how it is made.
2. **A malicious cluster administrator at run time.** They can disable enforcement. They cannot forge a past sealed session.
3. **Compromise of a signing key.** Detectable only through external witnessing, which is specified but not implemented here.
4. **Semantic correctness of what a human approves.** If the reviewer signs a harmful changeset that was shown to them truthfully, it is applied. Countersign's job is that the review shows everything, flags what is suspicious, and that exactly the signed set is applied.
5. **Covert channels through timing and ordering** of permitted requests. Explicit content is bounded by the leak budget (P13); timing is limited only by rate limits and is reported.
6. **Effects with no way back.** Some writes are `irreversible` (a payment, a delivered message). They need a signature each time. Countersign does not pretend otherwise.
7. **True atomicity across independent systems.** Commit is ordered application with preconditions, and compensation on failure. Two systems can be left in a reported, partial state.
8. **Everything a staged write would have triggered.** A staged push starts no pipeline and notifies nobody until commit. An agent that needs those results meets a commit barrier.
9. **State inside the sandbox.** Rewinding files and processes is the sandbox platform's or the agent's job. Countersign rewinds the world.
10. **Side channels inside the node; denial of service.** A sandbox can make itself useless but must not make the broker unsafe.
11. **Endpoints that pin certificates or need client certificates.** Reachable only through an explicit `passthrough` grant, recorded as opaque, never credentialed, never staged, and `irreversible` unless the grant declares another class, which every review then flags.

## 4. Trust boundary

```
 ┌──────────── sandbox pod (untrusted) ─────────────┐
 │ agent harness · tools · arbitrary code           │
 │ env: placeholders, proxy address, session CA     │
 └───────────────────────┬──────────────────────────┘
   NetworkPolicy: egress only to broker; no DNS
                         │ explicit HTTP(S) proxy
 ┌───────────────────────▼──── countersign-system (trusted) ───────────────┐
 │ broker ── policy ── credentials ── ledger                               │
 │   │ staged writes                         ▲ records                     │
 │   ▼                                       │                             │
 │ world service: shadow git remotes · outbox · prior-state vault · tape   │
 │   │ apply at commit / compensate at undo  (always back through broker)  │
 │ controller · webhook · review service · observer ◄─ Tetragon            │
 └───────────────────────┬─────────────────────────────────────────────────┘
                         ▼ upstream: model API, code host, registries, APIs, MCP servers
```

Every request to an upstream, whether it originates in the sandbox or in the world service, passes the same broker path: matched to a grant, credentialed, recorded first.

## 5. Residual risks to report, not hide

| Risk | Where measured |
|---|---|
| Timing and ordering channels through allowed destinations | M13, M14: reported rate under default limits |
| Window attribution is coarse for broad tools | M9: share of effects `EXACT` vs `WINDOW`, per tool class |
| Session-level taint is coarse | M10, M14: reviews per benign task, by label |
| Process ownership needs the harness to run the declared command as one argument; absent inside guest kernels | M11: asserted for the wrapping case; runtime classes listed |
| Compensation coverage depends on the API | M7, M14: share of writes per class; list of `irreversible` effects in the benign suite |
| Partial commits | M6, M14: rate under injected conflicts and failures; every one reported |
| Staging hides effects from systems the agent may be waiting on | M6: barrier counts per benign task |
| Passthrough tunnels are opaque | M14: count per scenario |
| A replay tape is stale after the first divergence | M12: effects beyond it are labelled and never counted |
| A delegated reviewer can be wrong or injected | M7.7, M14: bounded to reversible entries on probation; revocations reported |
| Inference inspection depends on provider wire formats | M8: conformance on recorded transcripts; explicit unparsed fail-safe |
| A reviewer can sign without reading | Not measurable here. Published figures say people approve 93–97% of per-action prompts and catch 13.6% of dangerous commands, so no property rests on careful reading. Mitigated by invariants, flags placed above the entries, probation and undo; stated plainly |

## 6. Global denied list

Attractive, and **not** to be built during this plan. A milestone may add its own. If one seems necessary, file a change request.

| # | Denied | Why |
|---|---|---|
| D1 | Any model, embedding or classifier inside Countersign: in a decision, verdict or gated metric | Decisions must be deterministic and reproducible. A model may appear only as the *subject* of an M12 replay experiment, or as an outside delegated reviewer bounded by `05` §8. No gated check uses a real model for either |
| D2 | Our own MCP gateway, agent framework, SDK or wrapper the agent must import | No agent changes |
| D3 | A policy language with expressions, or a general policy engine | Policy is a small declarative schema; commit invariants are a fixed vocabulary (`05` §7) |
| D4 | A token or identity system; an identity provider | Identity is asserted by the platform and recorded |
| D5 | Transparent interception | Explicit proxy plus deny-all network policy suffices |
| D6 | Request or response bodies in the **ledger** | The ledger holds digests and bounded redacted previews. Content lives only in the world service's encrypted stores (staged entries, prior states, opt-in tape) |
| D7 | A web console or dashboards | Only the single review page of M6.7 and CLI output |
| D8 | Multi-cluster, multi-region, high-availability broker or world service | One of each, with documented restart behaviour |
| D9 | Cloud key management, hardware security modules, hardware enclaves | Keys are Kubernetes Secrets behind one interface |
| D10 | Object storage back ends, long-term retention, databases | Local persistent volumes, append-only files |
| D11 | Non-HTTP protocols: SSH, raw TCP, SMTP, QUIC | Denied at the network and recorded |
| D12 | eBPF programs written by this project; agents inside guest kernels | Use Tetragon as shipped |
| D13 | Filesystem or process snapshots, forking a running sandbox | The platform's job. Worlds fork at session start only |
| D14 | Content inspection for data-loss prevention | Only the credential-shape detector of `04` §4.4 |
| D15 | Compliance report generators | Documentation later |
| D16 | A new on-the-wire evidence standard; SCITT/COSE export | Use DSSE, in-toto statements and C2SP checkpoints. Export is future work |
| D17 | Windows or macOS nodes; non-Kubernetes deployment | kind on Linux (the ARM64 build host of `06` §11), plus the local test mode |
| D18 | Performance work beyond the stated targets | Stop when the target is met |
| D19 | Model providers beyond the two in M8 | |
| D20 | Weakening, skipping, or marking as flaky any check | `06` |
| D21 | Stagers beyond git and the deferred-send outbox | Object stores, databases and file shares are future work |
| D22 | Staging generic REST writes by emulating the remote service | A write with no stager is `compensable` or `irreversible`, never faked |
| D23 | Shared worlds across sessions; merging two worlds; nested transactions | One world per session; sibling worlds race, they do not merge |
| D24 | Automatic conflict resolution at commit or undo (rebasing, three-way merging, retrying with new state) | Conflicts are reported. The agent or a person resolves them |
| D25 | Cost or spend accounting | Budgets cover leaked bytes and resources written only |
| D26 | Tokenizing data values so the sandbox holds only references | Recorded as the next horizon (`05` §16); not in this plan |
| D27 | Granting authority through the boundary endpoint | The agent may read its boundary and request a commit. It cannot widen anything |
