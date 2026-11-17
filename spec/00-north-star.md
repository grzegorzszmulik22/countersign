# 00. North star

## 1. Thesis

A sandbox exists so that an agent can be given more autonomy than it is trusted with. There are three ways to close that gap:

1. **Restrict** what the agent can reach. Costs usefulness.
2. **Check each action** before it happens. Costs attention, breeds approval fatigue, and requires judging consequences from one request.
3. **Make actions not count until verified, and undoable afterwards.** The agent runs at full speed. Trust is applied once, to outcomes, with full information.

Shipped agent platforms are built from 1 and 2, and increasingly hand 2 to a model reviewer. Way 3 is how people have always scaled trust in each other: drafts, pull requests, staging environments, escrow, transactions, undo. The pull request is why coding agents are deployable at all. Research runtimes (Atomix, Cordon) have begun applying way 3 **inside** agent frameworks. Nothing found applies it **below** the agent, at the network boundary, where no framework has to cooperate.

> **Today's sandbox draws its boundary around the process. Countersign draws it around consequences.**

Countersign treats an agent session as a **transaction over the outside world**:

- **Mediate.** Every effect passes one broker that holds the secrets and writes signed evidence before anything is forwarded.
- **Stage.** Writes land in a private *world*. The agent sees its own writes. Reality does not.
- **Commit.** One review of the whole change, signed once, applied only if the world is still as the agent saw it.
- **Undo.** Whatever was applied directly has a recorded way back that never overwrites someone else's change.
- **Explain.** Each effect is tied to the model's declared intent, the process that caused it, and the untrusted content that preceded it.
- **Replay.** Any session can be re-run against a new policy or a new model, with nothing reaching the real world.
- **Attest.** Every artifact that becomes real carries a verifiable statement of how it came to exist.

All of it for **unmodified agents**, decided **without any model in the loop**, and **checkable offline** by anyone holding public keys.

## 2. What is and is not new

A prior-art check (`reports/Prior art check.md`, 14 Nov 2026) found that **no mechanism here is new as an idea.** Each has a precedent in research, a product, or an adjacent field. What was not found is the same things done at the network layer, for unmodified agents, in one system with one evidence chain that a third party can verify.

So the contribution is stated as four things, and nothing more is to be claimed:

1. **Below the agent.** Staging, commit, undo, intent capture and replay all happen at the egress boundary. No framework, SDK or tool adapter takes part.
2. **One substrate.** The same signed ledger is the write-ahead log for staging, the undo log, the tape index, the input to policy what-if, and the source of output statements.
3. **Verifiable by outsiders.** Every decision procedure has two independent implementations, and a bundle checks offline with public keys.
4. **A safety net under any reviewer.** Whether a person or a model approves, a wrong approval of anything staged or compensable is recoverable, bounded and on the record.

| # | Mechanism | Closest prior art | What appears unclaimed |
|---|---|---|---|
| 1 | Reversibility classes as the basis of policy | Atomix; "Revisable by Design"; Revoco | Class derived from observed traffic and grants, not from tool adapters |
| 2 | Worlds: staged side effects, racing siblings | Cordon; Atomix; Airlock and FINOS GitProxy for git | Network-layer staging for unmodified agents; per-session git overlay |
| 3 | Changeset commit | YoloFS; GitLab issue 591235 (unbuilt); Merkle-root signatures outside agents | One passkey signature over an agent's staged external writes, with fixed invariants |
| 4 | Guarded undo | Rubrik Agent Rewind; STRATUS; GoEx | Restore only if unchanged since the agent's write |
| 5 | Probationary commit | Junos `commit confirmed`; GoEx | Not found for agents |
| 6 | Intent from the inference stream | AgentSight (observation only) | Use as the declared side for enforcement and evidence |
| 7 | Intent-bound credentials | Destination-keyed credential proxies | Scope and session state, not host, decide release |
| 8 | Process ownership | IronScope; AgentCgroup; ActPlane | Keyed on tool-call IDs from traffic; recomputable offline |
| 9 | Verified tool behaviour; transaction propagation into MCP servers | Cordon and Atomix exclude opaque tools; MCPGuard is allow/deny | Not found |
| 10 | Time: what-if, tape, replay, model regression, intervention | Policy simulators; agrepl; Docker cagent; Kitaru; AgentCheck; Docent | All four on one enforced network tape, with policy verdicts on counterfactual effects |
| 11 | Bounded leak; blast-radius budget | Borders & Prakash (2008–2009); Metere; OCELOT; AWS AgentCore | Hard per-session cap with manifest-derived requests free |
| 12 | Attested outputs | in-toto PR #603; yuma-agent-git #58; agentattest; Git AI | Taint labels; model identity observed, not self-declared |
| 13 | A boundary the agent can read | Denial reasons in auto modes; APPA; Cloudflare problem documents | Querying one's own staged set; requesting a commit |
| 14 | A differential benchmark | AgentDojo and similar, for model-level attacks | Five infrastructure levels with outside oracles |

Two things in the spec are **not** claimed at all, because they exist: approvals bound to a request digest and consumed once (draft-schrock-ep-authorization-receipts), and mining review history for automation rules (Hedwig and others). Both are cited where they are specified.

The check was one day of web, arXiv and Internet-Draft searches with no patent search. Re-check before any public claim (M14.6), and obtain a freedom-to-operate opinion on the leak budget (the patent family around US 8,515,918).

## 3. Properties

Every milestone exists to make one of these true and measured.

| ID | Property | Statement | Proven in |
|---|---|---|---|
| **P1** | Secret confinement | No real credential value is ever present inside the sandbox, in any form | M3, M4, M14 |
| **P2** | Mediated egress | Every byte leaving the sandbox's network boundary passes the broker; everything else is dropped | M4 |
| **P3** | Ledger completeness | Every request made by or on behalf of a session has exactly one effect record, durable before the request is forwarded | M2, M4, M5 |
| **P4** | Intent-bound release | A credential is injected only into a request that fits a grant and that the session's autonomy rules, intents, taint and reviews permit | M3, M6, M9 |
| **P5** | Credential pinning | A request to a credentialed destination carrying any other credential is denied | M3 |
| **P6** | Tamper evidence | Modification, reordering or deletion in a sealed session is detected offline with public keys only | M1 |
| **P7** | Reconciliation soundness | A `CLEAN` verdict implies every allowed effect is attributed to a declared intent or a standing grant | M9 |
| **P8** | Review binding | A signature authorizes exactly one changeset root (or one request), at most once, within its lifetime, and is verifiable without trusting the broker | M6 |
| **P9** | Staging isolation | A staged effect causes no write to its real destination before commit. After abort, outside state equals its state before the session | M5 |
| **P10** | Commit integrity | What is applied is exactly the selected set whose root was signed or automatically approved under recorded invariants; each entry at most once; each only if its precondition holds | M6 |
| **P11** | Undo safety | A compensation is applied only if the resource is still in the state the original effect left; otherwise a conflict is reported and nothing is written | M7 |
| **P12** | Replay isolation | In replay, no request reaches any upstream except an explicitly configured live model endpoint | M12 |
| **P13** | Bounded leak | Bytes of agent-controlled request content sent to counted destinations never exceed the session's budget | M13 |
| **P14** | Output provenance | Every artifact applied at commit has a statement, verifiable offline, binding it to session, policy, observed models, taint labels and reviewer | M13 |

## 4. Headline numbers

Targets are set **before** measurement and marked [T] throughout. An unreachable target gets a change request with data (`06` §6), never a silent edit.

### The door

| ID | Metric | Target |
|---|---|---|
| H1 | Real secrets found inside any sandbox across all benchmark runs | **0** |
| H2 | Credential-theft scenarios (class A) succeeding under Countersign | **0 of 15** |
| H3 | Network flows in packet capture with no ledger record, over ≥ 10,000 flows | **0** |
| H4 | Ledger mutants detected; agreement between the two verifiers | **100%** of ≥ 1,000; **100%** |
| H5 | Added latency per kept-alive request; added time to first byte on a stream | p50 ≤ **3 ms**, p99 ≤ **12 ms**; ≤ **5 ms** p99 |

### The transaction

| ID | Metric | Target |
|---|---|---|
| H6 | Interruptions of the agent during a benign task that has no irreversible effect | **0** |
| H7 | Benign tasks whose changeset commits with no human; the rest | ≥ **80%**; exactly **1** review each, **0** unexpected |
| H8 | Write effects in the benign suite that are `staged` or `compensable` | ≥ **90%** |
| H9 | After abort, digest of all outside state equals its digest before the session, over every benign and attack scenario | **100%** |
| H10 | Applied set equals signed set under ≥ 1,000 randomized commits with crash injection; entries applied twice | **100%**; **0** |
| H11 | Undo restores prior state when untouched by others; conflicts detected otherwise; third-party changes overwritten | **100%**; **100%**; **0** |
| H12 | In a race of three sibling worlds, exactly one commits and the others leave no trace | **100%** |

### The meaning

| ID | Metric | Target |
|---|---|---|
| H13 | Planted unattributed effects detected; benign effects wrongly flagged | **100%**; ≤ **1%** |
| H14 | Divergence scenarios (class D) stopped inline and found offline | **5 of 5**, both |
| H15 | A write caused by untrusted content, or by code the model never asked to run, becoming real without a human signature (B2, B6, B7) | **0** |
| H16 | Causal chain reconstructed for each such write, beginning at the true source | **100%** |

### Time and trust

| ID | Metric | Target |
|---|---|---|
| H17 | Policy what-if agrees with real re-execution up to the first divergence | **100%** |
| H18 | Scripted sessions replaying identically from tape; planted model divergences found; upstream contacts during replay | **100%**; **100%**; **0** |
| H19 | Bytes leaked through allowed read-only destinations (B5) | ≤ the configured **budget** |
| H20 | Committed commits carrying a valid statement; unattested or forbidden pushes refused by the gate | **100%**; **100%** |

### Adoption

| ID | Metric | Target |
|---|---|---|
| H21 | Benign task completion relative to no protection | ≥ **95%** |
| H22 | Empty cluster to a staged, reviewed, committed and verified session, following the quickstart | ≤ **10 minutes** |

### Real agents (CR-001)

| ID | Metric | Target |
|---|---|---|
| H23 | Over ≥ 90 runs of two unmodified production agents from different vendors under `cs run` in enforced mode (M14.0): real secrets found inside the sandbox; attacks becoming real; world oracle equal to its prior digest after abort; bundles verifying in both verifiers; requests observed by a fixture with no ledger record | **0**; **0**; **100%**; **100%**; **0** |

H23 holds whatever the agent does: it is a property of the boundary, not of the agent's behaviour. Completion, interruptions and reviews on real agents are reported beside it and never claimed.

## 5. The bar

Asked at every milestone exit review (`06` §3).

**Would the CTO of a frontier lab see this as ahead of what they run?** What they are known to run (`reports/Prior art check.md` §3): process isolation; default-deny egress through a proxy that keeps credentials outside the sandbox; a **model reviewer** that approves actions in place of the user (by the labs' own figures it catches about 89% of dangerous commands, where people catch 13.6% and approve 93–97% of prompts); file-level checkpoints; and the pull request as the only staging mechanism. Phase 1 of this plan is therefore table stakes. Against that:

- *A safety net under their reviewer.* A miss by any reviewer, human or model, on anything staged or compensable is recoverable and on the record. → H9, H11
- *Autonomy that does not depend on a classifier being right.* The agent is never interrupted for anything reversible. → H6, H7
- *An undo that reaches outside the machine.* → H11
- *One review of everything, with the reasons attached.* → M6 review document, H16
- *Racing several attempts with no duplicated side effects.* → H12
- *A way to ask "what would the next model have done on last week's work?" with no risk.* → H18
- *Proof for customers that a hosted agent did only what was allowed.* → P6, P10, P14
- *Policy rollouts tested against history.* → H17
- *Drop-in, fail-closed, bounded overhead.* → H5, H22
- *One command around an unmodified production agent, rootless, and the guarantees hold for agents from two vendors speaking two model API formats; the agent never holds its own model credential.* → H23, M2.7

**Would a researcher at a frontier lab respect it?**

- *Properties stated precisely under an explicit threat model, including what is not defended.* → §3, `01`
- *No model inside the system.* Models appear only as the subject of replay experiments, or as an outside delegated reviewer whose signature is bounded to reversible changes on probation and never trusted as correct.
- *A benchmark with baselines where each row isolates one mechanism, and oracles outside the system under test.* → `07`
- *Security bought with measured utility and measured human burden.* → H7, H21
- *Two independent implementations of every verifier and decision procedure.* → M1, M5, M6, M9
- *Causality claimed only where it is measured by intervention.* → M12.5
- *Residuals reported with numbers.* → H19, `01` §5

**What would not impress either**, and is not the goal: a signed log of what the agent says it did; an allow-list proxy with a dashboard; a policy language; anything that needs the agent rewritten; detection by a second model.

## 6. Deployment scenarios

- **S1. Agent sandbox.** A coding or task agent runs in a pod. Model calls, tool traffic and everything else go through the broker. The session has one world.
- **S2. MCP server sandbox.** A third-party MCP server runs in its own brokered pod. Calls into it are the declared side; its egress is the observed side; and its side effects join the **caller's** world (`05` §12).

## 7. Non-negotiable design constraints

1. Countersign contains no model: none in any allow/deny decision, verdict or gated measurement. A delegated reviewer (`05` §8) is an outside party, like a human reviewer, and policy bounds what its signature can authorize.
2. No change to the agent or the MCP server is required for any property in §3.
3. Evidence is written before effects are released.
4. The default answer is deny; an unclassified write is `irreversible`.
5. Verification needs public keys and the bundle, nothing else.
6. Every gated check is hermetic.
7. A commit applies what was signed, or nothing it cannot account for.
8. Undo never guesses: without a matching recorded state it reports a conflict.
