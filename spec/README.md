# Countersign: specification set (version 2, transactional)

*Working name. Renaming is one `sed` (see `02-architecture.md` §9).*

> **Agents run with zero prompts. Nothing becomes real until one signed commit. Everything real can be undone. Any run can be replayed against a new model or policy without touching the world.**

This folder is the complete brief for an implementation agent working in a loop. Read it in this order:

| # | File | What it settles |
|---|---|---|
| 1 | `00-north-star.md` | The thesis, the fourteen properties, the headline numbers, and the bar the project is judged against |
| 2 | `01-threat-model.md` | Who the attacker is, what is trusted, residual risks, and the **global denied list** |
| 3 | `02-architecture.md` | Components, data flows, technology choices, repository layout |
| 4 | `03-evidence-format.md` | Record types, signing, chains, the Merkle log, bundles, the verifier algorithm |
| 5 | `04-policy-and-reconciliation.md` | Policy schema, request matching, credentials, intents, reconciliation, process lineage, taint |
| 6 | `05-transactions.md` | Reversibility classes, autonomy, worlds, staging, changesets, signed commit, undo, budgets, replay, attested outputs, the readable boundary |
| 7 | `06-agent-loop.md` | **How to work**: the loop, definition of done, sabotage checks, stuck protocol, change requests |
| 8 | `07-benchmark.md` | `effectbench`: scenarios, defence levels, metrics, the expected results table |
| 9 | `milestones/M0…M14` | Small chunks, each with build instructions, checks, sabotage, measurements and denied items |
| 10 | `PROGRESS.md` | The tracker the loop reads and updates |

## Rules that override everything else

1. **A check is never edited to make it pass.** Thresholds, test vectors and expected verdicts change only through `CHANGE_REQUESTS/` and a human decision (`06-agent-loop.md` §6).
2. **"Denied" sections are binding.** They list attractive improvements that are out of scope. Building them is a failure, not a bonus.
3. **Every chunk has sabotage checks.** A test suite that stays green when the implementation is deliberately broken does not count as a passing suite.
4. **Numbers are recorded raw.** Every measurement goes to `evidence/` with the command that produced it.

## The five phases

| Phase | Milestones | What exists at the end |
|---|---|---|
| **1. The door** | M0–M4 | Every byte leaving a sandbox passes one broker that holds the secrets and writes signed evidence first. Installed by one Helm chart |
| **2. The transaction** | M5–M7 | Writes are staged in a private world. One signed commit makes them real. Committed effects can be undone. Messages can be deferred. Commits can be probationary |
| **3. The meaning** | M8–M11 | Each effect is tied to the model's declared intent, to the process that caused it, and to the untrusted content that preceded it. These annotate the changeset and gate automatic commit |
| **4. Time and trust** | M12–M13 | Policies are tested against history. Sessions replay without touching the world. Leaks have a stated upper bound. Every committed artifact carries a verifiable statement of where it came from |
| **5. The argument** | M14 | `effectbench`: 71 scenarios against five defence levels, reproducible offline |

## Milestone map

| ID | Name | Produces | Depends on |
|---|---|---|---|
| M0 | Foundation | Repo, pinned toolchain, hermetic kind cluster, fixture services, scripted agent | none |
| M1 | Evidence core | Record format, signing, Merkle log, two independent verifiers, mutation suite | M0 |
| M2 | Broker data plane | Intercepting egress proxy with write-ahead evidence | M1 |
| M3 | Policy and credential binding | Grants, placeholders, pinning, response scrubbing | M2 |
| M4 | Kubernetes integration | Controller, webhook, network lockdown, Helm chart, completeness vs packet capture | M3 |
| M5 | Worlds and staging | Reversibility classes, autonomy policy, the world service, the git stager, abort and rewind | M4 |
| M6 | Commit and review | Changesets, invariants, passkey-signed commit, apply with preconditions, barriers, world groups, the readable boundary | M5 |
| M7 | Undo and deferral | Prior-state capture, compensation, undo sessions, deferred sends with provisional IDs, probation, the delegated reviewer | M6 |
| M8 | Intent capture | Declared intents read from inference and MCP traffic, with no agent changes | M4 |
| M9 | Reconciliation | Declared-vs-observed engine, MCP effect contracts, transaction propagation into MCP servers, policy learning | M7, M8 |
| M10 | Taint and lineage | Label-based taint, causal chain from untrusted source to effect | M9 |
| M11 | Process observer | Second independent emitter (Tetragon), bypass evidence, process ownership of effects | M9 |
| M12 | Time | Policy what-if, encrypted tape, deterministic replay, model regression, causal intervention, earned autonomy | M10, M11 |
| M13 | Budgets and provenance | Leak and blast-radius budgets, attested outputs, the admission gate | M7, M10 |
| M14 | Benchmark and release | `effectbench` results across five levels, quickstart, release readiness | all |

**Where the step forward is.** Phase 1 reproduces, in the open, what the major agent platforms already run. Phase 3 alone would be a better guard. The leap is phase 2 together with phase 4, done **below the agent**: the sandbox boundary moves from the process to the consequences, with no framework taking part. Do not stop at M4, and do not ship phase 3 without phase 2.

**What may be claimed.** No single mechanism here is new as an idea (`00` §2; `reports/Prior art check.md`). The contribution is the combination at the network layer for unmodified agents, on one verifiable evidence chain. Cordon (arXiv 2606.17573) and Atomix (ICLR 2026) are the closest work and must be read before M5.
