# CR-001: Build the demonstrable slice first; prove it on unmodified agents from two vendors

**Status:** ACCEPTED 2026-11-16 by the supervisor, under the authority the human gave ("you own the code and have the full authority over it"; "draft the plan, make the changes as you go"). Applied to `README.md`, `00-north-star.md`, `07-benchmark.md`, `milestones/M2`, `M5`, `M9`, `M14`, `PROGRESS.md` and `FROZEN.sha256`.
**Raised by:** supervisor, 2026-11-16, after M0, M3.1, M3.6 and M9.1 were merged and M1.1–M1.4 reached review.

## The problem

The plan builds M0 to M14 in order. The bar (`00` §5) is judged on what a frontier-lab CTO can see, and the first thing they can see is `make demo` (M14.4), which arrives last and needs a Kubernetes cluster. Until then every merged chunk is infrastructure, and Phase 1 is by our own account "table stakes". Labs are shipping sandboxes, checkpoints and reviewers into their own agents now; arriving months later with a complete plan is worth less than arriving soon with the one thing they do not have.

The transactional chunks depend on Kubernetes far less than the milestone map says. Of M5 to M9, five lines assume a cluster (C5.2.5, C5.3.5, C5.6.1, the M9.3 end-to-end flows, and M5's `Depends on M4`). The broker (M2) and the credential store (M3.2) already have a local mode.

## The change

1. **Slice 1, "The transaction, demonstrated", is built before everything else.** It is the chunk list in `README.md` §"Build order". It ends with M14.0: the M14.4 demo on one machine, a benchmark subset at levels B0, B2 and T1, and real-agent runs.
2. **A local runner (new M2.7):** `cs run -- <agent command>` runs any agent inside a rootless user, mount and network namespace whose only way out is the broker, and whose view of the runner's data directory (credentials, keys, ledger) is an empty mount. No root, no containers, no cluster. Where unprivileged namespaces are not available the runner refuses, unless `--cooperative` is given, and then every record and verdict says so.
3. **Real agents become evidence for safety invariants (new H23), not only a non-deterministic appendix.** Whatever an agent does, some properties must hold for every run: no real secret inside the sandbox, no attack becoming real, the world unchanged after abort, every bundle verifying, every request a fixture saw having a ledger record. These are measured on two unmodified production agents from different vendors speaking different model API formats (Claude Code, Anthropic Messages; opencode with an OpenAI-compatible provider, Chat Completions). Completion, interruptions and reviews stay reported, never claimed.
4. **The agent never holds its own model credential.** Under `cs run`, the agent's model API credential is a placeholder; the broker substitutes the real one on the provider's host only (the M3.2 mechanism, applied to the agent's own key or subscription token).
5. **Milestone dependencies:** M5 depends on M2.7 and M3.2 (M4 adds cluster mode later); M8 depends on M2 (it inspects broker traffic and needs no cluster). Kubernetes (M4) moves behind the slice, unchanged.

## What the slice claims, and why it should clear the bar

Against what labs are known to run (`00` §5: isolation, an egress proxy that keeps credentials out, a model reviewer, file checkpoints, the pull request):

- **One command around any agent**, rootless: `cs run -- claude …`. No framework, no SDK, no agent change.
- **Nothing an agent does outside the machine is real until one signed commit**, shown on real agents, with the world oracle proving it after abort.
- **A prompt injection that makes the agent post a secret becomes a flagged entry in a review**, not an incident, and the review carries the reason (declared-vs-observed, read from the agent's own model traffic).
- **Undo that reaches outside the machine**, refusing to overwrite a third party's change.
- **Two vendors, two API formats, the same guarantees**: the proof that the boundary is below the agent.
- **Every claim checkable offline** by two independent verifiers.

## Effect on properties and numbers

Nothing is weakened. H1 to H22 keep their targets and their milestones; the slice only reorders work. New: H23, M2.7, M14.0. The five restated lines (C5.2.5, C5.3.5, C5.6.1, M9.3's end-to-end flows, M14.5's denied item) keep their property and name local mode as an equal environment. Cooperative mode can never count toward H1 or H23.

## Risks recorded

- Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor by default; a host may need the `kernel.apparmor_restrict_unprivileged_userns` setting or a profile. The runner probes and reports; it never weakens the boundary to work around it.
- Real-agent runs spend the human's model usage. The supervisor asks the human before running them.
- A production agent may pin certificates or ignore proxy variables. In enforced mode that shows up as a failed connection, not a leak, and is reported in the M14.5 vocabulary.

## Alternatives considered

- Keep the order and make M14.4 earlier by faking components: a demo backed by stand-ins fails C14.4.4 and would not survive a researcher's first question.
- Build the demo on kind: every viewer would need a cluster first, and agent-vpc cannot run one.
- Use containers for the local sandbox: needs a runtime and usually root; the namespace runner needs neither and is enforced.
