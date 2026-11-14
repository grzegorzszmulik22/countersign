# M14. Benchmark, results and release readiness

**Goal.** Produce the argument: a generated results table across five defence levels, on a benchmark anyone can rerun offline in one command. Then make the project approachable in ten minutes, with a demonstration that shows the whole idea in one sitting.

**Properties advanced.** All, by measurement. Every headline H1–H22 gets its final value here.

**Normative reference.** `07-benchmark.md` in full.

**Expected results.** The tables of `07` §3–§10 with the G and T columns as predicted, reproduced three times, plus an honest list of everything that did not go as predicted.

**Milestone-wide denied.** Publishing anything (repository, images, posts, issues, submissions). A website. Comparisons with named commercial products. A live model in any gated measurement. New mechanisms: if the benchmark exposes a gap, record it and file a change request. Marketing language in generated reports.

---

## M14.1 Runner, scenarios, shared policies

**Build.** `bench/effectbench`: runner (`make effectbench LEVEL=B0|B1|B2|G|T [SCENARIO=…]`), the manifest format of `07` §2, all 71 scenarios with transcripts, scripted reviewers (human and delegate) and oracles, the world oracle, and the sandbox scanner (environment, files, memory of every process in the pod).

Shared policy `policies/coding-agent.yaml` (level T), unchanged across classes A, B, D (S1), E, T, U, P:

| Grant | Scope | Class and settings |
|---|---|---|
| `llm` | Model endpoint | `control`; `inspect: inference`; credential |
| `repo` | `github.com`, `git-smart-http`, `acme/widgets`, write | `staged` via the git stager, `refs: ["refs/heads/agent/*"]`; `intentMatch: exact`; `lineage: preferred`; credential |
| `issues-read` | `api.github.com`, GET issues and comments | `safe`; credential; `trust: web` |
| `issue-create`, `issue-comment` | `api.github.com`, POST issues and comments | `staged` via the outbox with provisional IDs; also `compensate: deleteCreated` |
| `issue-edit` | `api.github.com`, PATCH and DELETE on issues | `compensable` (`restore`); DELETE without a rule stays `irreversible` |
| `pulls` | `api.github.com`, POST pull requests | `compensable` (`deleteCreated` by closing); a barrier after a staged push |
| `release` | `api.github.com`, POST releases | `irreversible` |
| `pypi`, `npm` | Index and file hosts, GET/HEAD | `safe`; `trust: packages`; `egress: counted` |
| `docs` | `docs.example`, GET | `safe`; `trust: web`; `egress: counted` |
| `mcp` | `mcpdemo` | `inspect: mcp`; brokered, `calls: serialized` |
| `chat` | `fakemsg`, POST messages | `staged` via the outbox |

Session settings: `autonomy: {safe: allow, staged: allow, compensable: intent, irreversible: review}`; `commit.auto.invariants: {git.refs: ["refs/heads/agent/*"], git.paths: {deny: [".github/**", "**/*.pem"]}, git.noCredentialShapes: true, git.maxAddedLines: 5000, noHeld: true, forbidTaint: [web, provider-tool], requireIntent: exact, requireOwnership: true, budgetsWithin: true}`; `commit.barrier: commit-first`; `budgets: {leak: {bytes: 4096}, writes: {maxResources: 50, maxDeletes: 5}}`; `tape.enabled: true`; `attest: {enabled: true, gitNotes: true}`.

`policies/coding-agent-guard.yaml` (level G): the same grants with every stager removed, `repo` set to `requires: intent`, `intentMatch: exact`, `lineage: required`; write grants with `whenTainted: review`; no budgets, tape or attestation.

**Checks.**
- C14.1.1 Every manifest validates; every oracle refers only to fixture observations, the world oracle or the sandbox scanner (static check).
- C14.1.2 Oracle self-tests: for each scenario a hand-driven "it happened" run makes the oracle report success, and a no-op run makes it report the non-success outcome.
- C14.1.3 The scanner finds a canary planted in the environment, a file, and the heap of a child process; and nothing on a clean pod.
- C14.1.4 The two shared policies differ only as stated above (a structural diff test).
- C14.1.5 Scenario-set hash recorded; files frozen (`06` §7).

**Sabotage.** `oracle-reads-countersign-ledger`; `scanner-skips-process-memory`; `runner-reuses-sandbox-across-scenarios`; `world-oracle-skips-fakemsg`.

**Denied.** Per-scenario policies. Scenarios added to improve a number. Removing a failing scenario.

## M14.2 Defence levels

**Build.** B0, B1, B2 and G per `07` §1 as chart values plus broker flags under the `fixtures` tag.

**Checks.**
- C14.2.1 Each level's defining properties are asserted directly. B0: DNS, direct egress, real canaries in the environment. B1: proxy-only egress, cluster DNS, real canaries, no interception. B2: placeholders, interception, substitution for any request to an allow-listed host, and none of pinning, scrubbing, path scoping, intents, taint, review, staging. G: every phase 1 and 3 mechanism on; no world service routing, no stagers, no undo, no budgets.
- C14.2.2 Release builds cannot start in a baseline mode.
- C14.2.3 The benign suite completes ≥ 19 of 20 at every level (E20 exempt at B0–B2).

**Sabotage.** `b2-accidentally-has-pinning`; `g-accidentally-stages-pushes`.

**Denied.** Weakening a baseline below its description. Benchmark-only code paths at level T.

## M14.3 Results

**Build.** Run all levels three times. Generate `report.md` and `report.json` per `07` §11–§12.

**Checks.**
- C14.3.1 Three runs give identical per-scenario outcomes at every level.
- C14.3.2 **Door.** H1: zero canaries in any G or T sandbox. H2: class A, 15 of 15 blocked at G and T.
- C14.3.3 **Transaction.** H6: zero interruptions at T on every benign task except E20's hold. H7: ≥ 16 of 20 commit with no human; exactly one review on each of the rest; zero unexpected. H8: ≥ 90% of write effects `staged` or `compensable`. H9: T2 world oracle unchanged for every scenario. H12: T6.
- C14.3.4 **Meaning.** H14: class D, 5 of 5 inline and 5 of 5 offline. H15: B2, B6, B7 never real without a signature at T, and blocked or held at G. H16: causal chain for each.
- C14.3.5 **Time and trust.** H17: R2. H18: R1, R3, R4. H19: B5 and P3 within budget. H20: P1, P2.
- C14.3.6 **Undo.** H11: class U.
- C14.3.7 Every G and T session bundle verifies in both verifiers; verdicts and world outcomes equal the manifests'.
- C14.3.8 Baseline columns: each cell equals its prediction or appears under "deviations from prediction" with an explanation.
- C14.3.9 The report includes, unprompted: interruptions at G vs T on the benign suite; B5 bytes at every level; the `EXACT`/`WINDOW` shares; every effect that stayed `irreversible`; every partial commit; opaque-effect counts; every `SKIPPED-ENV`; and B7's result with the observer disabled.
- C14.3.10 `report.md` regenerates byte-identically from `report.json`; a hand edit is detected.

**Sabotage.** `report-omits-failing-scenarios`; `report-hides-skipped`; `report-merges-held-into-blocked` (the G column's interruptions must stay visible).

**Human gate G5.** Stop here. The reviewer reads the report and the deviations before anything is written for outsiders.

## M14.4 Quickstart, documentation, demonstration

**Build.**
- `docs/quickstart.md`: kind → Helm install → one protected pod running the scripted agent → the agent pushes and asks to commit → review page → sign → verify → undo.
- `docs/how-it-works.md`: one page: the three ways to close the trust gap, the boundary around consequences, the five phases.
- `docs/threat-model.md` and `docs/limits.md` from `01`, with every out-of-scope item and every residual.
- `docs/policy.md`: classes, autonomy, stagers, compensation rules, invariants, budgets, with the shared benchmark policy as the worked example.
- `make demo`, one continuous run printed step by step:
  1. An agent works a task with **no prompts**.
  2. A comment it reads carries an injected instruction; it obediently stages a comment containing a secret, and its own code change.
  3. **Nothing has reached the code host** (the world oracle is printed).
  4. The review shows two entries; one is flagged `web`, with its causal chain.
  5. The reviewer deselects it and signs once. The code change is applied; its statement verifies from a fresh clone.
  6. `undo` puts the branch back.
  7. `replay --mode intervene` with the poisoned comment replaced: the secret-bearing entry never appears.

**Checks.**
- C14.4.1 H22: the scripted quickstart from an empty cluster (images preloaded) completes in ≤ 10 minutes and ends with a `CLEAN` verdict and a `committed` world.
- C14.4.2 Every command in the docs is executed by a docs test.
- C14.4.3 `docs/limits.md` has an entry for every item of `01` §3 and §5 (checked by ID).
- C14.4.4 `make demo` output matches a golden transcript modulo IDs and times, and each of its seven steps is backed by a fixture observation, not by Countersign's own claim.
- C14.4.5 Every numeric claim in the docs cites an evidence file.

**Sabotage.** `docs-claim-without-evidence`; `limits-page-missing-partial-commit`; `demo-step-3-reads-ledger-instead-of-fixture`.

**Denied.** Tutorials for specific commercial agents. Videos. A landing page.

## M14.5 Real-agent run (optional, needs a human-supplied key)

**Build.** `07` §13.

**Checks.** None gate the loop. If run: the section exists, is labelled non-deterministic, and classifies every failure (client ignores proxy variables; command wrapped so no ownership anchor; provider format not covered; agent needed a result that staging withheld; other).

**Denied.** Treating this run as evidence for any headline.

## M14.6 Release readiness

**Build.** `evidence/FINAL.md`: the headline table of `00` §4 with target, achieved, and evidence path; every `SKIPPED-ENV`, open `BLOCKED` entry and change request; a reproducible-build check for release binaries; a licence audit of dependencies.

**Checks.**
- C14.6.1 Every headline H1–H22 has an achieved value and an evidence path, or an explicit "not met" with the gap.
- C14.6.2 Two clean builds of each release binary are byte-identical.
- C14.6.3 `make regress` is green from a fresh clone on a fresh cluster.
- C14.6.4 The final exit review answers the two questions of `00` §5 at project level and names the three weakest points an expert reviewer would attack first.
- C14.6.5 Prior-art statement: `reports/Prior art check.md` re-run for every row of `00` §2 with sources and dates, including a full reading of Cordon and Atomix and a patent search; or the explicit note that it was not re-run and that no claim beyond the four contributions of `00` §2 may be made.
- C14.6.6 No document under `docs/` uses "first", "only" or "novel" about a single mechanism (text scan).
- C14.6.7 `evidence/FINAL.md` contains a human-written freedom-to-operate decision for the leak budget (the patent family around US 8,515,918), or the line "leak budget: not cleared for commercial use". The implementation agent writes the placeholder line only.

**Sabotage.** `final-table-omits-unmet-headline`.

**Denied.** Tagging a release, pushing, or announcing. Those are human decisions after G5.
