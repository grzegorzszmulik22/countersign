# 05. How the implementation agent works

This is the operating protocol. It is binding in the same way as the specs.

## 1. The loop

Repeat until every chunk in `PROGRESS.md` is `DONE` or the stop conditions in §5 apply.

1. **Read state.** `spec/PROGRESS.md`, `spec/BLOCKED.md`, and the last entry under `evidence/`.
2. **Select** the lowest-numbered chunk that is `TODO` or `IN_PROGRESS` and whose dependencies are `DONE`. Never work on two chunks at once.
3. **Re-read** that chunk's section, every spec section it cites, and the global denied list (`01` §6).
4. **Plan** in at most 15 lines, saved as `evidence/<chunk>/<UTC timestamp>/plan.md`: files to touch, the checks you expect to satisfy, the first test you will write.
5. **Write the checks first.** Tests and the `make check-<chunk>` target come before the implementation. Run them and confirm they fail for the right reason.
6. **Implement** the smallest change that can pass.
7. **Run** `make check-<chunk>`. Output is captured to the evidence folder automatically (M0.5).
8. **Run** `make sabotage-<chunk>` (§4).
9. **Run** `make regress` (all checks of all `DONE` chunks).
10. **Record** the outcome in `PROGRESS.md`. If all three passed twice in a row from `make clean`, mark `DONE` and commit (§9). Otherwise go to 6, or to §5 if stuck.

## 2. Definition of done for a chunk

All of the following, with evidence files to show for each:

- [ ] Every check listed for the chunk passes through `make check-<chunk>`, twice consecutively, starting from `make clean`.
- [ ] Every sabotage listed for the chunk turns at least one check red through `make sabotage-<chunk>`.
- [ ] `make regress` is green.
- [ ] `make lint` is green (formatting, vet, static analysis, licence headers).
- [ ] Every measurement listed for the chunk is recorded in `evidence/<chunk>/…/measurements.json` with raw samples, and meets its target.
- [ ] Nothing on the chunk's denied list or the global denied list was built.
- [ ] No check, vector, threshold or expected verdict was modified (the frozen-file hashes of §7 still match).
- [ ] Public behaviour added by the chunk is documented in `docs/` in at most one page.

## 3. Definition of done for a milestone

- All its chunks are `DONE`.
- The milestone's **exit review** is written to `evidence/<milestone>/exit-review.md`. It answers, in order: (1) which properties from `00` §3 this milestone advanced and the measured evidence; (2) each headline number touched, target vs achieved; (3) the two questions of `00` §5 answered honestly in three sentences each, naming the weakest point; (4) residual risks found that the spec did not anticipate.
- Where the milestone table says **human gate**, stop and wait (§10).

## 4. Sabotage checks

A test suite proves something only if it fails when the thing is broken. Each chunk lists sabotages: small, named, deliberate defects.

- Each sabotage is a patch file `test/sabotage/<chunk>/<name>.patch` against the implementation (never against tests).
- `make sabotage-<chunk>` applies each patch to a scratch copy, runs `make check-<chunk>`, and requires a **non-zero** exit. It then reports which check caught it.
- A sabotage that leaves the suite green means the suite is inadequate: strengthen the tests, never delete the sabotage.
- You may add sabotages. You may not remove or weaken the listed ones.

## 5. When stuck

A check is *stuck* when three consecutive iterations, each trying a materially different approach, fail on it.

1. Stop changing code for that check.
2. Append an entry to `spec/BLOCKED.md`: chunk, check ID, what was tried (three approaches, one line each), the exact failing output, your best hypothesis, and two or three options with their costs.
3. If another chunk is selectable under §1 step 2 without depending on the blocked one, continue there. Otherwise **stop and report**.

Stop immediately, without three attempts, when:
- passing would require changing a check, vector, threshold or denied item (file a change request instead, §6);
- a check needs something the environment cannot provide (a kernel feature, a runtime class). Record `SKIPPED-ENV` with the probe output; a skipped check is **not** a pass and stays listed in the milestone exit review;
- a spec statement contradicts another spec statement or an upstream fact you verified (§8).

## 6. Change requests

The spec can be wrong. It is changed deliberately, never by drift.

- File `spec/CHANGE_REQUESTS/NNN-<slug>.md` with: what you want changed, why (with data: measurements, upstream documentation, a failing proof), the alternatives, and the effect on each property and headline number.
- Mark the affected chunk `BLOCKED-CR-NNN` and move on under §5.
- Only a human marks a change request `ACCEPTED`. Until then the spec stands.
- Targets marked [T] were set before measurement. A request to relax one must include at least five measurement runs and an explanation of where the time or error goes.

## 7. Frozen files

After the gate named for each, these are hash-pinned in `spec/FROZEN.sha256`, and `make regress` fails if any hash changes:

| Files | Frozen at |
|---|---|
| `test/vectors/evidence/**` (golden bundles, mutation seeds) | M1 gate |
| `test/vectors/policy/**` (matching decision tables) | M3 gate |
| `test/vectors/transcripts/**` (recorded model and MCP traffic) | M8 gate |
| `test/vectors/reconcile/**` (trace corpus with expected verdicts) | M9 gate |
| `test/vectors/policy/classes.yaml`, `test/vectors/commit/**` (class table, invariants, review-abuse corpus) | G3 |
| `test/vectors/budget/**`, `test/vectors/attest/**` | M13 exit |
| `bench/effectbench/scenarios/**` (scenario manifests and oracles) | M14.1 completion |
| `spec/0*.md`, `spec/milestones/*.md` | From the start; changed only through §6 |

Adding new vectors is always allowed. Changing or deleting frozen ones is not.

## 8. Facts to verify upstream

The specs name external projects and formats from memory. Before relying on any of them, check the upstream source at the version you pin and save the excerpt to `evidence/<chunk>/…/upstream/`:

- DSSE v1 pre-authentication encoding; in-toto Statement v1 field names.
- C2SP `signed-note`, `tlog-checkpoint`, `tlog-witness` formats; RFC 6962 proof algorithms.
- Anthropic Messages API: streaming event names and tool-use block shapes.
- OpenAI Responses and Chat Completions: tool-call item shapes and streaming events.
- Model Context Protocol: current revision, Streamable HTTP transport, `tools/call`, `tools/list`, tool annotations.
- `kubernetes-sigs/agent-sandbox`: API group, kinds, versions.
- Tetragon: tracing-policy schema, event export format, enforcement actions.
- WebAuthn Level 2/3: assertion verification procedure.
- The CNI used by the test cluster actually enforcing `NetworkPolicy`.
- The pinned `git` version: `http-backend` behaviour, `--force-with-lease` semantics, the receive-pack command-line format, git notes.
- RFC 8785 (JSON canonicalization) test vectors; RFC 9457 (problem details).
- in-toto attestation subject conventions for git commits, and the state of in-toto attestation PR #603.
- draft-schrock-ep-authorization-receipts at its current revision (M6.3).
- Cordon (arXiv 2606.17573) and Atomix (ICLR 2026), read in full before M5.3.

If upstream differs from the spec in a way that matters, that is a contradiction: §5, then §6.

## 9. Commits

- One commit per chunk reaching `DONE`: `M<n>.<k>: <chunk title>`, body listing check IDs passed and the evidence folder.
- Work-in-progress commits are allowed on the working branch with prefix `wip:`.
- Never commit generated secrets other than fixture canaries under `test/`.
- Do not push to any remote, publish images, open issues or pull requests, or post anywhere. Those are human actions.

## 10. Human gates

| Gate | After | What the human decides |
|---|---|---|
| G1 | M1 | Freeze the evidence format and vectors |
| G2L | M2.7, M3.2 (CR-001) | Review the local runner's boundary (namespaces, relay, hidden data directory, placeholders, the agent's own model credential) before the transaction work builds on it |
| G2 | M4 | Review the trusted computing base and the lockdown before the transaction work builds on it |
| G3 | M7 | Review transaction semantics: staging isolation, commit integrity, undo safety. Freeze the class, commit and abuse vectors |
| G4 | M9 | Review reconciliation semantics against the reference model; freeze the trace corpus |
| G34 | Slice step 7 (CR-001) | The G3 and G4 questions, limited to the slice's chunks; freeze the slice's class, commit, abuse and trace vectors; approve M14.0's real-agent runs |
| G5 | M14.3 | Review the results table before anything is written for the public |

At a gate: write the exit review, set the milestone to `AWAITING-GATE` in `PROGRESS.md`, and stop.

## 11. Environment rules

- **Two build hosts**, both ARM64 (aarch64), reached over Tailscale:

  | Host | OS | Size | Account | May run |
  |---|---|---|---|---|
  | `oci-free-a1` | Ubuntu 24.04 | 2 cores, 11 GB | `opc`: no sudo, in the `docker` group | Everything, including Docker and the kind cluster |
  | `agent-vpc` | Oracle Linux 9 | 4 cores, 22 GB | `csbuild`: no sudo, no Docker, no Podman | **Cluster-free work only**: libraries, CLIs, reference implementations, unit and differential tests |

- `agent-vpc` runs another application and holds its data. On that host: never use `sudo`, `su` or any container tool; never read outside `/home/csbuild` except system paths needed to build; never open, connect to or probe the local services (PostgreSQL, the Python services, monitoring); and **stop if free space on `/` falls below 30 GB** (`df -h /`), writing the reading into `spec/BLOCKED.md`.
- Every cluster-free chunk's `make check-<chunk>` must pass on `agent-vpc` without Docker. A check that needs Docker belongs to a chunk run on `oci-free-a1`.
- **Toolchain on both hosts** is installed by `make tools` into `./.tools/` without root. The system Python on `agent-vpc` is 3.9, so the pinned Python 3.12+ must also be installed in user space (for example a standalone Python build fetched by `make tools`), never from the system package manager.
- **ARM64 consequences.** Every pinned tool binary and every container image pinned by digest must have a `linux/arm64` build; choose versions that do and record the check in evidence. Performance numbers describe the host they ran on: record `make sysinfo` with each, and treat a [T] target missed only for lack of cores as a change request with data.
- **Shared hosts.** At most one kind cluster exists, on `oci-free-a1`. Other processes on either host belong to other applications: do not stop, inspect or reconfigure them.
- Anything needing root is out of reach. If a check needs it, stop and write the exact command into `spec/BLOCKED.md` for the human.
- The kind cluster is named `countersign`. Do not touch any other cluster, container, image or volume on the machine. Never run a prune or delete command that is not scoped to that name.
- Tool versions are pinned in `tools/versions.env` at M0.1 and installed by `make tools` into `./.tools/`. Do not rely on globally installed versions.
- Checks are hermetic. Container images are pulled once by `make images`, pinned by digest, and loaded into kind. After that, checks must pass with the network disabled; M0.2 verifies this.
- No real credentials are used anywhere. Every secret in tests is a canary generated by the fixture tooling, matching the pattern `CANARY_[A-Z0-9]{32}`.

## 12. Measurement rules

- Every measurement states: command, machine description (`make sysinfo`), number of runs (minimum 5), all raw samples, median, and coefficient of variation. A result with variation above 10% is rerun on a quiet machine or reported as unstable.
- Latency is measured as a paired difference (through the broker minus direct) against the same upstream in the same run.
- Never report the best run. Never drop a run without stating why.
- Security metrics are counts over enumerated scenarios, not samples. Report the numerator, the denominator and the list of failing IDs.

## 13. `PROGRESS.md` row format

`| chunk | status | attempts | last evidence folder | note |` with status one of `TODO`, `IN_PROGRESS`, `DONE`, `BLOCKED`, `BLOCKED-CR-NNN`, `SKIPPED-ENV`, `AWAITING-GATE`.

## 14. Parallel sessions

Several sessions may run at once, on either host. The human supervisor (or an agent acting for them) assigns each session a **lane**: a branch name and an explicit list of chunks.

- Work only on your lane's chunks, in order, on your lane's branch (`lane/<name>`). Never commit to `main`, never merge, never rebase onto another lane.
- Record progress in `spec/progress/<lane>.md` using the row format of §13. **Do not edit `spec/PROGRESS.md`**; the supervisor updates it when a lane is merged.
- If a chunk needs something from a chunk outside your lane that is not yet on `main`, stop that chunk and record `BLOCKED` with the missing dependency.
- Push your branch to `origin` after every `DONE` chunk and at least once an hour.
- The supervisor merges a lane chunk into `main` only after re-running its checks and sabotages on `main`.
