# M12. Time

**Goal.** Make the past usable. Test a policy change against recorded sessions before rolling it out. Re-run a session with nothing reaching the world. Ask what a different model would have done. Measure, by intervention, whether a piece of untrusted content caused an effect. Turn review history into proposals for safe automation.

**Properties advanced.** P12 (replay isolation). Headlines H17, H18.

**Normative references.** `05` §13; `03` §4.1 (`session.open` kind `replay`, `tape`), §4.4 (`replay.divergence`).

**Expected results.**
- "This policy change would have altered N decisions across last week's sessions", computed from ledgers alone, and true.
- A scripted session replays to the identical effect sequence with every upstream unplugged.
- A changed model's first different action is located exactly.
- Removing the injected content removes the injected effect, measured.

**Measurements [T].**

| ID | Metric | Target |
|---|---|---|
| MM12.1 | What-if vs actual re-execution under the new policy, up to the divergence point | 100% of ≥ 300 (session, policy) pairs (H17) |
| MM12.2 | Go vs Python what-if output | identical for all of them |
| MM12.3 | Decrypted tape bodies matching ledger digests; plaintext markers on the tape volume | 100%; 0 |
| MM12.4 | Throughput cost of tape capture on the M2 perf workload | ≤ 20% |
| MM12.5 | Exact replays whose effect sequence equals the original; upstream contacts during replay | 100% of scripted sessions; 0 (H18) |
| MM12.6 | Planted model divergences located at the correct effect | 100% of ≥ 50 (H18) |
| MM12.7 | Intervention verdicts on constructed sessions (caused / not caused) | 100% of ≥ 20 |
| MM12.8 | Changesets that a human rejected, edited or later undid which the suggested automation would commit | 0 |

**Milestone-wide denied.** A model, classifier or heuristic judging anything: models appear only as the subject being replayed (D1). Normalizing or fuzzy-matching requests to reduce divergence. Replaying against real upstreams. Tape in the bundle or the ledger. Capturing tape for sessions whose policy does not enable it. Automatic application of suggested autonomy. A time-travel debugger or UI. Replay of the sandbox's filesystem or process state (D13). Sampling or statistics on what-if beyond exact counts.

---

## M12.1 Policy what-if

**Build.** `internal/whatif`, `csverify whatif`, and `ref/python/refwhatif`, per `05` §13.1. Inputs: bundles, a new policy, optional contracts. It reuses the classification, autonomy, taint, budget, intent and lineage recomputation of V16 with the new policy, walking sandbox effects in log order, and stops asserting at the first changed decision.

Agreement harness: 30 recorded scripted sessions (benign and attack flows from M5–M11) × 10 policy variants (a grant removed, a path narrowed, an autonomy level raised and lowered, a label added to a grant, a budget halved, `intentMatch` changed, a stager removed, an invariant added, a `deny` grant added, a no-op reformatting). For each pair the scenario is **actually re-run** under the new policy, and decisions are compared up to the divergence point.

**Checks.**
- C12.1.1 MM12.1 and MM12.2.
- C12.1.2 The no-op variant yields `same` for every session.
- C12.1.3 Effects after the divergence point are labelled `hypothetical` and excluded from totals; a test asserts no count includes them.
- C12.1.4 What-if needs only bundles and policy files: it runs in an empty container with no network.
- C12.1.5 A variant that changes only commit invariants reports changes in **auto-eligibility** of recorded changesets, recomputed from the bundled review documents.
- C12.1.6 Bundles from `learn`-mode sessions are accepted as input; `replay` sessions are refused.

**Sabotage.** `whatif-counts-hypothetical-effects`; `whatif-reuses-recorded-taint` (must recompute labels under the new policy); `whatif-ignores-budget-changes`.

**Denied.** Predicting agent behaviour after the divergence. Aggregations other than counts by reason code and by grant.

## M12.2 Tape

**Build.** `internal/tape`: capture of full request and response bodies for the grants selected by `tape.grants`, streamed to the world service's tape store, AES-256-GCM in 64 KiB chunks under a per-session key wrapped to the operator's X25519 recipient key (`05` §13.2). Format in `api/tape.md`. A Python decrypter in the reference tree. `tape.onFailure`. The recipient private key never enters the cluster.

**Checks.**
- C12.2.1 MM12.3: every decrypted body's SHA-256 equals the digest in its effect or result record, including streamed and deferred bodies and git packs.
- C12.2.2 The Python decrypter, written from `api/tape.md`, reads tapes written by Go.
- C12.2.3 Without the recipient private key nothing is readable: the cluster's Secrets contain no key that decrypts a tape (test attempts with every Secret in the namespace).
- C12.2.4 Flipping one byte of a tape chunk is detected at decryption.
- C12.2.5 Tape disabled → the tape store stays empty; `tape.grants` limited to one grant → only that grant's bodies exist.
- C12.2.6 Tape store failure: with `deny`, requests on taped grants are denied; with `continue-unrecorded`, a gap is recorded and replay later reports the session as not replayable from that point.
- C12.2.7 Real credential values never reach the tape: request bodies and headers are taped as the sandbox sent them (placeholders), and responses after scrubbing (canary scan of decrypted tapes).
- C12.2.8 MM12.4.

**Sabotage.** `tape-key-also-stored-in-cluster`; `tape-records-post-injection-headers`; `tape-without-authentication-tag-check`.

**Denied.** Compression. Deduplication across sessions. Selective field redaction. Any reader inside the cluster.

## M12.3 Replay: exact mode and isolation

**Build.** `internal/replay`, `csctl replay --mode exact`, and the broker's replay mode per `05` §13.3: answer by grant and request digest, earliest unconsumed first; `replay.divergence`; `--on-divergence`; sessions of kind `replay`. **The replay configuration constructs the broker without an upstream dialer**; the only dialer that can exist is the model endpoint in the other two modes.

**Checks.**
- C12.3.1 MM12.5: every scripted session recorded with tape replays to an identical ordered list of (grant, method, authority, path, request digest, class, decision).
- C12.3.2 During replay every fixture and `sink` observe zero requests; additionally the replay runs with the fixtures **scaled to zero** and still succeeds.
- C12.3.3 Structural isolation: a unit test proves that in replay mode a request for a non-model grant cannot obtain a dialer (the type has none), and a static check forbids importing the upstream dialer from the replay package.
- C12.3.4 A session with staged pushes and deferred sends replays with no world service running.
- C12.3.5 A deliberately changed scripted agent (one extra request) produces exactly one `replay.divergence` at the right position, answered with a `REPLAY_DIVERGENCE` problem document; with `stop` the replay ends there.
- C12.3.6 Replay sessions are marked in their bundle; `csverify` reports them as kind `replay` and never as `CLEAN` evidence of real activity; what-if refuses them.
- C12.3.7 Combining `--policy new.yaml` with exact replay yields decisions equal to M12.1's output for that pair.

**Sabotage.** `replay-falls-back-to-upstream-on-miss`; `replay-matches-by-path-only`; `replay-session-not-marked`.

**Denied.** See milestone list.

## M12.4 Model mode

**Build.** `--mode model --model-endpoint URL`: inference grants go live to the given endpoint (with a credential supplied to the replay, never the production one); everything else from tape. Report: the first divergent effect, its class, the decision the policy would make, and the set difference of effects by class between original and replay.

Test double: `mockllm --variant` serves the same transcripts with planted changes: an extra tool call, a missing one, a different argument, a reordered pair, a different target host, a write where there was a read.

**Checks.**
- C12.4.1 MM12.6 over ≥ 50 planted variants across ten sessions: the reported divergence position and class equal the plant.
- C12.4.2 A variant identical to the original yields no divergence.
- C12.4.3 The only upstream contacted is the model endpoint (fixtures scaled to zero as in C12.3.2).
- C12.4.4 A divergent request that policy would deny is reported as "divergent and denied"; one that policy would stage is reported as "divergent and staged". Neither reaches anything.
- C12.4.5 The production model credential is not usable in replay: the replay session has its own placeholder and its own credential reference.
- C12.4.6 **Repetition.** With `mockllm --variant --flaky p` (a seeded test double that plants its change with probability `p`), `--samples 200` reports the first-divergence position in a share of samples within three standard errors of `p`, for `p` of 0.1, 0.5 and 0.9. Every report states `n`.
- C12.4.7 **Stale tape.** Effects after the first divergence are labelled `beyond-divergence` and appear in no total (a test sums every count in the report and compares with the pre-divergence effects only). With `--on-divergence continue` the report carries a banner that it is for debugging.

**Sabotage.** `model-mode-dials-tool-upstreams`; `report-omits-denied-divergences`; `report-counts-beyond-divergence`; `report-omits-sample-count`.

**Denied.** Scoring or ranking models. Running real models in any gated check.

## M12.5 Intervention

**Build.** `--mode intervene --replace-response <effect_id>=<file> --samples n`: the tape response of the named effect is substituted; model calls are live; the report states, for each later effect of the original session, in how many samples it still occurred.

Test double: `mockllm --conditional` follows an instruction if and only if a given marker string is present in the context it receives. Constructed sessions: ten where a write was caused by an injected marker in a fetched page or comment, ten where the same write was asked for by the original task regardless.

**Checks.**
- C12.5.1 MM12.7: in the ten caused sessions the write disappears in every sample after substitution; in the ten not-caused sessions it remains.
- C12.5.2 Substituting the response of an effect that is not upstream of the write changes nothing.
- C12.5.3 The report is labelled as an experiment, names the model endpoint and sample count, and is never attached to a session's evidence bundle as a verdict.
- C12.5.4 Isolation as C12.4.3.

**Sabotage.** `intervene-substitutes-wrong-effect`; `intervene-report-claims-verdict`.

**Denied.** Interventions on the model's context directly. Any claim of causality without the sample counts beside it.

## M12.6 Earned autonomy

**Build.** `csctl autonomy suggest` per `05` §13.4, deterministic, with a Python cross-check of the shape extraction. Output: proposed `commit.auto.invariants`, each line annotated with how many human-approved changesets it covers and the bundle IDs.

**Checks.**
- C12.6.1 MM12.8: over a corpus of 200 recorded reviews (150 committed unedited, 20 subset-edited, 20 rejected, 10 later undone), the suggestion replayed through M12.1 makes auto-eligible only changesets from the first group, and none from the other three.
- C12.6.2 With `--min 20`, shapes seen fewer than 20 times produce no suggestion.
- C12.6.3 The suggestion never loosens an existing invariant and never proposes `forbidTaint` removal, `requireOwnership: false` or a wildcard path at the repository root.
- C12.6.4 Identical input gives identical output.

**Sabotage.** `suggest-ignores-later-undo`; `suggest-counts-subset-edits-as-approval`.

**Denied.** Applying suggestions. Statistical thresholds beyond the count. Suggestions for `compensable` or `irreversible` conditions.

---

## Exit

Exit review. No human gate. It must state plainly what replay does **not** promise: for real agents any non-determinism in the harness appears as a divergence; a tape is stale after the first divergence; and a single sample of a live model proves little. The scripted-agent results go beside that statement.
