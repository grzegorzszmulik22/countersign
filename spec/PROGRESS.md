# Progress

Updated by the implementation agent on every loop iteration (`06-agent-loop.md` §1, §13).
Statuses: `TODO`, `IN_PROGRESS`, `DONE`, `BLOCKED`, `BLOCKED-CR-NNN`, `SKIPPED-ENV`, `AWAITING-GATE`.

| chunk | title | status | attempts | last evidence folder | note |
|---|---|---|---|---|---|
| M0.1 | Repository and toolchain | DONE | 1 | evidence/M0.1/20261114T161541Z | lane foundation; re-verified by supervisor on oci-free-a1 and agent-vpc |
| M0.2 | Hermetic cluster | TODO | 0 | | |
| M0.3 | Fixture services | IN_PROGRESS | 5 | lane/fixtures | supervisor review 5: 9/9 unseen sabotages caught, regress green, race-clean. Earlier rounds found: wrong tool-result content accepted; token, repository, file and argument fields not tested; ignored JSON errors; two edits to shared tooling (kept, sound). REOPENED after merge: fakereg tests use the host's pip and npm, absent on oci-free-a1, so make regress fails there |
| M0.4 | Scripted agent | TODO | 0 | | |
| M0.5 | Check, sabotage and evidence tooling | DONE | 2 | evidence/M0.5/20261114T161922Z | lane foundation; re-verified by supervisor, frozen-file sabotages caught |
| M1.1 | Records and envelope | TODO | 0 | | |
| M1.2 | Signing, keys, emitter chains | TODO | 0 | | |
| M1.3 | Merkle log and checkpoints | TODO | 0 | | |
| M1.4 | Ledger storage, bundle, csverify | TODO | 0 | | |
| M1.5 | Python reference verifier | BLOCKED | 1 | lane/evidence-py bf9be33 | C1.5.2 needs csverify and golden bundles (M1.4). Supervisor review: lane marked DONE with C1.5.2 BLOCKED (not allowed by 06 §2); its suite misses an index/record count mismatch (supervisor sabotage). Resume after M1.4 lands |
| M1.6 | Mutation suite and measurements | TODO | 0 | | |
| **G1** | **Human gate: freeze the evidence format** | TODO | | | |
| M2.1 | Proxy listener and sessions | TODO | 0 | | |
| M2.2 | TLS interception | TODO | 0 | | |
| M2.3 | Streaming and digests | TODO | 0 | | |
| M2.4 | Write-ahead evidence and fail-closed | TODO | 0 | | |
| M2.5 | Protocol edges and hardening | TODO | 0 | | |
| M2.6 | Performance harness | TODO | 0 | | |
| M3.1 | Policy schema and matcher | DONE | 1 | lane/policy | run ahead of M2 by supervisor waiver (no code dependency). Supervisor review: regress green, 3/3 unseen sabotages caught (http default port, trailing-dot host, ** zero segments), race-clean. Lane edited shared tooling (sabotage.sh evidence, lint cache dirs): reviewed, sound, kept |
| M3.2 | Credential store, placeholders, injection | TODO | 0 | | |
| M3.3 | Pinning, placeholder misuse, credential shapes | TODO | 0 | | |
| M3.4 | Response scrubbing | TODO | 0 | | |
| M3.5 | Limits | TODO | 0 | | |
| M3.6 | Semantic matchers | TODO | 0 | | |
| M4.1 | Custom resources and session lifecycle | TODO | 0 | | |
| M4.2 | Admission webhook | TODO | 0 | | |
| M4.3 | Network lockdown | TODO | 0 | | |
| M4.4 | Broker in cluster mode | TODO | 0 | | |
| M4.5 | Helm chart and csctl | TODO | 0 | | |
| M4.6 | Completeness against packet capture | TODO | 0 | | |
| M4.7 | agent-sandbox adapter | TODO | 0 | | |
| **G2** | **Human gate: trusted computing base and lockdown** | TODO | | | |
| M5.1 | Ledger as a service | TODO | 0 | | |
| M5.2 | Reversibility classes and autonomy | TODO | 0 | | |
| M5.3 | World service and lifecycle | TODO | 0 | | |
| M5.4 | Git stager: read path | TODO | 0 | | |
| M5.5 | Git stager: write path | TODO | 0 | | |
| M5.6 | Abort, rewind, world-unchanged proof | TODO | 0 | | |
| M6.1 | Changeset and review document | TODO | 0 | | |
| M6.2 | Invariants and automatic commit | TODO | 0 | | |
| M6.3 | Signed review | TODO | 0 | | |
| M6.4 | Apply | TODO | 0 | | |
| M6.5 | Single-effect review and barriers | TODO | 0 | | |
| M6.6 | The readable boundary | TODO | 0 | | |
| M6.7 | Review service and page | TODO | 0 | | |
| M6.8 | World groups | TODO | 0 | | |
| M6.9 | Verifier integration | TODO | 0 | | |
| M7.1 | Prior and post state capture | TODO | 0 | | |
| M7.2 | Compensation and undo | TODO | 0 | | |
| M7.3 | Undo evidence | TODO | 0 | | |
| M7.4 | Deferred sends and provisional identifiers | TODO | 0 | | |
| M7.5 | Probationary commit | TODO | 0 | | |
| M7.6 | Directly applied effects in the review document | TODO | 0 | | |
| M7.7 | Delegated reviewer | TODO | 0 | | |
| **G3** | **Human gate: transaction semantics** | TODO | | | |
| M8.1 | Inspection framework and Anthropic Messages | TODO | 0 | | |
| M8.2 | OpenAI Responses and Chat Completions | TODO | 0 | | |
| M8.3 | Request-side tracking: results, windows, context | TODO | 0 | | |
| M8.4 | MCP inspection | TODO | 0 | | |
| M8.5 | Privacy and redaction | TODO | 0 | | |
| M9.1 | Reference reconciler and trace corpus | TODO | 0 | | |
| M9.2 | Go engine and offline verification | TODO | 0 | | |
| M9.3 | Inline enforcement | TODO | 0 | | |
| M9.4 | Expectation rule packs | TODO | 0 | | |
| M9.5 | MCP: undeclared calls and server contracts | TODO | 0 | | |
| M9.6 | Policy and contract learning | TODO | 0 | | |
| M9.7 | Intent annotations on changesets | TODO | 0 | | |
| M9.8 | Transaction propagation into MCP servers | TODO | 0 | | |
| **G4** | **Human gate: reconciliation semantics** | TODO | | | |
| M10.1 | Labels and taint state | TODO | 0 | | |
| M10.2 | Provider-executed tools | TODO | 0 | | |
| M10.3 | Stateful decisions | TODO | 0 | | |
| M10.4 | Attack and benign flows | TODO | 0 | | |
| M10.5 | Causal chain: csverify explain | TODO | 0 | | |
| M11.1 | Observer on the ledger service | TODO | 0 | | |
| M11.2 | Tetragon deployment and tracing policy | TODO | 0 | | |
| M11.3 | csobserver | TODO | 0 | | |
| M11.4 | Bypass evidence and cross-emitter consistency | TODO | 0 | | |
| M11.5 | Process lineage and ownership | TODO | 0 | | |
| M12.1 | Policy what-if | TODO | 0 | | |
| M12.2 | Tape | TODO | 0 | | |
| M12.3 | Replay: exact mode and isolation | TODO | 0 | | |
| M12.4 | Model mode | TODO | 0 | | |
| M12.5 | Intervention | TODO | 0 | | |
| M12.6 | Earned autonomy | TODO | 0 | | |
| M13.1 | Leak budget | TODO | 0 | | |
| M13.2 | Write budget | TODO | 0 | | |
| M13.3 | Attested outputs | TODO | 0 | | |
| M13.4 | The gate | TODO | 0 | | |
| M14.1 | Benchmark runner, scenarios, shared policies | TODO | 0 | | |
| M14.2 | Defence levels | TODO | 0 | | |
| M14.3 | Results | TODO | 0 | | |
| **G5** | **Human gate: results review** | TODO | | | |
| M14.4 | Quickstart, documentation, demonstration | TODO | 0 | | |
| M14.5 | Real-agent run (optional) | TODO | 0 | | |
| M14.6 | Release readiness | TODO | 0 | | |

## Headline tracker

| ID | Target | Achieved | Evidence |
|---|---|---|---|
| H1 | 0 real secrets in any sandbox | | |
| H2 | 0 of 15 credential-theft scenarios succeed | | |
| H3 | 0 unrecorded flows over ≥ 10,000 | | |
| H4 | 100% of ≥ 1,000 mutants detected; verifiers agree 100% | | |
| H5 | p50 ≤ 3 ms, p99 ≤ 12 ms added; streamed first byte ≤ 5 ms p99 | | |
| H6 | 0 interruptions on benign tasks without irreversible effects | | |
| H7 | ≥ 80% of benign tasks commit with no human; 1 review each otherwise; 0 unexpected | | |
| H8 | ≥ 90% of benign write effects staged or compensable | | |
| H9 | World unchanged after abort in 100% of scenarios | | |
| H10 | Applied set = signed set in 100% of ≥ 1,000 commits with crashes; 0 double applies | | |
| H11 | Undo restores 100%; conflicts detected 100%; 0 overwrites | | |
| H12 | Sibling-world race: exactly one commits, losers leave no trace | | |
| H13 | Planted unattributed effects: recall 100%, false positives ≤ 1% | | |
| H14 | 5 of 5 divergence scenarios stopped inline and found offline | | |
| H15 | 0 untrusted-caused or unrequested writes real without a signature | | |
| H16 | Causal chain reconstructed in 100% | | |
| H17 | Policy what-if agrees with re-execution 100% | | |
| H18 | Replay identical 100%; planted divergences found 100%; 0 upstream contacts | | |
| H19 | Leak through allowed read-only destinations ≤ budget | | |
| H20 | 100% of committed commits attested; gate refuses 100% of bad pushes | | |
| H21 | Benign completion ≥ 95% of unprotected | | |
| H22 | Quickstart ≤ 10 minutes | | |
