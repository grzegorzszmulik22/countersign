# M6. Commit and review

**Goal.** Turn a world's pending entries into one reviewable changeset; let it commit automatically when fixed invariants hold; otherwise collect one passkey signature over exactly what will become real; apply it with preconditions; and give the agent a boundary it can read.

**Properties advanced.** P8 (review binding), P10 (commit integrity). P4 completed for `review` conditions.

**Normative references.** `05` §3 (groups), §6–§9, §15; `03` §4.3, §10 (V12–V13).

**Expected results.**
- What reaches the real remote is exactly the set whose root was signed, each entry once, and only if the remote is still as the agent saw it.
- A signature cannot be replayed, stretched to a different set, or fabricated by the system.
- A benign task that changes only allowed paths commits with no human at all.
- An agent that is refused something is told why in a form it can act on.

**Measurements [T].**

| ID | Metric | Target |
|---|---|---|
| MM6.1 | Applied set equals selected set, over ≥ 1,000 randomized commits with crashes injected at every step | 100% (H10) |
| MM6.2 | Entries applied twice in the same runs | 0 (H10) |
| MM6.3 | Review-abuse corpus cases that succeed | 0 of ≥ 22 |
| MM6.4 | Go vs Python: changeset roots, review documents (byte-identical), invariant results, signature verification | 100% of ≥ 2,000 random changesets |
| MM6.5 | Conflicts detected when the upstream ref moved between stage and commit; upstream refs overwritten | 100%; 0 |
| MM6.6 | World-group races of three: exactly one `committed`; losers' outside-state contribution | 100% of 200 races; none (H12) |
| MM6.7 | Time from trigger to `commit.closed` for an automatic commit of one ref | p50 ≤ 1.5 s (dominated by the push) |
| MM6.8 | Problem-document conformance for every reason code | 100% |

**Milestone-wide denied.** Approval by any channel without a signature. Blanket or time-boxed approvals ("always allow"). Editing an entry during review (a reviewer may only select or reject). Automatic conflict resolution (D24). Notifications. Reviewer groups, quorum, escalation. Model-written summaries (D1). Invariants beyond `05` §7 (D3). Granting anything through the boundary (D27). A second page or any dashboard (D7).

---

## M6.1 Changeset and review document

**Build.** `internal/commit` and `ref/python/refcommit`: entry canonicalization (RFC 8785), entry digests, `changeset_root` and `selected_root` (RFC 6962), dependency closure for subsets, and the review document of `05` §6 with git facts computed from the shadow repository (commit IDs, changed paths, line counts, binary sizes, credential-shape counts in added lines, fast-forward test). Annotation fields from later milestones are `null`. `commit.requested` recorded with the root and `review_sha256`.

**Checks.**
- C6.1.1 MM6.4 for roots and documents.
- C6.1.2 Git facts equal an independent computation with plain `git diff --numstat`, `git rev-list` and `git merge-base` on 200 generated histories (including renames, binary files, merges, an empty commit, a 5,000-file change).
- C6.1.3 The document contains no file content and no request body: planted markers in file contents and commit messages do not appear; paths do, and are replaced by digests when `privacy.reviewPaths: false`.
- C6.1.4 Squashed entries appear once; the root is over the squashed set in `journal_seq` order.
- C6.1.5 A subset that omits a dependency of a selected entry is rejected.
- C6.1.6 The Merkle code is the M1 code (no second implementation in Go); the Python reference is independent.

**Sabotage.** `root-over-unsorted-entries`; `review-doc-omits-an-entry` (the document lists fewer entries than the root covers; V12 must catch it); `facts-count-deleted-lines-as-added`.

**Denied.** Rendering diffs into the bundle. Natural-language descriptions of the change.

## M6.2 Invariants and automatic commit

**Build.** Every invariant of `05` §7 that needs no later milestone (`forbidTaint`, `requireIntent`, `requireOwnership` are rejected at validation until their milestones). Auto-eligibility. Triggers: operator (`csctl commit`), session end, and a test hook standing in for the agent trigger until M6.6. `commit.decision{by: auto}` records each invariant result.

Decision table `test/vectors/commit/invariants.yaml` (≥ 150 rows): each invariant passing, failing at the boundary value, and failing clearly; combinations; an entry staged under condition `review`; `auto.enabled: false`.

**Checks.**
- C6.2.1 The decision table: Go and Python equal the expected column.
- C6.2.2 Benign flow: a change under `src/` on `refs/heads/agent/x` with `git.paths.allow: ["src/**"]` commits automatically; `fakehub` shows the branch.
- C6.2.3 The same flow touching `.github/workflows/ci.yml`, or adding a credential-shaped string, or exceeding `maxAddedLines`, is not auto-eligible and waits for review; `fakehub` unchanged.
- C6.2.4 A path that matches `allow` through a symlink entry or a path with unusual characters is evaluated on the literal tree path (20 hostile path vectors).
- C6.2.5 Offline: recomputing invariants from the bundled review document gives the recorded results; a re-signed test bundle with a flipped result → `F_INVARIANT_MISMATCH`.

**Sabotage.** `auto-commit-ignores-failed-invariant`; `paths-deny-not-evaluated`; `credential-shape-scan-on-deleted-lines-only`.

**Denied.** Invariants written as expressions. Per-reviewer invariants. Learning invariants here (that is M12.6).

## M6.3 Signed review

**Build.** `internal/review`: the challenge of `05` §8; WebAuthn assertion verification for ES256 and EdDSA per the pinned specification; reviewer registration producing `reviewer` entries in the key manifest (credential ID, public key, RP ID, origins). Go and Python implementations. Tests use a software authenticator.

**Abuse corpus** `test/vectors/commit/abuse.yaml`. Each must be refused inline where applicable and yield `E_COMMIT` offline:

1. The same signature presented twice.
2. A signature for root R used with a different selected set.
3. One entry's `new` object ID changed after signing.
4. An entry added after signing; an entry removed after signing.
5. The review document changed after signing (same root).
6. Expired decision.
7. Signature from another session; another commit ID in the same session.
8. Wrong RP ID hash. 9. Origin not in the manifest.
10. User-present clear; user-verified clear when required.
11. Unregistered key; registered key whose role is not `reviewer`.
12. A `reject` assertion presented as `commit`.
13. `clientDataJSON.type` of `webauthn.create`.
14. `probation` (window or mode) altered after signing.
15. A `by: human` decision with no assertion (re-signed test bundle).
16. A `by: auto` decision although an invariant failed (re-signed test bundle).
17. A decision recorded after an apply effect (re-signed test bundle).
18–22. For a `held` entry: the request altered in one byte of body, path, query, method, authority.

**Checks.**
- C6.3.1 MM6.3.
- C6.3.2 MM6.4 for signature verification over random valid and corrupted assertions.
- C6.3.3 Upstream WebAuthn test vectors verify in both implementations.
- C6.3.4 Removing any one field from the challenge makes at least one corpus case pass wrongly (proved by the sabotages).
- C6.3.5 **Comparison with draft-schrock-ep-authorization-receipts.** Read the current revision (`06` §8) and save `evidence/M6.3/draft-comparison.md`: its context-hash construction and consume-once rule set against `05` §8, field by field. Where a single-effect review can be expressed in the draft's receipt format without weakening P8, emit that receipt alongside the native record and verify it with a second implementation. Where it cannot, record why. The changeset challenge is not altered to fit the draft.

**Sabotage.** `challenge-omits-selected-root`; `challenge-omits-review-digest`; `challenge-omits-decision`; `challenge-omits-expiry`; `challenge-omits-probation`; `skip-origin-check`; `skip-user-presence`.

**Denied.** Attestation checks at registration. Passkey recovery flows. Other algorithms.

## M6.4 Apply

**Build.** The apply loop of `05` §9 for `git-ref` entries: `git push --force-with-lease` through the broker as `actor: world, purpose: apply`; outcome mapping; at-most-once; restart recovery from the ledger with outcome `unknown` for an apply effect that has no result; `onFailure: stop` (the `compensate` option is wired in M7). The broker lets `receive-pack` reach the real remote **only** for `actor: world, purpose: apply` serving a selected entry of a decided commit, and only if the ref-update command lines at the start of the request (ref name, old ID, new ID; never the pack data) equal that entry's `ref`, `base` and `new`.

**Checks.**
- C6.4.1 MM6.1 and MM6.2: a generator builds worlds with 1–12 entries, random selections and decisions, and kills the world service or broker at a random point among: before the decision record, after it, before the apply effect, between the apply effect and the push, after the push before the result, after `commit.applied`. After recovery and completion, `fakehub`'s refs equal the expected result of applying exactly the selected entries whose preconditions held, and no ref received two pushes for one entry.
- C6.4.2 MM6.5: a third party moves the upstream ref after staging; the entry's outcome is `conflict`; the upstream value is the third party's; with `onFailure: stop`, later entries stay pending and the commit closes `partial`.
- C6.4.3 A sandbox request to `receive-pack` can never reach `fakehub`, whatever headers or tokens it presents, including a stolen world token (it fails the certificate and source checks).
- C6.4.4 An apply attempt for an entry that is not in `selected`, or whose commit has no `commit` decision, is refused by the broker (the broker checks the decision record itself; it does not trust the world service's word).
- C6.4.5 After a `committed` commit the world is `open` with no pending entries; a new push to the same ref creates an entry whose `base` is the applied value.
- C6.4.6 The crash window "push accepted, result not recorded" yields `unknown`, a `W_APPLY_UNKNOWN` warning, and no retry; the test then shows that `fakehub` has the ref exactly once.
- C6.4.7 MM6.7.
- C6.4.8 After the signature, the shadow repository's ref is replaced with a different commit (a simulated compromise of the stager): the broker refuses the push because the new ID is not the signed one; `fakehub` never holds the substitute (benchmark T3 in miniature).

**Sabotage.** `apply-without-lease`; `apply-unselected-entries`; `retry-after-unknown`; `broker-trusts-world-about-decision`; `broker-skips-ref-command-check`.

**Denied.** Parallel apply. Reordering entries. Retrying conflicts with fresh state.

## M6.5 Single-effect review and barriers

**Build.** `05` §8 single-effect protocol (hold, problem-document pending answer, release of held bytes, identical-digest retry consumed exactly once) and §9 barriers with all three `commit.barrier` settings.

**Checks.**
- C6.5.1 Commit within the hold: the upstream receives the held request once; records in the order `effect.http{hold}` → `commit.requested` → `commit.decision` → apply.
- C6.5.2 Pending answer after `holdSeconds`; later decision; an identical retry succeeds; a second identical retry opens a new review.
- C6.5.3 `reject` → `REVIEW_REJECTED`; expiry → `REVIEW_TIMEOUT` with a `timeout` decision.
- C6.5.4 1,000 concurrent identical retries after one decision: exactly one is forwarded.
- C6.5.5 A request over the buffer limit on a review path → `LIMIT_BODY`.
- C6.5.6 Pending reviews survive a broker and a world-service restart and stay single-use.
- C6.5.7 Barrier, `commit-first`: with a staged branch pending, the agent's POST to create a pull request triggers a commit; when it closes `committed` the POST proceeds and `fakehub` (which requires the branch to exist) accepts it. When the commit is not auto-eligible and no reviewer acts within the hold, the POST gets `BARRIER`.
- C6.5.8 Barrier `deny` and `independent` behave as specified; `independent` is refused for a request carrying a provisional ID (vector prepared here, exercised fully in M7.4).

**Sabotage.** `release-resent-bytes-not-held-bytes`; `retry-matched-by-effect-id-not-digest`; `barrier-proceeds-before-commit-closes`.

**Denied.** Holding longer than `holdSeconds`. Queuing other requests behind a hold.

## M6.6 The readable boundary

**Build.** `internal/boundary`: RFC 9457 problem documents for every denial, hold and pending answer, from fixed templates per reason code; the `countersign.internal` endpoints of `05` §15, answered by the broker, recorded as `control` effects with `served_by: boundary`.

**Checks.**
- C6.6.1 MM6.8: for every reason code in `03` §9, a triggering request yields a problem document that validates against the schema and whose `reason` equals the recorded one.
- C6.6.2 No problem document or boundary response contains a credential value, a placeholder of another session, content from another session, or another session's grant (cross-session leak test with two sessions under different policies).
- C6.6.3 `GET /v1/boundary` equals a golden rendering of the test policy; budgets and taint fields reflect the session's state.
- C6.6.4 `POST /v1/commit` triggers a commit request and returns its ID and state; with pending entries that are auto-eligible the state reaches `committed`.
- C6.6.5 No boundary request changes a grant, a budget, a class or an autonomy level (property test: policy digest and effective decisions identical before and after 1,000 random boundary requests).
- C6.6.6 The scripted agent, given a denial's problem document as its tool result and a transcript that reads `/v1/boundary` and retries within the grants, completes its task.
- C6.6.7 `countersign.internal` is unreachable from anything but a session's own proxy connection, and is never forwarded upstream.

**Sabotage.** `problem-doc-includes-real-secret-in-hint`; `boundary-lists-other-sessions-grants`; `boundary-post-can-raise-budget`.

**Denied.** Any endpoint that requests more authority. Free-text hints. Localization.

## M6.7 Review service and page

**Build.** `csreview`: API to list pending commit requests and fetch one review document; a single static page that renders it verbatim: each entry with its ref, base and new IDs, commit list, changed paths and counts, flags (`declared_safe`, failed invariants, later: taint, attribution, ownership), the directly applied effects, budgets; diffs fetched on demand from the world service; checkboxes for subset selection; two buttons calling `navigator.credentials.get` with the challenge. The passkey is the login.

**Checks.**
- C6.7.1 API-level end to end with the software authenticator: list → fetch → select → sign → applied.
- C6.7.2 The page's displayed entries, object IDs and flags equal the review document (DOM snapshot in a headless browser with a virtual authenticator if the toolchain provides one; otherwise `SKIPPED-ENV` plus a manual checklist with screenshots, required before M14).
- C6.7.3 The challenge computed by the page's script equals the Go and Python computations for 100 random reviews, including subsets.
- C6.7.4 The page displays the full 40-character object IDs it signs, and flags are impossible to scroll past unseen for the first failed invariant (it is rendered above the entries). A truncated or hidden entry is caught by C6.7.2.
- C6.7.5 Content security policy forbids inline script and third-party origins; one HTML file, one script, one stylesheet, no framework, no build step.

**Sabotage.** `page-signs-full-set-while-showing-subset`; `page-omits-failed-invariants`; `page-computes-challenge-without-review-digest`.

**Denied.** D7 beyond this page. Commenting, assigning, history views.

## M6.8 World groups

**Build.** `05` §3 groups: label-based membership, `exactly-one` serialization in the world service, `superseded` closure, denial `GROUP_SUPERSEDED` for losers' later writes. (`losers: undo` is wired in M7.)

**Checks.**
- C6.8.1 MM6.6: three sandboxes from the same start each stage a different change to the same ref and request commit within the same 50 ms; exactly one closes `committed`; `fakehub` holds exactly that change; the others close `superseded` with decisions recorded as `reject`.
- C6.8.2 A loser's write after supersession → `GROUP_SUPERSEDED`.
- C6.8.3 Each of the three bundles verifies on its own and reports its world outcome.
- C6.8.4 A session without the group label is unaffected by the group.

**Sabotage.** `group-commits-not-serialized` (two winners under contention).

**Denied.** Choosing a winner by any measure of quality. Merging losers' work. Groups larger than 16.

## M6.9 Verifier integration

**Build.** V12 and V13 of `03` §10 in `csverify` and `refverify`; the `world` field in the output.

**Commit mutations** (applied to valid bundles, then re-signed with the genuine emitter keys so that only the commit logic can catch them): an apply effect for an unselected entry; two apply effects with results for one entry; an apply effect before its decision; `selected_root` not matching `selected`; a `changeset_root` not matching the entries; a review document with an extra entry; a `by: auto` decision with `auto_eligible: false`; a `commit.applied{applied}` whose apply effect was denied.

**Checks.**
- C6.9.1 Golden bundles: automatic commit, human commit, subset commit, rejected, expired, partial with a conflict, an `unknown` outcome, a group loser. Each gives the expected verdict, `world` outcome and warnings in both verifiers.
- C6.9.2 Every commit mutation and every abuse-corpus bundle → `E_COMMIT` in both verifiers.
- C6.9.3 Verification needs only the bundle and the trusted key manifest.

**Sabotage.** `verifier-skips-selected-root-recomputation`; `verifier-accepts-human-decision-without-assertion`.

**Denied.** Online revocation checks.

---

## Exit

Exit review; gate G3 follows M7. The review must show MM6.1 broken down by crash point, and list every way a commit can end other than `committed`, with how each appears to a reviewer and to the agent.
