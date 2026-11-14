# M7. Undo and deferral

**Goal.** Give effects that could not be staged a recorded way back that is safe to use; let messages and simple creates wait for commit; let a commit be provisional; and let an outside reviewer, human or not, sign for reversible work without that signature having to be right.

**Properties advanced.** P11 (undo safety). P9 extended to deferred sends. Completes the lattice: after this milestone every write is `staged`, `compensable` or explicitly `irreversible`.

**Normative references.** `05` §5, §9 (`onFailure: compensate`, barriers and provisional IDs), §10; `03` §4.3.

**Expected results.**
- `csctl undo` puts the outside world back, and refuses to touch anything someone else has changed since.
- A message "sent" by the agent goes out only at commit.
- An agent can work overnight on probation; in the morning one signature keeps the work, or its absence removes it.
- A reviewing model can approve routine changes; when it is wrong, the change is reversible, inside a window, and on the record.

**Measurements [T].**

| ID | Metric | Target |
|---|---|---|
| MM7.1 | Undo of untouched resources restores the prior state digest | 100% of ≥ 500 randomized effects (H11) |
| MM7.2 | Undo when a third party changed the resource: conflict reported; third-party state overwritten | 100%; 0 (H11) |
| MM7.3 | Go vs Python on undo planning and guards over random traces | 100% of ≥ 5,000 |
| MM7.4 | Requests observed by `fakemsg` before commit, for deferred sends | 0 |
| MM7.5 | Provisional identifiers rewritten correctly at apply and afterwards | 100% of ≥ 1,000 generated chains |
| MM7.6 | Probation: unratified commits fully reverted at expiry; ratified commits untouched | 100%; 100% |
| MM7.7 | Added latency of a `compensable` write (two extra reads) | reported; p50 ≤ 2 × upstream round-trip + 5 ms |
| MM7.8 | Share of write effects in the M7 benign flows that are `staged` or `compensable` | reported (feeds H8) |

**Milestone-wide denied.** Guessing compensations from API shape, documentation or response codes: a write is `compensable` only through an explicit rule. Emulating a remote service to stage arbitrary REST writes (D22). Force-undo that overrides the guard. Automatic resolution of undo conflicts (D24). Undo of `irreversible` effects by "best effort". Scheduled or recurring undo. Partial restoration of a resource (field-level merge). Template logic in outbox responses beyond the three variables of `05` §5.

---

## M7.1 Prior and post state capture

**Build.** For each `compensable` effect: a `purpose: prestate` read before the write and a `purpose: poststate` read after, both through the broker, both recorded as effects; `prestate.captured` records with state digests per `05` §10 (canonical JSON minus `stateDigest.ignore`, raw bytes otherwise); bodies into the encrypted vault. The write is not forwarded until the `before` record is durable. For `deleteCreated`, the created URL is resolved from the response and only the post state is captured.

**Checks.**
- C7.1.1 Ordering: `prestate.captured{before}` ack precedes the write's first upstream byte (instrumented, 10,000 writes).
- C7.1.2 Prior read fails (upstream 5xx, timeout, 403): the write is **not** sent; the agent gets a problem document. A prior read returning 404 is recorded as "absent" and the write proceeds.
- C7.1.3 State digest is stable across volatile fields listed in `stateDigest.ignore` and changes on any other field change (200 generated documents).
- C7.1.4 `deleteCreated` URL resolution from `Location`, from a JSON pointer, and from a template; a response without the expected field leaves the effect recorded as applied with **no** undo available, and the review document says so.
- C7.1.5 Vault contents are encrypted (marker scan) and never appear in the ledger or bundle.
- C7.1.6 MM7.7.

**Sabotage.** `write-before-prestate-durable`; `write-proceeds-when-prestate-read-fails`; `state-digest-ignores-nothing-configured` (ignores all fields).

**Denied.** Capturing state of resources the effect did not address. Following links to capture related resources.

## M7.2 Compensation and undo

**Build.** `internal/undo` and the Python reference: the rules `restore` and `deleteCreated`; the git-ref rule (push `base` back with a lease on `new`); the guard (probe, compare with the recorded post state, write nothing on mismatch); reverse-order processing; outcomes of `05` §10; `csctl undo` with scopes session, commit and effect, signed by a reviewer (`countersign-undo-v1`). Wire `onFailure: compensate` (M6.4), `losers: undo` (M6.8) and the undo part of rewind (M5.6).

**Checks.**
- C7.2.1 MM7.1: random sequences of PUT, PATCH and comment creation against `fakehub`, then undo; `fakehub`'s state digest equals the digest before the session.
- C7.2.2 MM7.2: as above, with a third party editing a random subset of the resources in between; those report `conflict` and keep the third party's state; the rest are restored.
- C7.2.3 Undo of an applied git-ref entry: the ref returns to `base`; if a third party pushed on top, `conflict` and the ref is untouched; a ref created by the commit is deleted on undo.
- C7.2.4 A resource created by PUT (prior state absent) is deleted on undo.
- C7.2.5 Effects with no rule are reported `not-compensable`, listed, and never attempted.
- C7.2.6 Undo twice: the second run reports every target as already restored and makes no request.
- C7.2.7 An unsigned or wrongly signed operator undo is refused; the automatic triggers need no signature and record their trigger.
- C7.2.8 `onFailure: compensate`: a three-entry commit whose third entry conflicts ends `rolled-back` with the first two refs restored; if a restore itself conflicts the commit ends `partial` and says which.
- C7.2.9 MM7.3.

**Sabotage.** `undo-skips-guard`; `undo-forward-order`; `undo-put-without-if-match-when-etag-known`; `restore-uses-post-state-body`.

**Denied.** See milestone list.

## M7.3 Undo evidence

**Build.** Undo inside an unsealed session is recorded in that session. Undo of a sealed session runs as a session of kind `undo` with `parent_session` and `parent_seal_hash`, its own world (closed `empty` or `committed`), and its own bundle. Verifier: every `purpose: compensate` effect follows a `purpose: probe` effect whose recorded state digest equals the target's post state; `F_PRECONDITION` otherwise. `csverify` accepts a parent bundle alongside an undo bundle and checks the link.

**Checks.**
- C7.3.1 Golden bundles: undo within the session; undo session with parent; undo with conflicts (`W_UNDO_CONFLICT`); each verifies in both verifiers.
- C7.3.2 A re-signed test bundle where a compensation was made despite a mismatching probe → `F_PRECONDITION`.
- C7.3.3 An undo bundle whose `parent_seal_hash` does not match the supplied parent bundle → `E_OPEN`.
- C7.3.4 The undo session's effects are matched against the **parent's** policy digest (the policy that granted the original effects); a compensation outside those grants is denied.

**Sabotage.** `verifier-ignores-probe-digest`; `undo-session-uses-current-policy`.

**Denied.** Rewriting the parent session's records. A combined bundle format.

## M7.4 Deferred sends and provisional identifiers

**Build.** `internal/stager/outbox`: `05` §5. Synthetic responses from the template; `http` entries with `provisional[]` and `depends_on[]`; dependency detection (a provisional ID in a later request's URL, headers or buffered body); apply with rewriting and `idMap` extraction; idempotency header; rewriting of mapped provisional IDs for the rest of the session; barrier rule for non-staged requests carrying an unmapped provisional ID.

**Checks.**
- C7.4.1 MM7.4: the agent posts three messages to `fakemsg`; it receives three synthetic successes with distinct provisional IDs; `fakemsg` observes nothing until commit, then exactly three.
- C7.4.2 A staged reply that references the first message's provisional ID is applied after it, with the real ID substituted; `fakemsg` shows the reply attached to the real message.
- C7.4.3 MM7.5: generated chains up to depth 5 with IDs in paths, queries, JSON bodies and headers.
- C7.4.4 Subset selection that drops a message but keeps its reply is rejected (dependency closure, as C6.1.5).
- C7.4.5 A non-staged request carrying an unmapped provisional ID is a barrier under every `commit.barrier` setting; `independent` is refused.
- C7.4.6 Apply failure of the first message: its dependents are not sent; outcomes recorded; commit `partial`.
- C7.4.7 A connection error during apply with an idempotency header configured: retried up to three times; `fakemsg` (which honours the header) shows one message. Without the header: outcome `unknown`, no retry.
- C7.4.8 Template injection: request JSON values containing `{provisional}`, quotes, or control characters cannot alter the synthetic response's structure (50 hostile inputs).
- C7.4.9 Abort after staging sends: `fakemsg` state digest unchanged.

**Sabotage.** `outbox-forwards-immediately`; `provisional-id-not-rewritten-in-body`; `retry-without-idempotency-header`; `template-values-not-escaped`.

**Denied.** D21, D22. Deferred sends for requests whose real response the agent must read to continue (the policy author decides that by not configuring a stager).

## M7.5 Probationary commit

**Build.** `05` §10 probation in both modes. `commit.probation` defaults by who decided (`human`, `auto`; `delegate` arrives in M7.7); a reviewer may lengthen the window or choose the stricter mode when signing; `probation{until, on_expiry}` is inside the signed challenge. Mode `revert`: the world stays open; `csctl ratify` with a signed ratification; expiry triggers an undo with `trigger: probation-expired`; the session seals after ratification or after the undo closes. Mode `keep`: the world closes and the session seals at commit; the review service lists the commit as revocable until `until`; a signed `csctl revoke` runs the undo with `trigger: probation-revoked`. A timer in the world service that survives restarts (deadlines are rebuilt from the ledger).

**Checks.**
- C7.5.1 MM7.6: twenty commits on probation, ten ratified at random times; at expiry the ten unratified are reverted (state digests) and the ten ratified untouched.
- C7.5.2 Expiry while a third party has changed one resource: that one reports `conflict`, the rest revert; nothing is overwritten.
- C7.5.3 World-service restart across the deadline: the undo still runs once.
- C7.5.4 A ratification signed for another commit, or after expiry, is refused.
- C7.5.5 Clock tests: the deadline uses the world service's monotonic view reconciled with wall time at restart; setting the wall clock back does not extend probation beyond the recorded `probation_until` by more than the documented skew (30 s).
- C7.5.6 In `revert` mode the session is not sealed during probation (ordering asserted).
- C7.5.7 Defaults: a commit decided `by: auto` carries a 24 h `keep` probation without any policy setting; one decided `by: human` carries none; a policy override changes both.
- C7.5.8 `keep` mode: the world closes and the session seals at commit; at expiry nothing happens; `fakehub` is unchanged by the expiry.
- C7.5.9 `keep` mode, `csctl revoke` inside the window with a reviewer's signature: the undo runs with `trigger: probation-revoked` in an undo session; the same command with a bad signature is refused; after the window the command is recorded as an ordinary operator undo.
- C7.5.10 A reviewer's signed decision may lengthen the window or switch `keep` to `revert`; a decision that shortens the policy's window is refused; altering `probation` after signing fails verification (abuse-corpus case 14).

**Sabotage.** `probation-expiry-does-nothing`; `ratify-accepts-any-signature`; `seal-during-probation`; `auto-commit-without-default-probation`; `revoke-accepts-any-signature`.

**Denied.** Probation for `irreversible` effects (nothing to revert; such effects are listed as "outside probation" in the review document). Extending probation without a new signature.

## M7.6 Directly applied effects in the review document

**Build.** Fill `applied_directly` of `05` §6: each `compensable` or `irreversible` effect already real in the session, its class, whether an undo exists, and for JSON resources with captured states a field-level before/after summary (changed JSON pointers and value digests, never values). The review page fetches values from the vault on demand.

**Checks.**
- C7.6.1 The summary equals an independent JSON diff on 300 generated before/after pairs.
- C7.6.2 No value from a captured state appears in the bundled review document (marker scan).
- C7.6.3 Effects with no undo are marked and rendered above the entries on the page (manual checklist if C6.7.2 was skipped).

**Sabotage.** `review-hides-not-compensable-effects`.

**Denied.** Rendering captured state into the bundle.

## M7.7 Delegated reviewer

**Build.** `05` §8 "Who may sign": key role `reviewer:delegate` (Ed25519) in the manifest; the review service's API accepts a delegate's signed decision; the world service checks the four acceptance conditions before recording `commit.decision{by: delegate}`; both verifiers recompute them. `commit.delegate` policy fields. A **scripted delegate** for tests: a small service that fetches pending reviews and signs or rejects according to a script. No model is used in any check.

**Checks.**
- C7.7.1 With `delegate.enabled: false` (the default) every delegate signature is refused.
- C7.7.2 A changeset that failed only a soft invariant (for example `git.maxAddedLines`), no forbidden label, no `held` entry: the delegate's `commit` with a 24 h `keep` probation is accepted and applied; the statement and the bundle say `by: delegate`.
- C7.7.3 Each acceptance condition, violated alone, causes refusal inline and `E_COMMIT` offline in a re-signed test bundle: a `held` entry present; a hard invariant failed; a selected entry carrying a forbidden label; probation shorter than `minProbation`; probation absent.
- C7.7.4 A delegate key cannot sign a ratification, a revocation, an undo request, or a single-effect review (each refused; each an abuse-corpus case).
- C7.7.5 A delegate signature presented as a human decision, and a WebAuthn assertion presented as a delegate decision, are both refused.
- C7.7.6 **Revocation closes the loop.** After C7.7.2, a human's signed `csctl revoke` inside the window restores the pre-commit state (world oracle), with `trigger: probation-revoked`; the revocation and its outcome are in an undo session linked to the parent (benchmark T9 in miniature).
- C7.7.7 **Injection of the delegate is contained, not prevented.** A scripted delegate that approves whatever it is shown is pointed at changesets built from the M7 attack flows: everything it is able to sign is reversible and revocable, and everything `irreversible`, hard-invariant-failing or forbidden-labelled is refused regardless of its signature.
- C7.7.8 Go and Python agree on delegate acceptance for 2,000 random changesets and policies.
- C7.7.9 The delegate receives exactly the review document and, on request, the same diffs a human sees; it has no other API, no credentials, and no access to the ledger or the vault (permission test).

**Sabotage.** `delegate-may-sign-held-entries`; `delegate-probation-not-enforced`; `delegate-signature-accepted-as-human`; `delegate-can-ratify`.

**Denied.** Shipping or recommending any particular reviewing model. Calling a model from Countersign. Trust levels or scores for delegates. More than one delegate signature per decision (quorum). A delegate for single-effect reviews.

---

## Exit: human gate G3

The exit review must contain: MM7.8 with the list of every effect in the benign flows that remained `irreversible` and why; the conflict cases of MM7.2 with before/after digests; and the reviewer question, "is there any path by which undo or abort can destroy work that the session did not create?"
