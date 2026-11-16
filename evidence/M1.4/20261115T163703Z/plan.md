# M1.4 (reopened) — plan

Supervisor review reopened M1.4 (progress note + .lane/objective.md lane
note). Three required properties:

## (1) Hostile-input-safe bundle reader → E_BUNDLE

`ReadBundle` in `internal/ledger/bundle.go` currently does
`make([]byte, hdr.Size)` from an untrusted tar header. Fix:

- Track bytes consumed; declared `hdr.Size` must be ≤ remaining input,
  else E_BUNDLE before any allocation.
- `hdr.Size` must also be ≤ `MaxMemberBytes`; running total ≤
  `MaxTotalBytes`; member count ≤ `MaxMembers` (all documented
  constants in code + docs/ledger-and-verify.md).
- Reject `hdr.Size < 0`, non-regular members, duplicates (kept).
- `tr.Next()` errors: only `io.EOF` ends the loop; every other error —
  truncated header/member, bad checksum, trailing garbage — is
  E_BUNDLE. (Currently any error silently ends the loop → V1 hole.)
- ReadBundle is the only tar-parse site (csverify → VerifyBundle →
  ReadBundle; VerifyBundle2 receives already-parsed members).

## (2) Same error discipline everywhere a bundle is parsed

VerifyBundle surfaces BundleError as E_BUNDLE; csverify prints INVALID.
No second tar reader exists — verify again during work.

## (3) Deterministic rejecting test per step V1–V11 + V15

New file `internal/ledger/verifyreject_test.go`:

- `TestC143_VSteps`: for each step, take a sealed bundle's members,
  mutate exactly the field that step defends, assert the code:
  V2 corrupt envelope → E_SCHEMA; V3 flipped sig byte → E_SIG and
  key validity-window violation → E_KEY; V4 wrong session/subject →
  E_SESSION; V5 chain reorder → E_CHAIN; V6 wrong-origin / emitter-signed
  checkpoint → E_CHECKPOINT; V7 corrupted proof + non-increasing
  log_index → E_INCLUSION; V8 missing session.open → E_OPEN, mutated
  policy digest → E_POLICY; V9 drop world.closed → UNSEALED; V10 wrong
  seal head → E_SEAL; V11 result for unknown effect → E_STRUCTURE;
  V15 crafted bundles asserting W_DANGLING, W_UNCLEAN_EMITTER,
  W_OBSERVER_GAP, W_UNPARSED, W_PARTIAL_COMMIT, W_APPLY_UNKNOWN,
  W_UNDO_CONFLICT.
- `TestC147_ReaderRejects` (run as the deterministic half of C1.4.7):
  truncated header, truncated member, bad checksum, trailing garbage,
  size>remaining, size>MaxMemberBytes, giant (1<<60) claim, negative
  size, non-regular member, duplicate, missing/extra member → E_BUNDLE.

## Sabotage additions (spec-mandated two more)

- `unbounded-tar-alloc.patch`: restore `make([]byte, hdr.Size)` without
  bounds → giant-claim test panics/OOMs vs E_BUNDLE.
- `swallow-tar-errors.patch`: restore `if err != nil { break }` →
  trailing-garbage/bad-header tests pass CLEAN vs E_BUNDLE.

## Loop

checks first (already failing today on unhardened reader → the aimed
tests ARE the new checks; add them, watch them catch the defects on a
mutated tree), implement (1)+(2), `make check-M1.4`,
`make sabotage-M1.4` (6 patches), two consecutive clean runs,
`make lint`, `make regress`, mark DONE in spec/progress/evidence-go.md,
commit + push, `bash .lane/verify.sh`.

No spec/check-ID/vector edits; additive vectors only if needed.
