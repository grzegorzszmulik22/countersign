<!-- Copyright 2026 The Countersign Authors
     SPDX-License-Identifier: Apache-2.0 -->

# refverify — the Python reference verifier (M1.5)

`ref/python/refverify` is a second, independent implementation of the
`csverify` algorithm, written from `spec/03-evidence-format.md` and the
upstream standards alone (no Go source is read, generated or consulted —
C1.5.3 enforces this). It exists so the Go verifier can be cross-checked
against something that shares no code or test helpers with it.

## Run

```
.tools/python/bin/python3 -m refverify <bundle.tar> --keys <trusted-keys.json>
```

with `ref/python` on `PYTHONPATH` (the check suite does this). Output is the
same JSON object `csverify` prints:
`{verdict, world, errors[], warnings[], findings[], stats{}}`. Exit status is
0 for `CLEAN`/`CLEAN_WITH_DENIALS`, 1 for any other verdict, 2 on usage or
unreadable inputs.

## What it implements

V1–V11 and V15 of spec 03 §10:

| Check | Covers |
|---|---|
| V1 | bundle member set, manifest shape, canonical encodings |
| V2 | strict JSON (duplicate keys rejected), DSSE envelope shape, exactly one signature, in-toto v1 statement, `record/v1` predicate, per-type body schema |
| V3 | keyid in trusted manifest, `emitter:<role>` match, `not_before`/`not_after` covers `ts`, Ed25519 verify over the DSSE PAE, bundle `keys.json` must match the trusted manifest |
| V4 | `session` field and statement subject name/digest = `sha256(session)` |
| V5 | per-emitter `eseq` 0..n-1 gap-free, `eprev` hash chain, unique record ids |
| V6 | `checkpoint.txt` is a C2SP tlog-checkpoint note, origin = `manifest.log_origin`, at least one `log`-key signature verifies, no emitter/attestor signature |
| V7 | RFC 6962 inclusion proofs against the checkpoint root at `tree_size`, `log_index` strictly increasing |
| V8 | record 0 is `session.open`; `policy.yaml` and `contracts/*.yaml` hash to the declared digests |
| V9/V10 | `world.closed` then controller `session.seal`; each seal entry's `final_eseq`/`head_hash` equals that chain's head, no emitter missing, nothing after a sealed head |
| V11 | reference resolution (result→effect, `stage.entry`/`prestate.captured`/`commit.*`/`undo.*`/`intent.*`) and the §4.5 ordering rules in log order |
| V15 | `W_DANGLING`, `W_UNCLEAN_EMITTER`, `W_OBSERVER_GAP`, `W_UNPARSED`, `W_PARTIAL_COMMIT`, `W_APPLY_UNKNOWN`, `W_UNDO_CONFLICT` |

Verdict severity: `INVALID` > `UNSEALED` > `LEARN` > `VIOLATIONS` >
`CLEAN_WITH_DENIALS` > `CLEAN`; no seal is ever `CLEAN`.

Two judgment calls, both derived from the spec text: the sealing emitter's
declared head is its last record *before* `session.seal` (the seal's hash
covers `emitters[]`, so it cannot name itself); and the sealer writes no
`emitter.seal` — `emitter.seal` is the last record an emitter writes, and the
controller finishes with `session.seal` instead.

## Layout

`dsse.py` envelope/PAE · `strict.py` duplicate-key JSON · `schema.py` record
schemas · `keys.py` trusted manifests/validity · `mlog.py` RFC 6962 hashing
and inclusion/consistency proofs · `note.py` C2SP signed-note +
tlog-checkpoint · `bundle.py` tar reading · `verify.py` V1–V11 + V15 ·
`errors.py` structured codes.

## Checks

`make check-M1.5`: C1.5.1 import scan (stdlib + `cryptography` only), C1.5.3
no-Go-source scan, C1.5.4 RFC 6962/C2SP vectors, C1.5.5 61 spec-derived
bundle vectors covering every error code, warning and verdict. C1.5.2 (the
differential against `csverify` golden bundles) is reported `BLOCKED` until
the Go lane lands — the suite stays green and prints the block explicitly.

`make sabotage-M1.5` applies `py-skip-chain-check` (drops V5 chain
continuity); C1.5.5 catches it. `go-skip-seal-check` is the Go lane's patch
and is out of scope here.
