# M1.3 plan — Merkle log and checkpoints

UTC: 2026-11-14T19:37:51Z

Spec: 03 §3 (leaf/node/record hashes), §5 (ledger layout), §6 (checkpoints
and proofs); milestone M1.3; denied: sparse/prefix trees, tile serving,
public log endpoints.

## Build

`internal/mlog`:

- `tree.go` — RFC 6962: `HashLeaf(0x00‖line)`, `HashNode(0x01‖l‖r)`, MTH
  over leaf hashes, append-only leaf list.
- `proof.go` — inclusion `PATH(index,D[n])` and consistency
  `SUBPROOF(m,D[n],b)` generation per RFC 6962 §2.1, plus standalone
  `VerifyInclusion`/`VerifyConsistency` used by the M1.4 verifier.
- `log.go` — `Log{origin, signer, leaves}`; `NewLog(origin, signer,
  manifest)` refuses a log key whose key ID is not a `log` role entry or
  collides with an `emitter:*`/`attestor` entry (C1.3.5).
- `checkpoint.go` — C2SP `tlog-checkpoint` in signed-note format:
  text = `origin\n<size>\n<base64 root>\n`, sig line
  `— <origin> <b64(keyhash4‖sig)>` where keyhash =
  sha256(origin‖"\n"‖0x01‖pub)[:4] (x/mod `note` compatible);
  `SignCheckpoint`/`ParseCheckpoint` — parse enforces the signer is a
  `log`-role manifest key that is no emitter/attestor key (V6).

## Deps added

- `golang.org/x/mod v0.42.0` (sumdb/note oracle for C1.3.3)
- `github.com/transparency-dev/merkle v0.0.2` (independent proof oracle
  for C1.3.1/C1.3.2)

## Checks-first

- C1.3.1 sizes 1..257 × all indices: our `VerifyInclusion` AND
  `proof.VerifyInclusion(rfc6962.DefaultHasher,…)` accept our proof.
- C1.3.2 all (m,n), m≤n≤64: both verifiers accept.
- C1.3.3 `note.Open` accepts our checkpoint; `note.Sign` output verifies
  with our `ParseCheckpoint`.
- C1.3.4 published vectors (crpt/go-merkle + RFC §2.1):
  `MTH({})=e3b0…`, leaf `""`=6e34…, leaf `"L123456"`=395a…,
  node `N123‖N456`=aa21… (excerpt saved).
- C1.3.5 `NewLog` refuses log key ID equal to an emitter key ID.

## Sabotage

- `leaf-prefix-missing` — drop 0x00 in HashLeaf.
- `checkpoint-signed-by-emitter-key-allowed` — drop the role check in
  ParseCheckpoint/NewLog.
- `proof-off-by-one-at-power-of-two` — boundary k computation off by one.
