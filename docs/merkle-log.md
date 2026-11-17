# Merkle log and checkpoints (M1.3)

`internal/mlog` is the append-only log of 03 §5–§6. RFC 6962 only — no
sparse or prefix trees, no tile serving, no public endpoints (denied list).

- **Hashing** — `HashLeaf(line) = SHA-256(0x00‖line)` over the *stored* line
  bytes exactly as appended (no added newline); `HashNode = SHA-256(0x01‖l‖r)`;
  `Root()` is MTH(D[n]) with `MTH({}) = SHA-256("")`. Pinned against the
  published vectors in C1.3.4.
- **Proofs** — `InclusionProof(i)` returns PATH(i, D[n]);
  `ConsistencyProof(m,n)` returns SUBPROOF(m, D[n], true). `VerifyInclusion`
  and `VerifyConsistency` are the standalone verifiers the M1.4 verifier
  uses. Both proof directions are cross-checked against the independent
  `transparency-dev/merkle` library for every size ≤ 257 (C1.3.1, C1.3.2).
- **Checkpoint** — C2SP `tlog-checkpoint` as a signed note:
  `origin\n<size>\n<base64 root>\n` followed by a blank line and
  `— <origin> <base64(keyhash4‖sig)>`; keyhash =
  `SHA-256(origin‖"\n"‖0x01‖pub)[:4]` so it is byte-compatible with
  `golang.org/x/mod/sumdb/note` in both directions (C1.3.3).
- **Log key** — a dedicated `log`-role key, never an emitter or attestor
  key; `ParseCheckpoint` enforces this at verify time (V6, C1.3.5).

Checks: C1.3.1–C1.3.5 above. Sabotage: `leaf-prefix-missing`,
`checkpoint-signed-by-emitter-key-allowed`, `proof-off-by-one-at-power-of-two`.
