# M1.2 plan — Signing, keys, emitter chains

Files: `internal/keys/` (signer.go, manifest.go, emitter.go, ulid.go — no,
ULID lives in `internal/evidence` since it is record-format), tests;
`internal/evidence/chain.go` (per-emitter chain checker used by V5);
`test/checks/check-M1.2.sh`; `docs/keys.md`; sabotages in
`test/sabotage/M1.2/`.

Signer: Ed25519 only, PKCS8 PEM file back-end, KeyID = first16(sha256(pub)).
Manifest: keys.json read/write, roles emitter:* / log / attestor / reviewer /
reviewer:delegate / witness, validity window covers record ts.
Emitter: assigns eseq, chains eprev = SHA-256(PAE(prev)), signs, ULID instance
per process. VerifyRecord enforces role `emitter:<role>` + validity + sig.

Checks first: C1.2.1 key-id vector; C1.2.2 3×1000 interleaved chains;
C1.2.3 python cryptography verifies PAE sig; C1.2.4 role mismatch;
C1.2.5 restart → fresh chain + unsealed-by-emitter. First test: C1.2.1.
