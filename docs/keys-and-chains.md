# Keys, signing, and emitter chains (M1.2)

`internal/keys` holds everything that touches a private key.

- **Signer** — the only private-key interface (`KeyID`, `Public`, `Sign`).
  Implemented by a file-backed Ed25519 signer (`NewSigner` from a 32-byte
  seed; `SaveSigner`/`LoadSigner` as PKCS8 PEM, mode 0600). Ed25519 only —
  no other algorithms, no certificates, no threshold signing (denied list).
- **Key ID** — first 16 bytes of SHA-256 of the raw 32-byte public key,
  lowercase hex (03 §7). Checked against a hand-computed vector in C1.2.1.
- **Manifest** — `keys.json`, a JSON array of
  `{key_id, role, public_key, not_before, not_after?, rp_id?, origins?}`.
  `public_key` is standard base64 of the raw key. Roles: `log`, `attestor`,
  `reviewer`, `reviewer:delegate`, `witness`, and `emitter:<role>` for
  `broker|controller|world|observer`. Validity is `[not_before, not_after]`
  over the record's `ts`.
- **Emitter** — `NewEmitter(role, session, signer)` mints a fresh instance
  ULID and starts a chain at `eseq=0`, `eprev=64 zeros`. `Emit` builds the
  record, signs `PAE(payloadType, statement)`, and returns the canonical
  stored-line bytes (the ledger adds the newline). After `emitter.seal` the
  emitter refuses further records. A restart = new instance ULID = fresh
  chain; the old chain stays *unsealed-by-emitter* until proven otherwise.
- **ChainChecker** (`internal/evidence`) — replays records in log order and
  enforces per-emitter `eseq` gap-freedom and `eprev = record_hash(prev)`
  where `record_hash = SHA-256(PAE)` (03 §3). Reports one `ChainHead` per
  emitter with `sealed_by_emitter`.
- **VerifyRecord** — V3: key must exist in the manifest, its role must be
  exactly `emitter:<emitter role>` (an `emitter:world` key cannot sign
  `broker/…` records; a `log` key cannot sign emitter records), the record's
  `ts` must fall in the key's validity window, then `ed25519.Verify` over
  the PAE. Errors are classed `E_KEY` / `E_SIG` / `E_CHAIN` for the M1.4
  verifier to map to exit codes.

Checks: C1.2.1 key-ID vector · C1.2.2 three emitters × 1000 records,
interleaved · C1.2.3 the Python `cryptography` library independently verifies
the PAE signature (and rejects a flipped bit) · C1.2.4 role/validity/unknown
key rejection · C1.2.5 restart semantics.
