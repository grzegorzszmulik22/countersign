# M1. Evidence core

**Goal.** The record format, signing, emitter chains, Merkle log, bundle, and two independent verifiers. A pure library plus CLIs; no network, no Kubernetes.

**Properties advanced.** P6 (tamper evidence). Foundation of P3.

**Normative reference.** `03-evidence-format.md` in full.

**Expected results.**
- Any of 1,000+ seeded mutations of a valid bundle is rejected by both verifiers with the same error class (H4).
- 200 randomly generated valid bundles all verify.
- Checkpoints and proofs are accepted by independent third-party libraries.

**Measurements [T].**

| ID | Metric | Target |
|---|---|---|
| MM1.1 | Go verification throughput, signatures included, per CPU-second of one core | ≥ 50% of the same core’s raw Ed25519 verification rate, calibrated in the same run (CR-002) |
| MM1.2 | Durable append throughput, single writer, group commit, per CPU-second of the writer | ≥ 5,000 records per CPU-second, and ≤ 1 fsync per 10 records (CR-002) |
| MM1.3 | Append latency at 1,000 appends/s, on runs with 1-minute load ≤ core count | p99 ≤ the same disk’s fsync p99 + 5 ms, calibrated in the same run, absolute p99 recorded; `not judged: host contended` if no run qualifies, open for G1 (CR-002, CR-003) |
| MM1.4 | Mutants detected / generated; verifier agreement | 100% / ≥ 1,000; 100% |
| MM1.5 | Median stored size per record | reported (no target) |

**Milestone-wide denied.** CBOR/COSE encodings (export comes in M14.5). Tile-based log storage. Witness cosigning implementation. Any database. Compression of ledger files. Key rotation mechanics beyond validity windows in the manifest. Encryption of the ledger.

---

## M1.1 Records and envelope

**Build.** `internal/evidence`: Go types for every record in `03` §4; JSON Schemas in `api/schema/`; DSSE envelope encode/decode; PAE; in-toto statement wrapper; strict decoding (unknown fields rejected, duplicate JSON keys rejected, non-UTF-8 rejected).

**Checks.**
- C1.1.1 Round trip: for every record type, encode → decode → encode yields identical bytes.
- C1.1.2 PAE matches the DSSE specification's published test vector (save the upstream excerpt).
- C1.1.3 Decoder rejects: unknown predicate field, unknown body field, unknown `type`, duplicate key, wrong `_type`, wrong `predicateType`, two signatures, zero signatures, non-canonical base64. One test each.
- C1.1.4 Every Go record type validates against its JSON Schema and every schema has a Go type (bijection test).
- C1.1.5 Go native fuzzing of the envelope decoder for 10 minutes: no panic, no accepted input that fails re-encoding.

**Sabotage.** `accept-unknown-fields`; `pae-wrong-length` (off-by-one in a length); `allow-two-signatures`.

**Denied.** Optional fields "for future use". A generic key-value extension map.

## M1.2 Signing, keys, emitter chains

**Build.** `internal/keys`: `Signer` interface, file-backed Ed25519 implementation, key-ID derivation, key manifest read/write with roles and validity. Emitter object that assigns `eseq`, computes `eprev`, signs. Record hash per `03` §3.

**Checks.**
- C1.2.1 Key ID equals the first 16 bytes of SHA-256 of the public key, checked against a hand-computed vector.
- C1.2.2 A chain of 1,000 records per emitter, three emitters interleaved in one session: every `eprev` verifies; `eseq` gap-free.
- C1.2.3 Signature verifies with an independent Ed25519 implementation (the Python `cryptography` library) over the PAE bytes.
- C1.2.4 A signer whose role in the manifest does not match the record's emitter role is rejected at verification.
- C1.2.5 An emitter restarted mid-session gets a new instance ID and starts a fresh chain at `eseq` 0; the old chain is reported unsealed-by-emitter.

**Sabotage.** `eprev-uses-payload-only` (hash the payload instead of the PAE); `eseq-reuse-after-error`; `skip-role-check`.

**Denied.** Other signature algorithms. Certificates or any public-key infrastructure. Threshold or multi-party signing.

## M1.3 Merkle log and checkpoints

**Build.** `internal/mlog`: RFC 6962 leaf and node hashing, root computation, inclusion and consistency proofs, C2SP checkpoint in signed-note format, log key separate from emitter keys.

**Checks.**
- C1.3.1 For every tree size 1…257 and every leaf index: the inclusion proof verifies with our verifier **and** with an independent Go library (`06` §8).
- C1.3.2 Consistency proofs for every pair of sizes up to 64 verify with both.
- C1.3.3 Our checkpoints verify with `golang.org/x/mod/sumdb/note`; a checkpoint produced by that package verifies with ours.
- C1.3.4 Root for the RFC 6962 reference inputs matches published values (save the excerpt).
- C1.3.5 Constructing a log whose log key ID equals an emitter key ID is refused.

**Sabotage.** `leaf-prefix-missing` (omit the 0x00 prefix); `checkpoint-signed-by-emitter-key-allowed`; `proof-off-by-one-at-power-of-two`.

**Denied.** Sparse or prefix trees. Tile serving. Public log endpoints.

## M1.4 Ledger storage, bundle, `csverify`

**Build.** `internal/ledger`: the layout of `03` §5; single-writer append with group commit; crash recovery (a torn final line is detected and truncated on open, and only then); checkpoint issuance; session index; deterministic bundle export. `cmd/csverify` implementing V1–V11 and V15 of `03` §10 (V12–V13 arrive in M6, V14 in M13, V16 in M9) with JSON output and exit codes.

**Checks.**
- C1.4.1 Append returns only after the record is on disk: kill the process (`SIGKILL`) at random points during 10,000 appends, 50 trials; after recovery every acknowledged record is present and verifies, and at most the unacknowledged tail is missing.
- C1.4.2 Exporting the same session twice yields byte-identical bundles.
- C1.4.3 Golden bundles in `test/vectors/evidence/` (one clean with all record types, one with denials, one unsealed, one with a dangling effect, one multi-emitter, one per error code of `03` §10) produce exactly the expected verdict, error list and warning list.
- C1.4.4 `csverify` uses only the bundle and `--keys`; it runs with no network and no access to the ledger directory (verified in an empty container).
- C1.4.5 A bundle whose `keys.json` differs from the trusted manifest for a used key → `E_KEY`.
- C1.4.6 Ledger files are opened append-only; an attempt in tests to rewrite a line through the package API does not compile or returns an error (no such API exists).
- C1.4.7 Fuzz the bundle reader for 10 minutes: never panics; arbitrary input yields `E_BUNDLE` or `E_SCHEMA`.

**Sabotage.** `ack-before-fsync`; `seal-not-required-for-clean` (verdict `CLEAN` without a seal); `skip-inclusion-check`; `nondeterministic-tar` (real mtimes).

**Denied.** Remote storage. Concurrent writers. Log compaction or deletion. A query language over the ledger.

## M1.5 Python reference verifier

**Build.** `ref/python/refverify`: V1–V11 and V15 written **from `03` alone**, not ported from the Go code. Standard library plus `cryptography`. Same JSON output schema.

**Checks.**
- C1.5.1 Import scan: only standard-library modules and `cryptography`.
- C1.5.2 Every golden bundle: verdict, set of error codes and set of warning codes identical to `csverify`.
- C1.5.3 No file under `ref/python/` is generated from, or reads, Go sources (scan).
- C1.5.4 Merkle and signed-note code in Python passes the same RFC and C2SP vectors as C1.3.3–C1.3.4.

**Sabotage.** (applied to the Python code) `py-skip-chain-check`; (applied to Go) `go-skip-seal-check`. Each must make the differential test C1.6.2 fail, proving the differential is live in both directions.

**Denied.** Performance work on the reference. Sharing test helpers that compute expected results between the two implementations.

## M1.6 Mutation suite and measurements

**Build.** A seeded generator of valid bundles (random record mixes, 1–3 emitters, 5–500 records) and a mutator implementing the nine classes and the directed extras of `03` §11.

**Checks.**
- C1.6.1 200 generated valid bundles: both verifiers return a `CLEAN`-class verdict.
- C1.6.2 ≥ 1,000 mutants, at least 100 per class, fixed seed: both verifiers reject each one; error class identical between the two; class 5 never yields `CLEAN*`.
- C1.6.3 Measurements MM1.1–MM1.5 recorded per `06` §12 and meeting targets as restated by CR-002 and CR-003 (the Ed25519 calibration, the fsync calibration and the per-second load samples recorded with them; MM1.3 may be `not judged: host contended`, never dropped).

**Sabotage.** `mutator-noop-class-5` (the mutator silently produces unmodified bundles for one class; the suite must notice that mutants equal their originals and fail).

**Denied.** Counting a mutant as "detected" on verdict alone without checking the error class is in the expected set.

---

## Exit: human gate G1

Freeze `test/vectors/evidence/**`. The reviewer is asked specifically: is anything in `03` §4 missing that M2–M14 will need? Adding a record type after this gate costs a format version bump.
