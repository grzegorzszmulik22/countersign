# M1.4 plan — ledger storage, bundle, csverify

UTC: 2026-11-14T19:42:42Z

Spec: 03 §5 (layout), §7 (bundle), §10 (V1–V11, V15); milestone M1.4.
Denied: remote storage, concurrent writers, compaction/deletion, query
language.

## Build

`internal/ledger`:
- `storage.go` — Open(dir): log/entries.jsonl, log/hashes.bin (index-aligned
  32B leaves), log/checkpoints/<size>.txt, sessions/<session>.idx.
  Recovery: scan lines; a torn final line (no trailing \n or undecodable)
  is truncated on open — only the torn tail. Hashes.bin trimmed to match.
- `append.go` — single writer; `Append(line)` writes line+\n and the leaf
  hash, then blocks until a group-commit fsync covers it (fsync at most
  every 2 ms). Checkpoint issued on `session.seal` and `commit.closed`.
  Session index rows appended per record. No rewrite/truncate/overwrite
  API (C1.4.6 is a compile-time property plus O_APPEND opens).
- `bundle.go` — deterministic tar (sorted names, zeroed
  mtime/uid/gid/uname/gname): manifest.json, keys.json, records.jsonl,
  index.json ({log_index, inclusion_proof[]}), checkpoint.txt (smallest
  stored/generated checkpoint covering session.seal), plus caller-supplied
  policy.yaml / contracts/*.yaml / reviews/*.json / attestations/*.json.
  `created` = ts of the last session record → export is a pure function
  of ledger content (C1.4.2).
- `bundleread.go` — strict tar reader for the verifier: parses entries,
  enforces allowed names, yields lines + index + checkpoint.
- `verify.go` — V1–V11 + V15 producing {verdict, world, errors, warnings,
  findings, stats}; errors carry {code, index, detail}.

`cmd/csverify` — `csverify <bundle> --keys keys.json`, JSON output;
exit 0 only for CLEAN / CLEAN_WITH_DENIALS.

## Golden vectors

`tools/genvectors` writes `test/vectors/evidence/<name>.{tar,keys.json,expected.json}`:
clean-all-types, clean-with-denials, unsealed, dangling-effect,
multi-emitter, and one bundle per error code (E_BUNDLE, E_SCHEMA, E_SIG,
E_KEY, E_SESSION, E_CHAIN, E_CHECKPOINT, E_INCLUSION, E_OPEN, E_POLICY,
E_SEAL, E_STRUCTURE).

## Checks-first

- C1.4.1 helper process appends 10k records (concurrent writer goroutines),
  SIGKILL at random, 50 trials; every acknowledged record present and
  verifying; only the unacknowledged tail may be missing.
- C1.4.2 two exports of one session are byte-identical.
- C1.4.3 every golden bundle → exact verdict/errors/warnings.
- C1.4.4 csverify touches only bundle + --keys (run in empty dir, `env -i`,
  plus import scan for net/fs accesses). Container-isolation part
  SKIPPED-ENV (no containers on agent-vpc) — noted in progress.
- C1.4.5 keys.json that differs from the trusted manifest for a used key
  → E_KEY.
- C1.4.6 no mutation API: grep for exported setters + O_APPEND flag assert.
- C1.4.7 fuzz bundle reader 10 min: no panic; bad input → E_BUNDLE/E_SCHEMA.

## Sabotage

ack-before-fsync, seal-not-required-for-clean, skip-inclusion-check,
nondeterministic-tar.
