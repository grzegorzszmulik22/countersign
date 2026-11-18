# Offline reconciliation — `csverify --reconcile` and `csverify explain`

Step **V16** of `csverify` recomputes every effect's attribution and
decision from the evidence records and the bundled `policy.yaml`
(spec/04 §6.5). The broker's recorded `attribution` and `decision`
fields are inputs to be checked, never trusted.

```
csverify <bundle.tar> --keys keys.json [--reconcile]
csverify explain <bundle.tar> --keys keys.json <effect_id>
```

`--reconcile` appends reconciliation findings (`F_*`) to the result and
merges the verdict per the lattice of spec/03 §10: `INVALID`, `UNSEALED`
and `LEARN` are preserved; a clean bundle with error findings becomes
`VIOLATIONS`; a clean bundle with recomputed denials is
`CLEAN_WITH_DENIALS`.

`explain` prints, for one `effect_id`, the recorded claims next to the
recomputed values (level, intents, grant, class, condition, action,
reason, would_deny) plus any findings for that effect.

## Real-record adaptation (`internal/reconcile/bundle.go`)

Real evidence differs from the abstract trace form; the adapter bridges:

- `request.query_sha256`/`query_len` become digested queries —
  expectation comparison is digest-with-digest, never digest-as-literal.
- `intent.declared` carries `input_sha256`/`input_len` and an optional
  `input_preview`; the preview is used as the input only when its
  canonical (RFC 8785) digest equals `input_sha256`.
- `decision.would_deny` is a reason string in real records; it is
  normalized to the abstract `{action, reason}` object.
- On grant-resolution denies (`NO_GRANT`, `DENY_GRANT`,
  `SMUGGLING_SUSPECT`) no class or condition is evaluated, so the
  non-nullable `class`/`requires` placeholders carry no claim.
- `effect.tunnel` claims only its decision block (no class/attribution
  fields exist on that record type).

## Abstract-trace drivers (used by check-M9.2)

```
csverify reconcile-trace  FILE [--packs DIR]   # one trace.meta+records file
csverify reconcile-batch  FILE [--packs DIR]   # JSONL {"meta","records"} lines
csverify reconcile-corpus DIR  [--packs DIR]   # every *.jsonl, diff vs meta.expect
```

Packs default to the rule packs embedded in the binary
(`internal/reconcile/packs`, via `go:embed`); `--packs` overrides for
testing. The Go engine shares no code or generated tables with the
frozen Python reference (`ref/python/refreconcile`, M9.1).
