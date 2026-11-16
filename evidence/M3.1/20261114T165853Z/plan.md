# Plan — M3.1 Policy schema and matcher

Scope (lane note): `SessionPolicy` fields of `04` §1 and the matcher of `04` §2
steps 1–2 only; `05` fields (autonomy, world, commit, budgets, tape, attest;
grant class/stager/compensate/tools/egress) rejected as unknown, additively.

Files to touch:
- `internal/policy/` — types, strict YAML load, validation, digest, matcher (new)
- `api/schema/sessionpolicy.schema.json` — JSON Schema (new)
- `ref/python/refreconcile/match.py` — ~60-line reference matcher (new)
- `test/vectors/policy/matching.yaml` + `invalid/*.yaml` — decision table ≥200 rows (expected column reasoned from spec), 20 invalid policies
- `test/checks/check-M3.1.sh`, `test/sabotage/M3.1/*.patch`, `docs/policy-schema.md`

Checks: C3.1.1 table 100%; C3.1.2 20 rejections naming fields; C3.1.3 digest
over file bytes; C3.1.4 Go-vs-Python property test; C3.1.5 10-min loader fuzz.
First test: decision-table Go test (fails until `internal/policy` exists).
