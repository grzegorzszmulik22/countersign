# M5.2 plan (lane classify) — reversibility classes and autonomy

Scope per lane note: classifier + Python reference + policy schema additions +
decision table + C5.2.1..C5.2.4 at classifier level. NOT built: broker wiring
(internal/proxy, cmd/csbroker, internal/runner — lane broker2, M2.4), C5.2.5.

Files to touch:

- internal/policy/types.go — Spec.autonomy map; Grant class/stager/compensate/
  tools/calls fields.
- internal/policy/validate.go — validation: class enum (staged needs stager),
  stager exactly-one-of git|outbox (+ subfields), tools/calls only on
  inspect:mcp, autonomy keys=5 classes values allow|review|deny (intent
  rejected until M9), requires intent rejected, compensate subrules.
- internal/classify/classify.go — 05 §1 rules 1-10 (mirroring merged
  internal/reconcile semantics) + declared_safe flag + §2 condition
  (autonomy[class], grant requires, whenTainted on compensable/irreversible).
- ref/python/refclassify/ — fresh implementation of 05 §1-§2 from the spec.
- internal/evidence/bodies_effects.go — Decision.declared_safe field;
  regenerate api/schema/records/*.
- api/schema/sessionpolicy.schema.json — admit the new fields.
- test/vectors/policy/classes.yaml — >=250 rows + invalid-policy entries;
  expected column transcribed from 05 §1-§2 (test/gen/classes_table.py is an
  independent expression, like matching_table.py; output reviewed by reading).
- test/vectors/policy/invalid/{06,11} — repoint at genuinely-invalid policies
  (autonomy intent; unknown stager type).
- internal/classify/*_test.go — table test, 10k differential vs refclassify,
  C5.2.2/2.3/2.4 assertions.
- test/checks/check-M5.2.sh, test/sabotage/M5.2/*.patch.
- docs/policy-schema.md — one-page update.

Checks expected: C5.2.1 (table 100% + 10,000 differential), C5.2.2 (no-rule ->
irreversible; unknown stager / staged-without-stager rejected), C5.2.3 (>=20
strictest-wins rows), C5.2.4 (declared_safe recorded + survives round trip).
C5.2.5 reports BLOCKED (needs merged M2.4). First test: classes.yaml rows for
rule order.
