# M1.1 plan — Records and envelope

Files: `internal/evidence/` (envelope.go, statement.go, record.go, bodies.go,
strict.go + tests); `api/schema/` (one JSON Schema per record type + shared
`common.json` + envelope/statement); `test/checks/check-M1.1.sh`;
`docs/evidence-format.md`; sabotages in `test/sabotage/M1.1/`.

Types: `Record` = common predicate fields + `Body any` via a type registry
(34 types, 03 §4). Envelope = DSSE {payloadType, payload b64, signatures[1]}.
PAE per DSSE v1. Decode path: strict JSON scan (dup keys, UTF-8, escapes,
depth) then typed unmarshal with DisallowUnknownFields; body decoded through
the registry; v==1 enforced; canonical std base64 required; exactly one sig.

Checks first: C1.1.1 round-trip per type; C1.1.2 PAE upstream vector;
C1.1.3 nine rejection cases; C1.1.4 schema bijection via santhosh jsonschema;
C1.1.5 `go test -fuzz` 10m. First test: round-trip.
