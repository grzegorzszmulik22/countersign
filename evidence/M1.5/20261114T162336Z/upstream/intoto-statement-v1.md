Upstream excerpt: in-toto Attestation Statement layer v1
Source: https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
Fetched 2026-11-14. Used for: Statement field names (spec 03 §1).

{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "<NAME>", "digest": {"<ALGORITHM>": "<HEX_VALUE>"} }, ...
  ],
  "predicateType": "<URI>",
  "predicate": { ... }
}

Fields:
  _type         string, required, always "https://in-toto.io/Statement/v1"
  subject       array of ResourceDescriptor, required; each MUST have digest
  predicateType string (TypeURI), required
  predicate     object, optional (unset == empty)

Matches spec 03 §1: _type, subject[{name,digest.sha256}], predicateType,
predicate.
