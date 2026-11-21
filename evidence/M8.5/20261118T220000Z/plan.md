# M8.5 plan — privacy and redaction

Files to touch:
- `internal/inspect/preview.go`: InputPreview — creds.RedactNamed over the
  original input bytes, then truncate to <= 256 bytes on a UTF-8 boundary;
  digest and length always describe the original bytes; previews disabled
  omits the field entirely.
- `internal/creds/detect.go`: exported RedactNamed emitting
  [REDACTED:<shape>] using the existing shape table.
- `internal/proxy/inspect_hook.go`: privacy.previews policy switch wired
  into intent.declared bodies.
- `test/vectors/transcripts/anthropic/cred-input-sse`: a credential-shaped
  input whose token straddles the 256-byte cap, so redact-then-truncate vs
  truncate-then-redact are observably different; markers for the ledger
  scan.
- `test/checks/check-M8.5.sh`, `test/sabotage/M8.5/*.patch`.

Checks expected: C8.5.1 (each shape → [REDACTED:<shape>], digest of the
original), C8.5.2 (previews off → no field), C8.5.3 (UTF-8 boundary, cap),
C8.5.4 (whole-ledger scan: zero canaries, zero markers). First test:
InputPreview on the cred vector — redacted marker present, canary absent.
