Upstream excerpt: C2SP signed-note (editor's copy)
Source: https://github.com/C2SP/C2SP/blob/main/signed-note.md
Fetched 2026-11-14. Used for: checkpoint signature format (spec 03 §6).

Format: a signed note is a text ending in newline (U+000A), followed by a
blank line, followed by signature lines:

    — <key name> base64(32-bit key ID || signature)

(em dash U+2014, space, key name, space, base64).

- The note text includes the final newline but not the separating blank line.
- Signed notes MUST be valid UTF-8, no ASCII control chars below U+0020 other
  than newline.
- Key names non-empty, no Unicode spaces or "+" (U+002B).
- Signature blob: first 4 bytes = uint32 key ID (big-endian), rest = signature.
- Verifiers MUST ignore signatures from unknown keys; if a known-key signature
  fails, reject the note; if no known-key signature verifies, reject.
- Recommended key ID = SHA-256(key name || 0x0A || signature type || public key)[:4]

Ed25519 (signature type 0x01): RFC 8032 signature over the note text.
    key ID = SHA-256(key name || 0x0A || 0x01 || 32-byte Ed25519 public key)[:4]

Verifier key (vkey): <key name>+hex(32-bit key ID)+base64(signature type || public key)

Published vector:
  vkey  example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k
  verifies note
    "This is an example message.\n"
  sig line: — example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=
