Upstream excerpt: C2SP tlog-checkpoint (editor's copy)
Source: https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md
Fetched 2026-11-14. Used for: checkpoint body format (spec 03 §6).

The note text of a checkpoint is a sequence of at least three non-empty lines:
 1. the log's origin
 2. tree size as ASCII decimal (no leading zeros; "0" for zero)
 3. root hash, base64 of the RFC 6962 Merkle tree root at that size
 4. optional non-empty extension lines (not recommended)

Then an empty line and one or more signature lines.

Ed25519 Log Signatures: signature over the note text with Ed25519
(signature type 0x01, no timestamp). "The key name SHOULD be the log origin."
    key ID = SHA-256(<origin> || "\n" || 0x01 || 32-byte pubkey)[:4]

MUST NOT have multiple signature lines with both same key name and same key id.

Consequence for refverify: the log key's note name is the checkpoint origin
(manifest.log_origin, e.g. "countersign.dev/log/<log ID>").
