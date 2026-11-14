# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""C2SP signed-note parsing/verification and tlog-checkpoint bodies.

signed-note: text ending in newline, blank line, then signature lines
"— <key name> base64(32-bit key ID ‖ signature)". Ed25519 (type 0x01):
signature over the note text; key ID = SHA-256(name‖0x0A‖0x01‖pubkey)[:4].
tlog-checkpoint: body = origin, tree size (decimal), root hash (base64),
optional extension lines; Ed25519 log signatures use key name = log origin.
"""
import base64
import binascii
import hashlib
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import VerifyError

_EM = "—".encode()
_SIG_RE = re.compile(rb"^([^\s+]+) ([A-Za-z0-9+/]+={0,2})$")


def note_key_id(name, sig_type, pubkey):
    return int.from_bytes(
        hashlib.sha256(name + b"\x0a" + bytes([sig_type]) + pubkey)
        .digest()[:4], "big")


class Sig:
    __slots__ = ("name", "key_id", "sig")

    def __init__(self, name, key_id, sig):
        self.name = name
        self.key_id = key_id
        self.sig = sig


def parse(data):
    """Parse a signed note → (text: bytes, [Sig]). Enforces UTF-8, the
    no-control-characters rule, the last-empty-line separator and the
    signature-line shape; key IDs and sig bytes are decoded (canonical b64)."""
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise VerifyError("E_CHECKPOINT", "note is not UTF-8") from e
    for i, b in enumerate(data):
        if b < 0x20 and b != 0x0A:
            raise VerifyError("E_CHECKPOINT", f"note: control byte {b:#x} at {i}")
    sep = data.rfind(b"\n\n")
    if sep < 0:
        raise VerifyError("E_CHECKPOINT", "note: no signature separator")
    text = data[:sep + 1]
    rest = data[sep + 2:]
    if not rest or not rest.endswith(b"\n"):
        raise VerifyError("E_CHECKPOINT", "note: trailing signature garbage")
    sigs = []
    for line in rest[:-1].split(b"\n"):
        if not line.startswith(_EM + b" "):
            raise VerifyError("E_CHECKPOINT", "note: bad signature line")
        m = _SIG_RE.match(line[4:])
        if not m:
            raise VerifyError("E_CHECKPOINT", "note: malformed signature line")
        name, b64 = m.groups()
        try:
            blob = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError) as e:
            raise VerifyError("E_CHECKPOINT", "note: bad signature base64") from e
        if len(blob) < 5:
            raise VerifyError("E_CHECKPOINT", "note: signature too short")
        sigs.append(Sig(name, int.from_bytes(blob[:4], "big"), blob[4:]))
    if not sigs:
        raise VerifyError("E_CHECKPOINT", "note: zero signatures")
    if len(sigs) > 1024:
        raise VerifyError("E_CHECKPOINT", "note: too many signatures")
    return text, sigs


def verify_text(text, sigs, keytab):
    """Per signed-note.md: ignore unknown-key signatures; a failing signature
    from a known key rejects the note; at least one known key must verify.

    keytab: {signer-name (bytes): [(key_id:int, pubkey:bytes, role:str)]}.
    Returns the list of roles whose signatures verified, or None on reject."""
    verified = []
    known_bad = False
    for s in sigs:
        cands = [k for k in keytab.get(s.name, ()) if k[0] == s.key_id]
        if not cands:
            continue  # unknown key: ignore
        ok = False
        for _kid, pub, role in cands:
            try:
                Ed25519PublicKey.from_public_bytes(pub).verify(s.sig, text)
                verified.append(role)
                ok = True
            except (InvalidSignature, ValueError):
                continue
        if not ok:
            known_bad = True
    if known_bad or not verified:
        return None
    return verified


def parse_vkey(vkey):
    """"<key name>+hex(32-bit key ID)+base64(signature type ‖ public key)" →
    (name: bytes, key_id: int, key_material: bytes)."""
    parts = vkey.split("+")
    if len(parts) != 3:
        raise ValueError("vkey must have 3 '+'-separated parts")
    name, hexid, b64 = parts
    key_id = int(hexid, 16)
    km = base64.b64decode(b64)
    return name.encode(), key_id, km


def parse_checkpoint_body(text):
    """Checkpoint note text → (origin: bytes, size: int, root: bytes,
    extensions: [bytes])."""
    if not text.endswith(b"\n"):
        raise VerifyError("E_CHECKPOINT", "checkpoint: text lacks final newline")
    lines = text[:-1].split(b"\n")
    if len(lines) < 3 or not lines[0] or not lines[1] or not lines[2]:
        raise VerifyError("E_CHECKPOINT", "checkpoint: needs ≥3 non-empty lines")
    if not re.fullmatch(rb"0|[1-9][0-9]*", lines[1]):
        raise VerifyError("E_CHECKPOINT", "checkpoint: bad tree size")
    size = int(lines[1])
    try:
        root = base64.b64decode(lines[2], validate=True)
    except (binascii.Error, ValueError) as e:
        raise VerifyError("E_CHECKPOINT", "checkpoint: bad root base64") from e
    if len(root) != 32:
        raise VerifyError("E_CHECKPOINT", "checkpoint: root not 32 bytes")
    if any(not l for l in lines[3:]):
        raise VerifyError("E_CHECKPOINT", "checkpoint: empty extension line")
    return lines[0], size, root, lines[3:]
