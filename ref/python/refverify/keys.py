# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""Trusted key manifest (spec 03 §7 keys.json): entries carry
key_id, role, public_key, not_before, not_after? plus reviewer metadata.
key_id = first 16 bytes of SHA-256 of the raw public key, lowercase hex.
"""
import hashlib

from .errors import VerifyError
from . import strict

ROLES = {"emitter:broker", "emitter:controller", "emitter:world",
         "emitter:observer", "log", "attestor", "reviewer",
         "reviewer:delegate", "witness"}


def key_id_of(pub):
    return hashlib.sha256(pub).digest()[:16].hex()


def _decode_pub(v, i):
    """public_key: standard base64 (preferred) or 64-hex of the raw 32 bytes."""
    if isinstance(v, str):
        try:
            raw = strict.b64d(v, "manifest public_key")
            if len(raw) == 32:
                return raw
        except VerifyError:
            pass
        if strict.is_hex(v, 64):
            return bytes.fromhex(v)
    raise VerifyError("E_KEY", f"keys.json[{i}]: public_key not a 32-byte key")


class KeyEntry:
    __slots__ = ("key_id", "role", "pub", "not_before", "not_after", "extra")

    def __init__(self, key_id, role, pub, not_before, not_after, extra):
        self.key_id = key_id
        self.role = role
        self.pub = pub
        self.not_before = not_before      # (sec, nanos)
        self.not_after = not_after        # (sec, nanos) or None
        self.extra = extra                # reviewer metadata (rp_id, origins)

    def covers(self, ts):
        if self.not_before and ts < self.not_before:
            return False
        return not (self.not_after and ts > self.not_after)

    def same_as(self, other):
        """Semantic equality for the bundle-vs-trusted comparison."""
        return (self.key_id == other.key_id and self.role == other.role and
                self.pub == other.pub and self.not_before == other.not_before
                and self.not_after == other.not_after)


def parse_manifest(obj, what="keys.json"):
    """Validate a manifest array → {key_id: KeyEntry}. Malformed entries are
    E_KEY; a duplicated key_id or a key_id that is not the hash of its public
    key is E_KEY."""
    if not isinstance(obj, list):
        raise VerifyError("E_KEY", f"{what}: not an array")
    keys = {}
    for i, e in enumerate(obj):
        if not isinstance(e, dict):
            raise VerifyError("E_KEY", f"{what}[{i}]: not an object")
        allowed = {"key_id", "role", "public_key", "not_before", "not_after",
                   "rp_id", "origins"}
        unknown = set(e) - allowed
        if unknown:
            raise VerifyError("E_KEY", f"{what}[{i}]: unknown fields {sorted(unknown)}")
        for req in ("key_id", "role", "public_key", "not_before"):
            if req not in e:
                raise VerifyError("E_KEY", f"{what}[{i}]: missing {req}")
        kid = e["key_id"]
        strict.check_hex(kid, 32, f"{what}[{i}].key_id")
        if kid in keys:
            raise VerifyError("E_KEY", f"{what}[{i}]: duplicate key_id {kid}")
        role = e["role"]
        if role not in ROLES:
            raise VerifyError("E_KEY", f"{what}[{i}]: unknown role {role!r}")
        pub = _decode_pub(e["public_key"], i)
        if key_id_of(pub) != kid:
            raise VerifyError("E_KEY",
                              f"{what}[{i}]: key_id is not SHA-256(pub)[:16]")
        nb = strict.parse_ts(e["not_before"], f"{what}[{i}].not_before")
        na = None
        if e.get("not_after") is not None:
            na = strict.parse_ts(e["not_after"], f"{what}[{i}].not_after")
        extra = {k: e[k] for k in ("rp_id", "origins") if k in e}
        keys[kid] = KeyEntry(kid, role, pub, nb, na, extra)
    return keys
