# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""Bundle archive reading (spec 03 §7). A bundle is a tar of regular files;
required members, allowed names, no extras — violations are E_BUNDLE."""
import io
import tarfile

from .errors import VerifyError

REQUIRED = {"manifest.json", "keys.json", "records.jsonl", "index.json",
            "checkpoint.txt"}
ALLOWED = REQUIRED | {"policy.yaml", "cosignatures.txt"}
PREFIXES = ("contracts/", "reviews/", "attestations/")

MAX_MEMBERS = 10000
MAX_BYTES = 512 * 1024 * 1024


def _name_ok(n):
    if not n or n.startswith("/") or ".." in n.split("/") or "\\" in n:
        return False
    if n in ALLOWED:
        return True
    return any(n.startswith(p) and len(n) > len(p) for p in PREFIXES)


def read(path):
    """Read a bundle tar → {member: bytes}. Raises VerifyError E_BUNDLE on any
    malformation: unreadable archive, non-regular members, unsafe or unknown
    names, missing required members, oversized payloads."""
    try:
        tf = tarfile.open(path, "r:*")
    except (tarfile.TarError, OSError, EOFError, ValueError) as e:
        raise VerifyError("E_BUNDLE", f"not a readable tar archive: {e}")
    files = {}
    total = 0
    try:
        members = tf.getmembers()
        if len(members) > MAX_MEMBERS:
            raise VerifyError("E_BUNDLE", f"more than {MAX_MEMBERS} members")
        for m in members:
            if not (m.isreg()):
                raise VerifyError("E_BUNDLE",
                                  f"member {m.name!r} is not a regular file",
                                  entry=m.name)
            if not _name_ok(m.name):
                raise VerifyError("E_BUNDLE",
                                  f"member name {m.name!r} not allowed",
                                  entry=m.name)
            if m.name in files:
                raise VerifyError("E_BUNDLE", f"duplicate member {m.name!r}",
                                  entry=m.name)
            total += m.size
            if total > MAX_BYTES:
                raise VerifyError("E_BUNDLE", "archive too large")
            f = tf.extractfile(m)
            data = f.read(m.size + 1) if f else b""
            if len(data) != m.size:
                raise VerifyError("E_BUNDLE", f"short read on {m.name!r}",
                                  entry=m.name)
            files[m.name] = data
    finally:
        tf.close()
    missing = sorted(REQUIRED - set(files))
    if missing:
        raise VerifyError("E_BUNDLE", f"missing required members: {missing}")
    return files


def records_lines(data):
    """records.jsonl bytes → list of stored line bytes (sans newline)."""
    if not data:
        return []
    if not data.endswith(b"\n"):
        raise VerifyError("E_BUNDLE", "records.jsonl lacks trailing newline")
    lines = data[:-1].split(b"\n")
    if any(b"\r" in l or not l for l in lines):
        raise VerifyError("E_BUNDLE", "records.jsonl: empty or CR line")
    return lines
