# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""Bundle archive reading per spec 03 §7 and V1 of §10.

The reader is a byte-level tar scan so that declared sizes, member types,
trailing garbage and the member-set rules are checked exactly, without
allocating more than the input could legitimately contain.
"""
import base64
import binascii

from . import schema
from .strict import (SchemaError, _gchar, _quote, go_parse_first, go_typed)

REQUIRED = ("manifest.json", "keys.json", "records.jsonl", "index.json",
            "checkpoint.txt")
_OPTIONAL_PREFIX = ("contracts/", "reviews/", "attestations/")
_OPTIONAL_EXACT = ("policy.yaml", "cosignatures.txt")

MAX_MEMBER = 256 << 20
MAX_TOTAL = 1 << 30
MAX_MEMBERS = 4096


class BundleError(Exception):
    """E_BUNDLE-class failure; message is the verifier detail."""


def _optional(name):
    if name in _OPTIONAL_EXACT:
        return True
    return any(name.startswith(p) and len(name) > len(p)
               for p in _OPTIONAL_PREFIX)


def _hdr_field(b, lo, hi):
    f = b[lo:hi]
    z = f.find(b"\0")
    if z >= 0:
        f = f[:z]
    return f


def _parse_size(field):
    """Tar size field: octal ASCII or base-256 (GNU binary)."""
    if not field:
        return 0
    if field[0] & 0x80:
        # base-256
        v = int.from_bytes(field, "big", signed=False) & ((1 << 63) - 1)
        if field[0] == 0x80:
            v = int.from_bytes(field[1:], "big")
        elif field[0] == 0xFF:
            v = -int.from_bytes(
                bytes(b ^ 0xFF for b in field[1:]), "big") - 1
        return v
    s = field.split(b"\0")[0].strip()
    if not s or not all(c in b"01234567" for c in s):
        raise BundleError("malformed archive: archive/tar: invalid tar header")
    v = 0
    for c in s:
        v = (v << 3) | (c - 0x30)
    return v


def _read_pax(data):
    """Minimal ustar/pax header parsing: returns (name, size_override)."""
    name = None
    size = None
    i = 0
    while i < len(data):
        j = data.find(b" ", i)
        if j < 0:
            break
        try:
            ln = int(data[i:j])
        except ValueError:
            break
        if ln <= 0 or i + ln > len(data):
            break
        rec = data[j + 1:i + ln - 1]
        k, _, v = rec.partition(b"=")
        if k == b"path":
            name = v
        elif k == b"size":
            try:
                size = int(v)
            except ValueError:
                pass
        i += ln
    return name, size


def read_bundle(data):
    """Tar bytes → {member name str: bytes}. Raises BundleError."""
    if not data:
        raise BundleError("empty bundle")
    members = {}
    order = []
    total = 0
    pos = 0
    n = len(data)
    pend_name = None
    pend_size = None
    while True:
        if pos + 512 > n:
            # Go's reader hits EOF mid-header.
            raise BundleError("malformed archive: unexpected EOF")
        blk = data[pos:pos + 512]
        pos += 512
        if blk == b"\0" * 512:
            break  # end-of-archive marker
        # checksum verify
        try:
            stored = int(blk[148:156].split(b"\0")[0].strip() or b"0", 8)
        except ValueError:
            raise BundleError(
                "malformed archive: archive/tar: invalid tar header")
        chk = sum(blk[:148]) + 8 * 0x20 + sum(blk[156:512])
        if chk != stored:
            raise BundleError(
                "malformed archive: archive/tar: invalid tar header")
        name = _hdr_field(blk, 0, 100)
        size = _parse_size(blk[124:136])
        tflag = blk[156]
        # ustar prefix
        if blk[257:262] == b"ustar":
            pre = _hdr_field(blk, 345, 500)
            if pre:
                name = pre + b"/" + name
        # extension headers: consume their data, then continue
        if tflag in (0x78, 0x67, 0x4C, 0x4B):  # x g L K
            nb = (size + 511) // 512 * 512
            if pos + nb > n:
                raise BundleError("malformed archive: unexpected EOF")
            ext = data[pos:pos + size]
            pos += nb
            if tflag in (0x78, 0x67):
                pend_name, pend_size = _read_pax(ext)
            elif tflag == 0x4C:
                pend_name = ext.split(b"\0")[0]
            continue
        if pend_name is not None:
            name = pend_name
            pend_name = None
        if pend_size is not None:
            size = pend_size
            pend_size = None
        try:
            sname = name.decode("utf-8")
        except UnicodeDecodeError:
            sname = name.decode("utf-8", "replace")
        if len(order) >= MAX_MEMBERS:
            raise BundleError("more than %d members" % MAX_MEMBERS)
        if tflag not in (0x30, 0x00):
            raise BundleError(
                "member %s is not a regular file" % _quote(sname))
        if sname in members:
            raise BundleError("duplicate member %s" % _quote(sname))
        if size < 0:
            raise BundleError(
                "member %s: negative size %d" % (_quote(sname), size))
        if size > MAX_MEMBER:
            raise BundleError(
                "member %s: size %d exceeds %d-byte limit"
                % (_quote(sname), size, MAX_MEMBER))
        remaining = n - pos
        if size > remaining:
            raise BundleError(
                "member %s: declared size %d exceeds %d bytes remaining"
                % (_quote(sname), size, remaining))
        if total + size > MAX_TOTAL:
            raise BundleError(
                "members exceed %d-byte total limit" % MAX_TOTAL)
        nb = (size + 511) // 512 * 512
        members[sname] = data[pos:pos + size]
        total += size
        pos += nb
        order.append(sname)
    consumed = pos
    for b in data[consumed:]:
        if b != 0:
            raise BundleError("trailing garbage after end of archive")
    for req in REQUIRED:
        if req not in members:
            raise BundleError("missing required member %s" % _quote(req))
    for name in order:
        if name not in REQUIRED and not _optional(name):
            raise BundleError("unexpected member %s" % _quote(name))
    parse_manifest(members["manifest.json"])
    return members


def _syntax_err(data, what):
    """encoding/json decode of one value + the strictJSON trailing check."""
    try:
        node, end = go_parse_first(data)
    except SchemaError as e:
        raise BundleError("%s: %s" % (what, e))
    i = end
    while i < len(data) and data[i] in b" \t\n\r":
        i += 1
    if end < len(data) and data[end] not in b" \t\n\r":
        raise BundleError("%s: invalid character %s after top-level value"
                          % (what, _gchar(data[end])))
    if i < len(data):
        raise BundleError("%s: trailing JSON" % what)
    return node


def parse_manifest(data):
    """manifest.json → dict; strict decode + required fields."""
    node = _syntax_err(data, "manifest.json")
    try:
        m = go_typed(node, schema.BUNDLE_MANIFEST)
    except SchemaError as e:
        raise BundleError("manifest.json: %s" % e)
    if (m["bundle_version"] != 1 or not m["session"] or
            not m["log_origin"] or not m["created"]):
        raise BundleError("manifest.json missing required fields")
    return m


def parse_index(data):
    """index.json → list of {log_index, proof(bytes[])}."""
    node = _syntax_err(data, "index.json")
    try:
        ix = go_typed(node, schema.INDEX)
    except SchemaError as e:
        raise BundleError("index.json: %s" % e)
    ix = ix or []
    out = []
    for e in ix:
        proofs = []
        for p in e["inclusion_proof"] or []:
            try:
                b = base64.b64decode(p.encode("ascii"), validate=True)
            except (binascii.Error, ValueError, UnicodeEncodeError):
                raise BundleError(
                    "index.json: proof node not 32-byte base64")
            if len(b) != 32:
                raise BundleError("index.json: proof node not 32-byte base64")
            proofs.append(b)
        out.append({"log_index": e["log_index"], "proof": proofs})
    return out
