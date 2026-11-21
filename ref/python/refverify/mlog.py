# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""RFC 6962 Merkle tree hashing and inclusion-proof verification.

MTH per RFC 6962 §2.1; proof verification per the inner/border decomposition
(equivalent to RFC 9162 §2.1.3.2). ``inclusion_error`` carries the reference
verifier's rejection diagnostics verbatim.
"""
import hashlib


def _h(b):
    return hashlib.sha256(b).digest()


def leaf_hash(data):
    """SHA-256(0x00 ‖ data) — data is the stored line without its newline."""
    return _h(b"\x00" + data)


def node_hash(left, right):
    """SHA-256(0x01 ‖ left ‖ right)."""
    return _h(b"\x01" + left + right)


def mth(leaf_hashes):
    """Merkle Tree Hash over a list of *leaf hashes* (already 0x00-hashed)."""
    n = len(leaf_hashes)
    if n == 0:
        return _h(b"")
    if n == 1:
        return leaf_hashes[0]
    k = 1 << (n.bit_length() - 1)
    if k == n:
        k >>= 1
    return node_hash(mth(leaf_hashes[:k]), mth(leaf_hashes[k:]))


def verify_inclusion(leaf, leaf_index, tree_size, proof, root):
    """Prove ``leaf`` (a 32-byte leaf hash) is at ``leaf_index`` in the tree
    of ``tree_size`` with ``root``. Boolean form used by RFC-vector tests."""
    return inclusion_error(leaf_index, tree_size, leaf, proof, root) is None


def _decomp(index, size):
    inner = (index ^ (size - 1)).bit_length()
    return inner, bin(index >> inner).count("1")


def root_from_inclusion(index, size, leaf, proof):
    """Fold an audit path to a candidate root, or raise ValueError."""
    if size == 0 or index >= size:
        raise ValueError("index out of range: inclusion %d/%d"
                         % (index, size))
    inner, border = _decomp(index, size)
    if len(proof) != inner + border:
        raise ValueError("inclusion proof size %d, want %d"
                         % (len(proof), inner + border))
    for p in proof:
        if len(p) != 32:
            raise ValueError("proof node is not 32 bytes")
    r = leaf
    for i, h in enumerate(proof[:inner]):
        if (index >> i) & 1 == 0:
            r = node_hash(r, h)
        else:
            r = node_hash(h, r)
    for h in proof[inner:]:
        r = node_hash(h, r)
    return r


def inclusion_error(index, size, leaf, proof, root):
    """Verify one inclusion proof; None on success, diagnostic otherwise."""
    if size == 0 or index >= size:
        return "index out of range: inclusion %d/%d" % (index, size)
    try:
        got = root_from_inclusion(index, size, leaf, proof)
    except ValueError as e:
        return str(e)
    if got != root:
        return ("inclusion proof root %s ≠ expected %s"
                % (got.hex(), root.hex()))
    return None
