# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""RFC 6962 Merkle tree hashing and inclusion-proof verification.

MTH per RFC 6962 §2.1; proof verification per RFC 9162 §2.1.3.2 (obsoletes
6962, same tree construction and verification algorithm).
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
    """RFC 9162 §2.1.3.2: prove ``leaf`` (a 32-byte leaf hash) is at
    ``leaf_index`` in the tree of ``tree_size`` with ``root``."""
    if leaf_index < 0 or leaf_index >= tree_size:
        return False
    if len(leaf) != 32 or len(root) != 32:
        return False
    fn = leaf_index
    sn = tree_size - 1
    r = leaf
    for p in proof:
        if len(p) != 32 or sn == 0:
            return False
        if (fn & 1) or fn == sn:
            r = node_hash(p, r)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root
