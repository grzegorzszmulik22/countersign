// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Package mlog implements the append-only Merkle log of 03 §5–§6:
// RFC 6962 leaf/node hashing and proofs, plus C2SP tlog-checkpoints in
// signed-note format signed by the dedicated `log` key.
package mlog

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/countersign/countersign/internal/keys"
)

// HashLeaf is RFC 6962 §2.1: SHA-256(0x00 ‖ leaf bytes). The leaf bytes are
// the stored record line exactly as appended (no added newline).
func HashLeaf(line []byte) [32]byte {
	buf := make([]byte, 0, 1+len(line))
	buf = append(buf, 0x00)
	buf = append(buf, line...)
	return sha256.Sum256(buf)
}

// HashNode is RFC 6962 §2.1: SHA-256(0x01 ‖ left ‖ right).
func HashNode(left, right []byte) [32]byte {
	buf := make([]byte, 0, 65)
	buf = append(buf, 0x01)
	buf = append(buf, left...)
	buf = append(buf, right...)
	return sha256.Sum256(buf)
}

// Log is an append-only RFC 6962 tree over stored record lines.
type Log struct {
	origin string
	signer keys.Signer
	leaves [][32]byte
}

// NewLog starts a log. origin is the checkpoint origin
// (names.APIGroup + "/log/<log ID>"); signer is the dedicated `log` key.
func NewLog(origin string, signer keys.Signer) *Log {
	return &Log{origin: origin, signer: signer}
}

// Origin is the checkpoint origin string.
func (l *Log) Origin() string { return l.origin }

// Size is the number of leaves.
func (l *Log) Size() uint64 { return uint64(len(l.leaves)) }

// AppendLeaf hashes the stored line and appends it; returns its index.
func (l *Log) AppendLeaf(line []byte) uint64 {
	l.leaves = append(l.leaves, HashLeaf(line))
	return uint64(len(l.leaves)) - 1
}

// LeafHash returns the leaf hash at index i.
func (l *Log) LeafHash(i uint64) ([32]byte, error) {
	if i >= uint64(len(l.leaves)) {
		return [32]byte{}, fmt.Errorf("leaf %d out of range (size %d)", i, len(l.leaves))
	}
	return l.leaves[i], nil
}

// Root is the Merkle Tree Hash MTH(D[n]); for n = 0 it is SHA-256("").
func (l *Log) Root() [32]byte { return mthRange(l.leaves, 0, uint64(len(l.leaves))) }

// mthRange computes MTH(D[lo:hi]) recursively per RFC 6962 §2.1.
func mthRange(leaves [][32]byte, lo, hi uint64) [32]byte {
	n := hi - lo
	if n == 0 {
		return sha256.Sum256(nil)
	}
	if n == 1 {
		return leaves[lo]
	}
	k := largestPow2Below(n)
	return HashNode(nodeBytes(mthRange(leaves, lo, lo+k)), nodeBytes(mthRange(leaves, lo+k, hi)))
}

// largestPow2Below returns the greatest power of two strictly below n (n≥2).
func largestPow2Below(n uint64) uint64 {
	k := uint64(1)
	for k<<1 < n {
		k <<= 1
	}
	return k
}

var errRange = errors.New("index out of range")

// Checkpoint is an unsigned tlog-checkpoint for the current tree.
func (l *Log) Checkpoint() (*Checkpoint, error) {
	if l.signer == nil {
		return nil, errors.New("log has no signer")
	}
	return &Checkpoint{Origin: l.origin, Size: uint64(len(l.leaves)), Root: l.Root()}, nil
}

// RootOf computes MTH over an arbitrary slice of leaf hashes.
func RootOf(leaves [][32]byte) [32]byte { return mthRange(leaves, 0, uint64(len(leaves))) }
