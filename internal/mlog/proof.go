// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package mlog

import (
	"errors"
	"fmt"
	"math/bits"
)

// InclusionProof returns the RFC 6962 §2.1.1 audit path PATH(index, D[n])
// for the leaf at index in the current tree.
func (l *Log) InclusionProof(index uint64) ([][]byte, error) {
	if index >= uint64(len(l.leaves)) {
		return nil, fmt.Errorf("%w: leaf %d, size %d", errRange, index, len(l.leaves))
	}
	return l.path(index, 0, uint64(len(l.leaves))), nil
}

// path computes PATH(i, D[lo:hi]).
func (l *Log) path(i, lo, hi uint64) [][]byte {
	n := hi - lo
	if n == 1 {
		return nil
	}
	k := largestPow2Below(n)
	if i < lo+k {
		return append(l.path(i, lo, lo+k), nodeBytes(mthRange(l.leaves, lo+k, hi)))
	}
	return append(l.path(i, lo+k, hi), nodeBytes(mthRange(l.leaves, lo, lo+k)))
}

// ConsistencyProof returns PROOF(m, D[n]) = SUBPROOF(m, D[n], true) for the
// current tree of size n (RFC 6962 §2.1.2).
func (l *Log) ConsistencyProof(m, n uint64) ([][]byte, error) {
	if m < 1 || n > uint64(len(l.leaves)) || m > n {
		return nil, fmt.Errorf("%w: consistency %d→%d, size %d", errRange, m, n, len(l.leaves))
	}
	return l.subproof(m, 0, n, true), nil
}

// subproof computes SUBPROOF(m, D[lo:hi], completeTree).
func (l *Log) subproof(m, lo, hi uint64, complete bool) [][]byte {
	n := hi - lo
	if m == n {
		if complete {
			return nil
		}
		return [][]byte{nodeBytes(mthRange(l.leaves, lo, hi))}
	}
	k := largestPow2Below(n)
	if m <= k {
		return append(l.subproof(m, lo, lo+k, complete), nodeBytes(mthRange(l.leaves, lo+k, hi)))
	}
	return append(l.subproof(m-k, lo+k, hi, false), nodeBytes(mthRange(l.leaves, lo, lo+k)))
}

// VerifyInclusion checks an audit path per RFC 6962 §2.1.1.
func VerifyInclusion(index, size uint64, leaf [32]byte, proof [][]byte, root [32]byte) error {
	if size == 0 || index >= size {
		return fmt.Errorf("%w: inclusion %d/%d", errRange, index, size)
	}
	got, err := RootFromInclusionProof(index, size, leaf, proof)
	if err != nil {
		return err
	}
	if got != root {
		return fmt.Errorf("inclusion proof root %x ≠ expected %x", got, root)
	}
	return nil
}

// RootFromInclusionProof recomputes the root from index, leaf, and proof.
func RootFromInclusionProof(index, size uint64, leaf [32]byte, proof [][]byte) ([32]byte, error) {
	if size == 0 || index >= size {
		return [32]byte{}, fmt.Errorf("%w: inclusion %d/%d", errRange, index, size)
	}
	inner, border := decompInclProof(index, size)
	if len(proof) != inner+border {
		return [32]byte{}, fmt.Errorf("inclusion proof size %d, want %d", len(proof), inner+border)
	}
	for _, p := range proof {
		if len(p) != 32 {
			return [32]byte{}, errors.New("proof node is not 32 bytes")
		}
	}
	r := chainInner(leaf[:], proof[:inner], index)
	return chainBorderRight(r, proof[inner:]), nil
}

// VerifyConsistency checks PROOF(m, D[n]) per RFC 6962 §2.1.2. The proof is
// a suffix of the inclusion proof for leaf m-1 in the size-n tree; when m is
// itself a power of two its root is implied and not carried in the proof.
func VerifyConsistency(m, n uint64, proof [][]byte, root1, root2 [32]byte) error {
	switch {
	case n < m || m < 1:
		return fmt.Errorf("%w: consistency %d→%d", errRange, m, n)
	case m == n:
		if len(proof) != 0 || root1 != root2 {
			return errors.New("equal sizes must share the root and carry an empty proof")
		}
		return nil
	case len(proof) == 0:
		return errors.New("empty consistency proof")
	}
	inner, border := decompInclProof(m-1, n)
	shift := bits.TrailingZeros64(m)
	inner -= shift // shift < inner because m < n
	seed, start := proof[0], 1
	if m == 1<<uint(shift) { // m is itself that power of two
		seed, start = root1[:], 0
	}
	if got, want := len(proof), start+inner+border; got != want {
		return fmt.Errorf("consistency proof size %d, want %d", got, want)
	}
	p := proof[start:]
	mask := (m - 1) >> uint(shift)
	h1 := chainInnerRight(seed, p[:inner], mask)
	h1 = chainBorderRight(h1, p[inner:])
	if h1 != root1 {
		return fmt.Errorf("consistency old root %x ≠ %x", h1, root1)
	}
	h2 := chainInner(seed, p[:inner], mask)
	h2 = chainBorderRight(h2, p[inner:])
	if h2 != root2 {
		return fmt.Errorf("consistency new root %x ≠ %x", h2, root2)
	}
	return nil
}

// decompInclProof returns the (inner, border) lengths of the inclusion proof
// for leaf index in a tree of the given size.
func decompInclProof(index, size uint64) (int, int) {
	inner := bits.Len64(index ^ (size - 1))
	return inner, bits.OnesCount64(index >> uint(inner))
}

func chainInner(seed []byte, proof [][]byte, index uint64) [32]byte {
	r := mustArr(seed)
	for i, h := range proof {
		if (index>>uint(i))&1 == 0 {
			r = HashNode(r[:], h)
		} else {
			r = HashNode(h, r[:])
		}
	}
	return r
}

func chainInnerRight(seed []byte, proof [][]byte, index uint64) [32]byte {
	r := mustArr(seed)
	for i, h := range proof {
		if (index>>uint(i))&1 == 1 {
			r = HashNode(h, r[:])
		}
	}
	return r
}

func chainBorderRight(seed [32]byte, proof [][]byte) [32]byte {
	r := seed
	for _, h := range proof {
		r = HashNode(h, r[:])
	}
	return r
}

func mustArr(b []byte) [32]byte {
	var a [32]byte
	copy(a[:], b)
	return a
}

func nodeBytes(h [32]byte) []byte { return h[:] }
