// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package mlog_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/mlog"
	"github.com/countersign/countersign/internal/names"
	tdmerkle "github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

// C1.3.1 Inclusion proofs: every size 1..257, every leaf index — our
// verifier AND the independent transparency-dev/merkle verifier accept.
func TestC131_Inclusion(t *testing.T) {
	const maxN = 257
	logSigner := keys.NewSigner(bytes.Repeat([]byte{7}, 32))
	lg := mlog.NewLog(names.APIGroup+"/log/testlog", logSigner)
	var lines [][]byte
	for n := 1; n <= maxN; n++ {
		line := []byte(fmt.Sprintf("record-%04d", n-1))
		lg.AppendLeaf(line)
		lines = append(lines, line)
		root := lg.Root()
		for i := 0; i < n; i++ {
			p, err := lg.InclusionProof(uint64(i))
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			leaf := mlog.HashLeaf(lines[i])
			if err := mlog.VerifyInclusion(uint64(i), uint64(n), leaf, p, root); err != nil {
				t.Fatalf("our verifier n=%d i=%d: %v", n, i, err)
			}
			if err := tdmerkle.VerifyInclusion(rfc6962.DefaultHasher, uint64(i), uint64(n), leaf[:], p, root[:]); err != nil {
				t.Fatalf("independent verifier n=%d i=%d: %v", n, i, err)
			}
		}
	}
}

// C1.3.1 at full width: the proof length must equal exactly the path
// length for (index, tree size). A proof one node short and a proof that
// is the valid path plus extra hashes are both rejected — never trimmed,
// folded in, or ignored. Several (index, size) pairs, including the last
// leaf and sizes that are not powers of two.
func TestC131_ProofExactLength(t *testing.T) {
	logSigner := keys.NewSigner(bytes.Repeat([]byte{7}, 32))
	pairs := [][2]uint64{
		{0, 1}, {0, 2}, {1, 2},
		{0, 3}, {2, 3}, // n=3, not a power of two
		{0, 4}, {3, 4},
		{0, 7}, {5, 7}, {6, 7}, // n=7, not a power of two
		{0, 8}, {7, 8}, // last leaf of a power of two
		{0, 9}, {8, 9},
		{0, 64}, {63, 64},
		{0, 100}, {99, 100},
		{0, 256}, {255, 256},
		{0, 257}, {100, 257}, {256, 257}, // last leaf, n not a power of two
	}
	for _, pr := range pairs {
		i, n := pr[0], pr[1]
		t.Run(fmt.Sprintf("leaf %d of %d", i, n), func(t *testing.T) {
			lg := mlog.NewLog(names.APIGroup+"/log/testlog", logSigner)
			lines := make([][]byte, n)
			for k := uint64(0); k < n; k++ {
				lines[k] = []byte(fmt.Sprintf("record-%04d", k))
				lg.AppendLeaf(lines[k])
			}
			root := lg.Root()
			leaf := mlog.HashLeaf(lines[i])
			p, err := lg.InclusionProof(i)
			if err != nil {
				t.Fatal(err)
			}
			if err := mlog.VerifyInclusion(i, n, leaf, p, root); err != nil {
				t.Fatalf("genuine proof rejected: %v", err)
			}
			// Too short: every strict prefix must fail.
			for k := 0; k < len(p); k++ {
				short := p[:k]
				if err := mlog.VerifyInclusion(i, n, leaf, short, root); err == nil {
					t.Fatalf("proof truncated to %d of %d nodes accepted", k, len(p))
				}
			}
			// Too long: valid path plus extra hashes.
			extra, err := lg.LeafHash(0)
			if err != nil {
				t.Fatal(err)
			}
			for _, add := range [][32]byte{extra, mlog.HashLeaf([]byte("filler")), root} {
				a := add
				long := append(append([][]byte{}, p...), a[:])
				if err := mlog.VerifyInclusion(i, n, leaf, long, root); err == nil {
					t.Fatalf("proof of %d nodes plus an extra accepted", len(p))
				}
				// Extra nodes at the front as well.
				long = append([][]byte{a[:]}, p...)
				if err := mlog.VerifyInclusion(i, n, leaf, long, root); err == nil {
					t.Fatalf("extra hash prepended to %d-node proof accepted", len(p))
				}
			}
		})
	}
}

// C1.3.2 Consistency proofs for every pair m ≤ n ≤ 64, both verifiers.
func TestC132_Consistency(t *testing.T) {
	const maxN = 64
	logSigner := keys.NewSigner(bytes.Repeat([]byte{7}, 32))
	lg := mlog.NewLog(names.APIGroup+"/log/testlog", logSigner)
	var roots [][32]byte
	for n := 1; n <= maxN; n++ {
		lg.AppendLeaf([]byte(fmt.Sprintf("record-%04d", n-1)))
		roots = append(roots, lg.Root())
	}
	for m := 1; m <= maxN; m++ {
		for n := m; n <= maxN; n++ {
			p, err := lg.ConsistencyProof(uint64(m), uint64(n))
			if err != nil {
				t.Fatalf("m=%d n=%d: %v", m, n, err)
			}
			if err := mlog.VerifyConsistency(uint64(m), uint64(n), p, roots[m-1], roots[n-1]); err != nil {
				t.Fatalf("our verifier m=%d n=%d: %v", m, n, err)
			}
			if err := tdmerkle.VerifyConsistency(rfc6962.DefaultHasher, uint64(m), uint64(n), p, roots[m-1][:], roots[n-1][:]); err != nil {
				t.Fatalf("independent verifier m=%d n=%d: %v", m, n, err)
			}
		}
	}
}

// C1.3.2 at full width: verification recomputes and checks BOTH the old
// root and the new root. A proof that reproduces the new root but not the
// old — and the reverse — is rejected. Each side is tested separately.
func TestC132_BothRootsChecked(t *testing.T) {
	const maxN = 64
	logSigner := keys.NewSigner(bytes.Repeat([]byte{7}, 32))
	lg := mlog.NewLog(names.APIGroup+"/log/testlog", logSigner)
	roots := make([][32]byte, maxN)
	for n := 1; n <= maxN; n++ {
		lg.AppendLeaf([]byte(fmt.Sprintf("record-%04d", n-1)))
		roots[n-1] = lg.Root()
	}
	bad := func(h [32]byte) [32]byte {
		h[0] ^= 0xff
		return h
	}
	pairs := [][2]uint64{
		{1, 2}, {1, 64}, // m = 1
		{2, 3}, {3, 8},
		{4, 8}, {4, 9}, // m a power of two
		{8, 16}, {8, 17},
		{5, 9}, {7, 16}, {9, 16}, // m not a power of two
		{16, 64}, {63, 64}, {1, 63},
	}
	for _, pr := range pairs {
		m, n := pr[0], pr[1]
		t.Run(fmt.Sprintf("%d to %d", m, n), func(t *testing.T) {
			p, err := lg.ConsistencyProof(m, n)
			if err != nil {
				t.Fatal(err)
			}
			r1, r2 := roots[m-1], roots[n-1]
			if err := mlog.VerifyConsistency(m, n, p, r1, r2); err != nil {
				t.Fatalf("genuine proof rejected: %v", err)
			}
			// Proof reproduces the new root but not the old root.
			if err := mlog.VerifyConsistency(m, n, p, bad(r1), r2); err == nil {
				t.Fatal("wrong old root accepted")
			}
			// Proof reproduces the old root but not the new root.
			if err := mlog.VerifyConsistency(m, n, p, r1, bad(r2)); err == nil {
				t.Fatal("wrong new root accepted")
			}
			// Swapped roots are wrong on both sides.
			if err := mlog.VerifyConsistency(m, n, p, r2, r1); err == nil {
				t.Fatal("swapped roots accepted")
			}
			// A proof truncated or extended is not a consistency proof.
			if len(p) > 0 {
				if err := mlog.VerifyConsistency(m, n, p[:len(p)-1], r1, r2); err == nil {
					t.Fatal("truncated consistency proof accepted")
				}
				h := mlog.HashLeaf([]byte("filler"))
				long := append(append([][]byte{}, p...), h[:])
				if err := mlog.VerifyConsistency(m, n, long, r1, r2); err == nil {
					t.Fatal("extended consistency proof accepted")
				}
			}
		})
	}
	// m == n: only an empty proof and identical roots are accepted.
	t.Run("equal sizes", func(t *testing.T) {
		r := roots[9]
		if err := mlog.VerifyConsistency(10, 10, nil, r, r); err != nil {
			t.Fatalf("m == n with empty proof rejected: %v", err)
		}
		if err := mlog.VerifyConsistency(10, 10, nil, r, bad(r)); err == nil {
			t.Fatal("m == n accepted differing roots")
		}
		if err := mlog.VerifyConsistency(10, 10, [][]byte{roots[0][:]}, r, r); err == nil {
			t.Fatal("m == n accepted a non-empty proof")
		}
	})
}

// C1.3.3 Our checkpoints verify with golang.org/x/mod/sumdb/note, and a
// note.Sign-produced checkpoint verifies with ours.
func TestC133_NoteInterop(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	logSigner := keys.NewSigner(seed)
	lg := mlog.NewLog(names.APIGroup+"/log/testlog", logSigner)
	for i := 0; i < 10; i++ {
		lg.AppendLeaf([]byte(fmt.Sprintf("record-%04d", i)))
	}
	m, err := keys.NewManifest([]keys.ManifestEntry{{
		Role: "log", Signer: logSigner, NotBefore: "2020-01-01T00:00:00Z",
	}})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := lg.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := mlog.SignCheckpoint(cp, logSigner)
	if err != nil {
		t.Fatal(err)
	}

	// Direction 1: x/mod note.Open accepts it. Build the verifier key.
	pub := logSigner.Public()
	hash := sha256.Sum256(append(append([]byte(names.APIGroup+"/log/testlog"), '\n'), append([]byte{1}, pub...)...))
	vkey := fmt.Sprintf(names.APIGroup+"/log/testlog+%08x+%s",
		uint32(hash[0])<<24|uint32(hash[1])<<16|uint32(hash[2])<<8|uint32(hash[3]),
		base64.StdEncoding.EncodeToString(append([]byte{1}, pub...)))
	v, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("note.NewVerifier: %v", err)
	}
	n, err := note.Open(signed, note.VerifierList(v))
	if err != nil {
		t.Fatalf("note.Open rejected our checkpoint: %v", err)
	}
	wantText := fmt.Sprintf(names.APIGroup+"/log/testlog\n10\n%s\n", base64.StdEncoding.EncodeToString(rootBytes(lg.Root())))
	if n.Text != wantText {
		t.Fatalf("note text:\n%s\nwant:\n%s", n.Text, wantText)
	}

	// Direction 2: a note.Sign checkpoint verifies with ours.
	skey := fmt.Sprintf("PRIVATE+KEY+"+names.APIGroup+"/log/testlog+%08x+%s",
		uint32(hash[0])<<24|uint32(hash[1])<<16|uint32(hash[2])<<8|uint32(hash[3]),
		base64.StdEncoding.EncodeToString(append([]byte{1}, seed...)))
	ns, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("note.NewSigner: %v", err)
	}
	theirs, err := note.Sign(&note.Note{Text: wantText}, ns)
	if err != nil {
		t.Fatal(err)
	}
	got, err := mlog.ParseCheckpoint(theirs, m)
	if err != nil {
		t.Fatalf("our parser rejected note.Sign output: %v", err)
	}
	if got.Size != 10 || got.Root != lg.Root() || got.Origin != names.APIGroup+"/log/testlog" {
		t.Fatalf("parsed %+v", got)
	}
}

// C1.3.4 Published RFC 6962 values (crpt/go-merkle rfc6962_test.go,
// RFC 6962 §2.1 empty-root).
func TestC134_Vectors(t *testing.T) {
	empty := sha256.Sum256(nil)
	if got := mlog.HashLeaf(nil); hex.EncodeToString(got[:]) != "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" {
		t.Fatalf("empty leaf: %x", got)
	}
	if got := mlog.HashLeaf([]byte("L123456")); hex.EncodeToString(got[:]) != "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56" {
		t.Fatalf("L123456 leaf: %x", got)
	}
	if got := mlog.HashNode(mustHex("4e313233", t), mustHex("4e343536", t)); hex.EncodeToString(got[:]) != "aa217fe888e47007fa15edab33c2b492a722cb106c64667fc2b044444de66bbb" {
		t.Fatalf("N123‖N456 node: %x", got)
	}
	if got := mlog.NewLog("o", nil).Root(); got != empty {
		t.Fatalf("empty root: %x", got)
	}
}

func rootBytes(h [32]byte) []byte { return h[:] }

func mustHex(s string, t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// C1.3.5 A log whose log key ID equals an emitter key ID is refused at
// checkpoint verification.
func TestC135_LogKeySeparation(t *testing.T) {
	signer := keys.NewSigner(bytes.Repeat([]byte{7}, 32))
	lg := mlog.NewLog(names.APIGroup+"/log/testlog", signer)
	lg.AppendLeaf([]byte("record"))
	cp, err := lg.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := mlog.SignCheckpoint(cp, signer)
	if err != nil {
		t.Fatal(err)
	}

	// Manifest where the same key is an emitter key → refused.
	bad, err := keys.NewManifest([]keys.ManifestEntry{{
		Role: "emitter:broker", Signer: signer, NotBefore: "2020-01-01T00:00:00Z",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mlog.ParseCheckpoint(signed, bad); err == nil {
		t.Fatal("checkpoint signed by an emitter key was accepted")
	}
	// Manifest where the key is absent → refused.
	if _, err := mlog.ParseCheckpoint(signed, keys.Manifest(nil)); err == nil {
		t.Fatal("checkpoint signed by an unknown key was accepted")
	}
	// Correct log role → accepted.
	good, err := keys.NewManifest([]keys.ManifestEntry{{
		Role: "log", Signer: signer, NotBefore: "2020-01-01T00:00:00Z",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mlog.ParseCheckpoint(signed, good); err != nil {
		t.Fatalf("log-key checkpoint rejected: %v", err)
	}
}
