// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package keys_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/evidence/evtest"
	"github.com/countersign/countersign/internal/keys"
)

// C1.2.2 A chain of 1,000 records per emitter, three emitters interleaved in
// one session: every eprev verifies; eseq gap-free.
func TestC122_InterleavedChains(t *testing.T) {
	session := testULID
	signers := []keys.Signer{
		keys.NewSigner(bytes.Repeat([]byte{1}, 32)),
		keys.NewSigner(bytes.Repeat([]byte{2}, 32)),
		keys.NewSigner(bytes.Repeat([]byte{3}, 32)),
	}
	roles := []string{"broker", "controller", "world"}
	ems := make([]*keys.Emitter, 3)
	for i := range ems {
		ems[i] = keys.NewEmitter(roles[i], session, signers[i])
	}

	const n = 1000
	var lines [][]byte
	for i := 0; i < n; i++ {
		for j, em := range ems {
			body, err := evtest.Sample("observer.gap")
			if err != nil {
				t.Fatal(err)
			}
			line, _, err := em.Emit("observer.gap", body, testTS)
			if err != nil {
				t.Fatalf("emit %d/%d: %v", i, j, err)
			}
			lines = append(lines, line)
		}
	}
	if got := len(lines); got != 3*n {
		t.Fatalf("got %d lines", got)
	}

	// Verify every eprev and the gap-free eseq of each emitter chain.
	cc := evidence.NewChainChecker()
	var last [3]*evidence.Record
	for i, line := range lines {
		env, _, r, err := evidence.DecodeRecordLine(line)
		if err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if err := cc.Add(env, r); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		wantSeq := uint64(i / 3)
		if r.Eseq != wantSeq {
			t.Fatalf("line %d: eseq %d, want %d", i, r.Eseq, wantSeq)
		}
		if prev := last[i%3]; prev != nil {
			if r.Eprev == "0000000000000000000000000000000000000000000000000000000000000000" {
				t.Fatalf("line %d: eprev zero after first record", i)
			}
		}
		last[i%3] = r
	}
	heads := cc.Heads()
	if len(heads) != 3 {
		t.Fatalf("heads: got %d", len(heads))
	}
	for _, h := range heads {
		if h.FinalEseq != n-1 {
			t.Fatalf("%s: final eseq %d", h.Emitter, h.FinalEseq)
		}
	}
}

// C1.2.2 eseq must be exactly previous + 1 (03 §2, V5): the chain checker
// rejects a wrong starting value, a gap, a repeat and a decrease, each with
// the chain reason — never silently skipping or renumbering a record.
func TestC122_EseqExactness(t *testing.T) {
	body, err := evtest.Sample("observer.gap")
	if err != nil {
		t.Fatal(err)
	}
	emitter := "broker/" + testULID
	// mkRecord builds a record carrying a chosen (eseq, eprev) plus an
	// envelope whose record hash the chain checker will store as the head.
	mkRecord := func(eseq uint64, eprev string, salt int) (*evidence.Envelope, *evidence.Record) {
		rec := &evidence.Record{
			V: 1, Type: "observer.gap", ID: testULID,
			Session: testULID, Emitter: emitter,
			Eseq: eseq, Eprev: eprev, TS: testTS, Body: body,
		}
		env := &evidence.Envelope{
			PayloadType: evidence.PayloadType,
			Payload:     []byte(fmt.Sprintf("payload-%d-%d", eseq, salt)),
		}
		return env, rec
	}
	// feed folds one eseq sequence through a fresh checker, keeping eprev
	// consistent with the chain, and reports where it failed.
	feed := func(seqs []uint64, firstEprev string) error {
		cc := evidence.NewChainChecker()
		prev := firstEprev
		for i, s := range seqs {
			env, rec := mkRecord(s, prev, i)
			if err := cc.Add(env, rec); err != nil {
				return err
			}
			prev = evidence.RecordHash(env)
		}
		return nil
	}

	t.Run("start at zero accepted", func(t *testing.T) {
		if err := feed([]uint64{0, 1, 2, 3, 4}, evidence.ZeroHash); err != nil {
			t.Fatalf("contiguous chain rejected: %v", err)
		}
	})
	for _, first := range []uint64{1, 2, 1000} {
		t.Run(fmt.Sprintf("wrong start %d", first), func(t *testing.T) {
			err := feed([]uint64{first}, evidence.ZeroHash)
			if err == nil || !strings.Contains(err.Error(), "eseq") {
				t.Fatalf("first eseq %d: got %v, want chain rejection", first, err)
			}
		})
	}
	t.Run("first eprev nonzero", func(t *testing.T) {
		err := feed([]uint64{0}, strings.Repeat("ab", 32))
		if err == nil || !strings.Contains(err.Error(), "eprev") {
			t.Fatalf("nonzero first eprev: got %v, want chain rejection", err)
		}
	})
	for _, tc := range []struct {
		name string
		seqs []uint64
	}{
		{"gap 0,2", []uint64{0, 2}},
		{"gap mid-chain", []uint64{0, 1, 2, 4, 5}},
		{"gap two skipped", []uint64{0, 1, 4}},
		{"repeat last", []uint64{0, 1, 2, 2}},
		{"repeat first", []uint64{0, 0}},
		{"decrease by one", []uint64{0, 1, 2, 1}},
		{"decrease to zero", []uint64{0, 1, 0}},
		{"decrease after long run", []uint64{0, 1, 2, 3, 4, 5, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := feed(tc.seqs, evidence.ZeroHash)
			if err == nil || !strings.Contains(err.Error(), "eseq") {
				t.Fatalf("%v: got %v, want chain rejection", tc.seqs, err)
			}
		})
	}
	// A wrong eprev at a correct eseq is also a chain failure: eseq alone
	// does not carry the link.
	t.Run("eprev mismatch at right eseq", func(t *testing.T) {
		cc := evidence.NewChainChecker()
		env0, r0 := mkRecord(0, evidence.ZeroHash, 0)
		if err := cc.Add(env0, r0); err != nil {
			t.Fatal(err)
		}
		env1, r1 := mkRecord(1, strings.Repeat("cd", 32), 1)
		if err := cc.Add(env1, r1); err == nil || !strings.Contains(err.Error(), "eprev") {
			t.Fatalf("eprev mismatch: got %v, want chain rejection", err)
		}
	})
}

// C1.2.5 An emitter restarted mid-session gets a new instance ID and starts a
// fresh chain at eseq 0; the old chain is reported unsealed-by-emitter.
func TestC125_EmitterRestart(t *testing.T) {
	s := keys.NewSigner(seedBytes(t))
	session := testULID

	em1 := keys.NewEmitter("broker", session, s)
	inst1 := em1.Instance()
	body, _ := evtest.Sample("observer.gap")
	if _, _, err := em1.Emit("observer.gap", body, testTS); err != nil {
		t.Fatal(err)
	}
	if _, _, err := em1.Emit("observer.gap", body, testTS); err != nil {
		t.Fatal(err)
	}
	// Restart: new emitter object, same role/session/signer.
	em2 := keys.NewEmitter("broker", session, s)
	if em2.Instance() == inst1 {
		t.Fatal("restarted emitter kept the same instance ID")
	}
	line, rec, err := em2.Emit("observer.gap", body, testTS)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Eseq != 0 {
		t.Fatalf("restarted chain begins at eseq %d", rec.Eseq)
	}
	env, _, _, err := evidence.DecodeRecordLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if got := evidence.RecordHash(env); got == rec.Eprev {
		t.Fatal("eprev points at itself")
	}

	// Seal the new chain; the old one stays unsealed.
	sealBody, _ := evtest.Sample("emitter.seal")
	if _, _, err := em2.Emit("emitter.seal", sealBody, testTS); err != nil {
		t.Fatal(err)
	}

	// Rebuild the chain view from all four lines.
	cc := evidence.NewChainChecker()
	heads := map[string]evidence.ChainHead{}
	for _, e := range em1.Lines() {
		env2, _, r2, err := evidence.DecodeRecordLine(e)
		if err != nil {
			t.Fatal(err)
		}
		if err := cc.Add(env2, r2); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range em2.Lines() {
		env2, _, r2, err := evidence.DecodeRecordLine(e)
		if err != nil {
			t.Fatal(err)
		}
		if err := cc.Add(env2, r2); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range cc.Heads() {
		heads[h.Emitter] = h
	}
	old := heads["broker/"+inst1]
	if old.SealedByEmitter {
		t.Fatalf("old chain %s reported sealed", old.Emitter)
	}
	new_ := heads["broker/"+em2.Instance()]
	if !new_.SealedByEmitter {
		t.Fatalf("new chain %s not sealed", new_.Emitter)
	}
	if fmt.Sprint(old.FinalEseq) != "1" {
		t.Fatalf("old chain head eseq %d", old.FinalEseq)
	}
}
