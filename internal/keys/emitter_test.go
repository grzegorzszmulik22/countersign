// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package keys_test

import (
	"bytes"
	"fmt"
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
