// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package evidence_test

import (
	"bytes"
	"testing"

	"github.com/countersign/countersign/internal/evidence"
)

// FuzzEnvelope is the C1.1.5 target: no panic, and no accepted input that
// fails re-encoding. Seeded by check-M1.1 with a valid line.
func FuzzEnvelope(f *testing.F) {
	r := testRecord(f, "effect.http")
	line, err := evidence.MarshalRecordLine(r, testSig())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(line)
	f.Add([]byte(`{"payloadType":"x","payload":"AA==","signatures":[]}`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		env, err := evidence.UnmarshalEnvelope(data)
		if err != nil {
			return
		}
		out, err := evidence.MarshalEnvelope(env)
		if err != nil {
			t.Fatalf("accepted input fails re-encoding: %v", err)
		}
		env2, err := evidence.UnmarshalEnvelope(out)
		if err != nil {
			t.Fatalf("re-encoded envelope fails decoding: %v", err)
		}
		out2, err := evidence.MarshalEnvelope(env2)
		if err != nil {
			t.Fatalf("second re-encoding failed: %v", err)
		}
		if !bytes.Equal(out, out2) {
			t.Fatalf("re-encoding not stable:\n 1: %s\n 2: %s", out, out2)
		}
	})
}

// FuzzRecordLine fuzzes the whole record path (envelope + statement +
// predicate + body).
func FuzzRecordLine(f *testing.F) {
	for _, tn := range []string{"session.open", "effect.http", "commit.decision", "intent.declared"} {
		r := testRecord(f, tn)
		line, err := evidence.MarshalRecordLine(r, testSig())
		if err != nil {
			f.Fatal(err)
		}
		f.Add(line)
	}
	f.Add([]byte("{}"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, r, err := evidence.DecodeRecordLine(data)
		if err != nil {
			return
		}
		out, err := evidence.MarshalPredicate(r)
		if err != nil {
			t.Fatalf("accepted input fails re-encoding: %v", err)
		}
		if _, err := evidence.UnmarshalPredicate(out); err != nil {
			t.Fatalf("re-encoded predicate fails decoding: %v", err)
		}
	})
}
