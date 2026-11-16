// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package evidence_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/evidence/evtest"
)

const (
	testULID1 = "01K7D7JQ9Y8T4X2Z6B4H4F4F4F"
	testULID2 = "01K7D7JQ9Y8T4X2Z6B4H4F4F4G"
	testULID3 = "01K7D7JQ9Y8T4X2Z6B4H4F4F4H"
	testTS    = "2026-11-14T00:00:00.000000000Z"
	testZero  = "0000000000000000000000000000000000000000000000000000000000000000"
)

func testSig() evidence.Signature {
	return evidence.Signature{
		KeyID: "0123456789abcdef0123456789abcdef",
		Sig:   bytes.Repeat([]byte{0x5a}, 64),
	}
}

func testRecord(t testing.TB, typeName string) *evidence.Record {
	t.Helper()
	body, err := evtest.Sample(typeName)
	if err != nil {
		t.Fatalf("sample body for %s: %v", typeName, err)
	}
	return &evidence.Record{
		V:       1,
		Type:    typeName,
		ID:      testULID1,
		Session: testULID2,
		Emitter: "broker/" + testULID3,
		Eseq:    0,
		Eprev:   testZero,
		TS:      testTS,
		Body:    body,
	}
}

// C1.1.1 Round trip: for every record type, encode → decode → encode yields
// identical bytes.
func TestC111_RoundTrip(t *testing.T) {
	types := evidence.Types()
	if len(types) != 34 {
		t.Fatalf("expected 34 record types from 03 §4, got %d", len(types))
	}
	for _, tn := range types {
		r := testRecord(t, tn)
		line, err := evidence.MarshalRecordLine(r, testSig())
		if err != nil {
			t.Fatalf("%s: marshal: %v", tn, err)
		}
		_, _, r2, err := evidence.DecodeRecordLine(line)
		if err != nil {
			t.Fatalf("%s: decode: %v\nline: %s", tn, err, line)
		}
		line2, err := evidence.MarshalRecordLine(r2, testSig())
		if err != nil {
			t.Fatalf("%s: re-marshal: %v", tn, err)
		}
		if !bytes.Equal(line, line2) {
			t.Fatalf("%s: round trip mismatch\n  1: %s\n  2: %s", tn, line, line2)
		}
	}
}

// C1.1.2 PAE matches the DSSE specification's published test vector
// (upstream excerpt: evidence/M1.1/*/upstream/dsse-pae-test-vector.txt).
func TestC112_PAEVector(t *testing.T) {
	got := evidence.PAE("http://example.com/HelloWorld", []byte("hello world"))
	want := []byte("DSSEv1 29 http://example.com/HelloWorld 11 hello world")
	if !bytes.Equal(got, want) {
		t.Fatalf("PAE mismatch:\n got: %q\nwant: %q", got, want)
	}
}

// C1.1.3 Decoder rejections, one test each.
func TestC113_Rejections(t *testing.T) {
	r := testRecord(t, "effect.denied")
	line, err := evidence.MarshalRecordLine(r, testSig())
	if err != nil {
		t.Fatal(err)
	}
	_, st, _, err := evidence.DecodeRecordLine(line)
	if err != nil {
		t.Fatal(err)
	}
	predBytes, _ := evidence.MarshalPredicate(r)

	mutateLine := func(f func([]byte) []byte) []byte { return f(bytes.Clone(line)) }

	t.Run("unknown predicate field", func(t *testing.T) {
		// Insert an extra field into the predicate object.
		var m map[string]json.RawMessage
		if err := json.Unmarshal(predBytes, &m); err != nil {
			t.Fatal(err)
		}
		m["zzz"] = json.RawMessage(`1`)
		b, _ := json.Marshal(m)
		if _, err := evidence.UnmarshalPredicate(b); err == nil {
			t.Fatal("accepted predicate with unknown field")
		}
	})

	t.Run("unknown body field", func(t *testing.T) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(predBytes, &m); err != nil {
			t.Fatal(err)
		}
		var bm map[string]json.RawMessage
		if err := json.Unmarshal(m["body"], &bm); err != nil {
			t.Fatal(err)
		}
		bm["zzz"] = json.RawMessage(`1`)
		bb, _ := json.Marshal(bm)
		m["body"] = bb
		b, _ := json.Marshal(m)
		if _, err := evidence.UnmarshalPredicate(b); err == nil {
			t.Fatal("accepted body with unknown field")
		}
	})

	t.Run("unknown type", func(t *testing.T) {
		b := bytes.Replace(predBytes, []byte(`"effect.denied"`), []byte(`"effect.nope"`), 1)
		if _, err := evidence.UnmarshalPredicate(b); err == nil {
			t.Fatal("accepted unknown record type")
		}
	})

	t.Run("duplicate key", func(t *testing.T) {
		// {"v":1,"v":1,...}
		s := strings.Replace(string(predBytes), `"v":1`, `"v":1,"v":1`, 1)
		if _, err := evidence.UnmarshalPredicate([]byte(s)); err == nil {
			t.Fatal("accepted duplicate key")
		}
	})

	t.Run("wrong _type", func(t *testing.T) {
		b, _ := json.Marshal(map[string]any{
			"_type":         "https://in-toto.io/Statement/v0",
			"subject":       st.Subject,
			"predicateType": st.PredicateType,
			"predicate":     st.Predicate,
		})
		if _, err := evidence.UnmarshalStatement(b); err == nil {
			t.Fatal("accepted wrong _type")
		}
	})

	t.Run("wrong predicateType", func(t *testing.T) {
		b, _ := json.Marshal(map[string]any{
			"_type":         st.Type,
			"subject":       st.Subject,
			"predicateType": "https://example.com/other/v1",
			"predicate":     st.Predicate,
		})
		if _, err := evidence.UnmarshalStatement(b); err == nil {
			t.Fatal("accepted wrong predicateType")
		}
	})

	t.Run("two signatures", func(t *testing.T) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatal(err)
		}
		var sigs []json.RawMessage
		if err := json.Unmarshal(m["signatures"], &sigs); err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs, sigs[0])
		m["signatures"], _ = json.Marshal(sigs)
		b, _ := json.Marshal(m)
		if _, err := evidence.UnmarshalEnvelope(b); err == nil {
			t.Fatal("accepted two signatures")
		}
	})

	t.Run("zero signatures", func(t *testing.T) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatal(err)
		}
		m["signatures"] = json.RawMessage(`[]`)
		b, _ := json.Marshal(m)
		if _, err := evidence.UnmarshalEnvelope(b); err == nil {
			t.Fatal("accepted zero signatures")
		}
	})

	t.Run("non-canonical base64", func(t *testing.T) {
		// Strip padding from the base64 payload; decoding would still work but
		// the encoding is not canonical.
		var m map[string]json.RawMessage
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatal(err)
		}
		var p string
		if err := json.Unmarshal(m["payload"], &p); err != nil {
			t.Fatal(err)
		}
		m["payload"], _ = json.Marshal(strings.TrimRight(p, "=") + "===")
		b, _ := json.Marshal(m)
		if _, err := evidence.UnmarshalEnvelope(b); err == nil {
			t.Fatal("accepted non-canonical base64 payload")
		}
	})

	// Envelope-level fields also reject unknowns.
	t.Run("unknown envelope field", func(t *testing.T) {
		b := mutateLine(func(l []byte) []byte {
			return bytes.Replace(l, []byte(`{"payloadType"`), []byte(`{"zzz":0,"payloadType"`), 1)
		})
		if _, err := evidence.UnmarshalEnvelope(b); err == nil {
			t.Fatal("accepted unknown envelope field")
		}
	})

	// Non-UTF-8 input is rejected.
	t.Run("non-utf8", func(t *testing.T) {
		b := mutateLine(func(l []byte) []byte {
			return append(l[:20], append([]byte{0xff, 0xfe}, l[20:]...)...)
		})
		if _, err := evidence.UnmarshalEnvelope(b); err == nil {
			t.Fatal("accepted non-UTF-8 input")
		}
	})
}
