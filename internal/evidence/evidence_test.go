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

// C1.1.3 duplicate keys at the full width of 03 §2: a duplicate is rejected
// at every nesting depth — the outer object, an object nested in an object,
// an object inside an array — and key identity is the DECODED string, so
// keys that differ only in escaping ("a" vs "a", "/" vs "\/", raw non-ASCII
// vs \uXXXX including a surrogate pair) are duplicates.
func TestC113_DuplicateKeys(t *testing.T) {
	// Reject vectors: raw JSON carrying a duplicate key. In a Go raw string
	// literal backslashes are literal, so `\u0061` here is the six-byte JSON
	// escape for "a" on the wire. The expected error names the decoded key.
	preds := []struct {
		name string
		in   string
		key  string // decoded key the error must name
	}{
		{"outer literal", `{"a":1,"a":2}`, "a"},
		{"outer literal three fields", `{"a":1,"b":0,"a":2}`, "a"},
		{"ascii raw vs escape", `{"a":1,"\u0061":2}`, "a"},
		{"ascii escape vs raw", `{"\u0061":1,"a":2}`, "a"},
		{"slash vs escaped slash", `{"\/":1,"/":2}`, "/"},
		{"escaped slash vs slash", `{"/":1,"\/":2}`, "/"},
		{"slash literal", `{"/":1,"/":2}`, "/"},
		{"escaped quote vs raw", `{"\"x":1,"\"x":2}`, "x"},
		{"hex escape vs escape", "{\"\\u002f\":1,\"\\/\":2}", "/"},
		{"hex quote vs raw escape", "{\"\\\"x\":1,\"\\u0022x\":2}", "x"},
		{"non-ascii raw vs escape", "{\"é\":1,\"\\u00e9\":2}", "é"},
		{"non-ascii escape vs raw", "{\"\\u00e9\":1,\"é\":2}", "é"},
		{"uppercase hex escape", "{\"é\":1,\"\\u00E9\":2}", "é"},
		{"surrogate pair raw vs escaped", "{\"𝕊\":1,\"\\ud835\\udd4a\":2}", "𝕊"},
		{"surrogate pair escaped vs raw", "{\"\\ud835\\udd4a\":1,\"𝕊\":2}", "𝕊"},
		{"nested object depth 2", `{"x":{"a":1,"a":2}}`, "a"},
		{"nested object depth 3", `{"x":{"y":{"a":1,"a":2}}}`, "a"},
		{"object in array depth 2", `{"x":[{"a":1,"a":2}]}`, "a"},
		{"object in nested arrays", `{"x":[[[{"a":1,"a":2}]]]}`, "a"},
		{"object in array in object", `{"x":{"y":[{"a":1,"a":2}]}}`, "a"},
		{"dup in inner, outer unique", `{"a":1,"b":{"a":1,"a":2}}`, "a"},
		{"escape-equal at depth 2", "{\"x\":{\"é\":1,\"\\u00e9\":2}}", "é"},
		{"escape-equal inside array", "{\"x\":[{\"\\u0061\":1,\"a\":2}]}", "a"},
		{"tab vs \\u0009", "{\"\\u0009\":1,\"\\t\":2}", "\\t"},
		{"newline vs \\u000a", "{\"\\u000a\":1,\"\\n\":2}", "\\n"},
		{"backspace vs \\u0008", "{\"\\u0008\":1,\"\\b\":2}", "\\b"},
		{"backslash vs \\u005c", "{\"\\u005c\":1,\"\\\\\":2}", "\\\\"},
	}
	for _, v := range preds {
		t.Run(v.name, func(t *testing.T) {
			_, err := evidence.UnmarshalPredicate([]byte(v.in))
			if err == nil {
				t.Fatalf("accepted %s", v.in)
			}
			if !strings.Contains(err.Error(), "duplicate key") {
				t.Fatalf("error %v is not the duplicate-key rejection", err)
			}
			if !strings.Contains(err.Error(), `"`+v.key+`"`) {
				t.Fatalf("error %v does not name decoded key %q", err, v.key)
			}
		})
	}
	// Envelope-level depth: the outer object of a stored line and an object
	// inside the signatures array.
	t.Run("envelope outer object", func(t *testing.T) {
		in := `{"payloadType":"x","payloadType":"x","payload":"AA==","signatures":[]}`
		if _, err := evidence.UnmarshalEnvelope([]byte(in)); err == nil ||
			!strings.Contains(err.Error(), `duplicate key "payloadType"`) {
			t.Fatalf("got %v, want duplicate key rejection", err)
		}
	})
	t.Run("envelope signatures array", func(t *testing.T) {
		in := `{"payloadType":"x","payload":"AA==","signatures":[{"keyid":"a","keyid":"a"}]}`
		if _, err := evidence.UnmarshalEnvelope([]byte(in)); err == nil ||
			!strings.Contains(err.Error(), `duplicate key "keyid"`) {
			t.Fatalf("got %v, want duplicate key rejection", err)
		}
	})
	t.Run("statement subject array", func(t *testing.T) {
		in := `{"_type":"x","subject":[{"name":"n","name":"n"}]}`
		if _, err := evidence.UnmarshalStatement([]byte(in)); err == nil ||
			!strings.Contains(err.Error(), `duplicate key "name"`) {
			t.Fatalf("got %v, want duplicate key rejection", err)
		}
	})
	// Controls: the same name in DIFFERENT objects is not a duplicate —
	// any failure must not be the duplicate-key error.
	for _, ok := range []string{
		`{"a":{"a":1}}`,
		`{"x":[{"a":1},{"a":2}]}`,
		`{"A":1,"a":2}`,
		`{"a":1,"x":{"a":1,"b":{"a":1}}}`,
	} {
		if _, err := evidence.UnmarshalPredicate([]byte(ok)); err != nil &&
			strings.Contains(err.Error(), "duplicate key") {
			t.Fatalf("%s wrongly rejected as duplicate: %v", ok, err)
		}
	}
}
