// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Deterministic rejecting tests: each step V1–V11 and V15 of 03 §10 is
// defended by an aimed case, so disabling any single step fails a
// non-fuzz check (supervisor review of M1.4).
package ledger_test

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/ledger"
	"github.com/countersign/countersign/internal/ledger/ldtest"
	"github.com/countersign/countersign/internal/mlog"
	"github.com/countersign/countersign/internal/names"
)

// sealedSession builds a minimal valid sealed session and returns the
// bundle members plus the session.
func sealedSession(t *testing.T, mid func(l *ledger.Ledger, s *ldtest.Session)) (map[string][]byte, *ldtest.Session) {
	t.Helper()
	dir := t.TempDir()
	s := ldtest.New(names.APIGroup + "/log/test")
	l, err := ledger.Open(dir, s.Origin, s.LogSigner)
	if err != nil {
		t.Fatal(err)
	}
	s.Open(l, "enforce")
	s.Emit(l, "broker", "effect.http", ldtest.Body("effect.http", map[string]any{
		"effect_id": "e1", "class": "safe",
		"decision": map[string]any{"action": "allow", "reason": "OK", "requires": "allow"},
	}))
	s.Emit(l, "broker", "effect.http.result", ldtest.Body("effect.http.result", map[string]any{
		"effect_id": "e1", "served_by": "upstream",
	}))
	s.Emit(l, "world", "world.rewound", ldtest.Body("world.rewound", nil))
	s.Emit(l, "observer", "effect.exec", ldtest.Body("effect.exec", nil))
	if mid != nil {
		mid(l, s)
	}
	s.Emit(l, "world", "world.closed", ldtest.Body("world.closed", map[string]any{
		"outcome": "committed", "commits": []string{},
	}))
	s.EmitterSeal(l, "broker")
	s.EmitterSeal(l, "world")
	s.EmitterSeal(l, "observer")
	s.Seal(l)
	b, err := l.ExportBundle(s.ID, s.Manifest, s.Extras())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	members, err := ledger.ReadBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	return members, s
}

// clone returns a deep copy of members so a mutation cannot leak.
func clone(m map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

// (hasCode from ledger_test.go asserts a finding list contains a code.)

func lines(m map[string][]byte) [][]byte {
	return bytes.Split(bytes.TrimSuffix(m["records.jsonl"], []byte("\n")), []byte("\n"))
}

func TestC143_VSteps(t *testing.T) {
	members, s := sealedSession(t, nil)
	trusted := s.Manifest

	t.Run("V2_schema", func(t *testing.T) {
		m := clone(members)
		ls := lines(m)
		// Corrupt the envelope JSON of record 1 so strict decode fails.
		ls[1] = append([]byte(`{"payloadType":"x"),`), ls[1][30:]...)
		m["records.jsonl"] = bytes.Join(ls, []byte("\n"))
		res := ledger.VerifyBundle2(m, trusted)
		hasCode(res.Errors, "E_SCHEMA", t)
	})

	t.Run("V3_signature", func(t *testing.T) {
		m := clone(members)
		// Flip a base64 character inside the first signature.
		ls := lines(m)
		// Flip one base64 character inside record 0's signature —
		// length preserved, ed25519 fails → E_SIG.
		var env map[string]any
		if err := json.Unmarshal(ls[0], &env); err != nil {
			t.Fatal(err)
		}
		sig0 := env["signatures"].([]any)[0].(map[string]any)
		sig := sig0["sig"].(string)
		flip := "A"
		if sig[0] == 'A' {
			flip = "B"
		}
		sig0["sig"] = flip + sig[1:]
		raw, _ := json.Marshal(env)
		ls[0] = raw
		m["records.jsonl"] = bytes.Join(ls, []byte("\n"))
		res := ledger.VerifyBundle2(m, trusted)
		hasCode(res.Errors, "E_SIG", t)
	})

	t.Run("V3_validity_window", func(t *testing.T) {
		// The trusted manifest claims every key is valid only from
		// 2030 → every record's key fails the window → E_KEY.
		m2 := append(keys.Manifest(nil), trusted...)
		for i := range m2 {
			m2[i].NotBefore = "2030-01-01T00:00:00Z"
		}
		res := ledger.VerifyBundle2(members, m2)
		hasCode(res.Errors, "E_KEY", t)
	})

	t.Run("V4_session", func(t *testing.T) {
		m := clone(members)
		// Manifest claims a different session ULID.
		var man map[string]any
		if err := json.Unmarshal(m["manifest.json"], &man); err != nil {
			t.Fatal(err)
		}
		man["session"] = "01J0000000000000000000ZZZZ"
		raw, _ := json.Marshal(man)
		m["manifest.json"] = raw
		res := ledger.VerifyBundle2(m, trusted)
		hasCode(res.Errors, "E_SESSION", t)
	})

	t.Run("V5_chain", func(t *testing.T) {
		m := clone(members)
		ls := lines(m)
		// Swap broker records 1 and 2 (same emitter) → eprev mismatch.
		ls[1], ls[2] = ls[2], ls[1]
		m["records.jsonl"] = bytes.Join(ls, []byte("\n"))
		res := ledger.VerifyBundle2(m, trusted)
		hasCode(res.Errors, "E_CHAIN", t)
	})

	t.Run("V6_checkpoint_origin", func(t *testing.T) {
		m := clone(members)
		cp := &mlog.Checkpoint{Origin: names.APIGroup + "/log/other", Size: 1}
		data, err := mlog.SignCheckpoint(cp, s.LogSigner)
		if err != nil {
			t.Fatal(err)
		}
		m["checkpoint.txt"] = data
		res := ledger.VerifyBundle2(m, trusted)
		hasCode(res.Errors, "E_CHECKPOINT", t)
	})

	t.Run("V6_checkpoint_emitter_key", func(t *testing.T) {
		m := clone(members)
		cp := &mlog.Checkpoint{Origin: s.Origin, Size: 1}
		data, err := mlog.SignCheckpoint(cp, s.Signers["broker"])
		if err != nil {
			t.Fatal(err)
		}
		m["checkpoint.txt"] = data
		res := ledger.VerifyBundle2(m, trusted)
		hasCode(res.Errors, "E_CHECKPOINT", t)
	})

	t.Run("V7_inclusion_proof", func(t *testing.T) {
		m := clone(members)
		var ix []map[string]any
		if err := json.Unmarshal(m["index.json"], &ix); err != nil {
			t.Fatal(err)
		}
		p := ix[2]["inclusion_proof"].([]any)[0].(string)
		b, _ := base64.StdEncoding.DecodeString(p)
		b[0] ^= 0xff
		ix[2]["inclusion_proof"].([]any)[0] = base64.StdEncoding.EncodeToString(b)
		raw, _ := json.Marshal(ix)
		m["index.json"] = raw
		res := ledger.VerifyBundle2(m, trusted)
		hasCode(res.Errors, "E_INCLUSION", t)
	})

	t.Run("V7_log_index_order", func(t *testing.T) {
		m := clone(members)
		var ix []json.RawMessage
		if err := json.Unmarshal(m["index.json"], &ix); err != nil {
			t.Fatal(err)
		}
		ix[1], ix[2] = ix[2], ix[1]
		raw, _ := json.Marshal(ix)
		m["index.json"] = raw
		res := ledger.VerifyBundle2(m, trusted)
		hasCode(res.Errors, "E_INCLUSION", t)
	})

	t.Run("V8_policy_digest", func(t *testing.T) {
		m := clone(members)
		m["policy.yaml"] = append(m["policy.yaml"], 'x')
		res := ledger.VerifyBundle2(m, trusted)
		hasCode(res.Errors, "E_POLICY", t)
	})

	t.Run("V10_seal_head", func(t *testing.T) {
		// The seal claims a head hash that is not the broker chain's →
		// E_SEAL. Chains stay consistent; only the claim is wrong.
		dir := t.TempDir()
		sx := ldtest.New(names.APIGroup + "/log/test")
		l, err := ledger.Open(dir, sx.Origin, sx.LogSigner)
		if err != nil {
			t.Fatal(err)
		}
		sx.Open(l, "enforce")
		sx.Emit(l, "broker", "effect.http", ldtest.Body("effect.http", nil))
		sx.Emit(l, "observer", "effect.exec", ldtest.Body("effect.exec", nil))
		sx.Emit(l, "world", "world.rewound", ldtest.Body("world.rewound", nil))
		sx.Emit(l, "world", "world.closed", ldtest.Body("world.closed", map[string]any{
			"outcome": "committed", "commits": []string{},
		}))
		sx.EmitterSeal(l, "broker")
		sx.EmitterSeal(l, "world")
		sx.EmitterSeal(l, "observer")
		var ems []evidence.SealEmitter
		for _, role := range []string{"controller", "broker", "world", "observer"} {
			es, hh := sx.Head(role)
			if role == "broker" {
				hh = strings.Repeat("0", 64)
			}
			ems = append(ems, evidence.SealEmitter{
				Emitter:   sx.Emitters[role].Name(),
				FinalEseq: es, HeadHash: hh, Clean: true,
			})
		}
		sx.Emit(l, "controller", "session.seal", ldtest.Body("session.seal", map[string]any{
			"emitters": ems, "counts": map[string]any{},
		}))
		b, err := l.ExportBundle(sx.ID, sx.Manifest, sx.Extras())
		if err != nil {
			t.Fatal(err)
		}
		_ = l.Close()
		m2, err := ledger.ReadBundle(b)
		if err != nil {
			t.Fatal(err)
		}
		res := ledger.VerifyBundle2(m2, sx.Manifest)
		hasCode(res.Errors, "E_SEAL", t)
	})

	t.Run("V11_structure", func(t *testing.T) {
		m, s3 := sealedSession(t, func(l *ledger.Ledger, s *ldtest.Session) {
			// A result record naming an effect that was never emitted.
			s.Emit(l, "broker", "effect.http.result", ldtest.Body("effect.http.result", map[string]any{
				"effect_id": "ghost", "served_by": "upstream",
			}))
		})
		res := ledger.VerifyBundle2(m, s3.Manifest)
		hasCode(res.Errors, "E_STRUCTURE", t)
	})
}

// V8 first-record rule and V9 need scenario variants (mutating records
// would break chains and land on INVALID before the aimed finding).
func TestC143_V8_V9(t *testing.T) {
	t.Run("V8_open", func(t *testing.T) {
		dir := t.TempDir()
		s := ldtest.New(names.APIGroup + "/log/test")
		l, err := ledger.Open(dir, s.Origin, s.LogSigner)
		if err != nil {
			t.Fatal(err)
		}
		// First record is not session.open.
		s.Emit(l, "controller", "sandbox.terminated", ldtest.Body("sandbox.terminated", nil))
		s.Emit(l, "broker", "effect.exec", ldtest.Body("effect.exec", nil))
		s.Emit(l, "world", "world.rewound", ldtest.Body("world.rewound", nil))
		s.Emit(l, "observer", "effect.exec", ldtest.Body("effect.exec", nil))
		s.Emit(l, "world", "world.closed", ldtest.Body("world.closed", map[string]any{
			"outcome": "committed", "commits": []string{},
		}))
		s.EmitterSeal(l, "broker")
		s.EmitterSeal(l, "world")
		s.EmitterSeal(l, "observer")
		s.Seal(l)
		b, err := l.ExportBundle(s.ID, s.Manifest, s.Extras())
		if err != nil {
			t.Fatal(err)
		}
		_ = l.Close()
		m, err := ledger.ReadBundle(b)
		if err != nil {
			t.Fatal(err)
		}
		res := ledger.VerifyBundle2(m, s.Manifest)
		hasCode(res.Errors, "E_OPEN", t)
	})

	t.Run("V9_unsealed", func(t *testing.T) {
		dir := t.TempDir()
		s := ldtest.New(names.APIGroup + "/log/test")
		l, err := ledger.Open(dir, s.Origin, s.LogSigner)
		if err != nil {
			t.Fatal(err)
		}
		s.Open(l, "enforce")
		s.Emit(l, "broker", "effect.exec", ldtest.Body("effect.exec", nil))
		s.Emit(l, "world", "world.rewound", ldtest.Body("world.rewound", nil))
		s.Emit(l, "observer", "effect.exec", ldtest.Body("effect.exec", nil))
		// No world.closed: the session is left unsealed.
		s.EmitterSeal(l, "broker")
		s.EmitterSeal(l, "world")
		s.EmitterSeal(l, "observer")
		s.Seal(l)
		b, err := l.ExportBundle(s.ID, s.Manifest, s.Extras())
		if err != nil {
			t.Fatal(err)
		}
		_ = l.Close()
		m, err := ledger.ReadBundle(b)
		if err != nil {
			t.Fatal(err)
		}
		res := ledger.VerifyBundle2(m, s.Manifest)
		if res.Verdict != "UNSEALED" {
			t.Fatalf("verdict %s ≠ UNSEALED", res.Verdict)
		}
	})
}

func TestC143_V15Warnings(t *testing.T) {
	cases := []struct {
		name string
		emit func(l *ledger.Ledger, s *ldtest.Session)
		code string
	}{
		{"dangling", func(l *ledger.Ledger, s *ldtest.Session) {
			s.Emit(l, "broker", "effect.http", ldtest.Body("effect.http", map[string]any{
				"effect_id": "dang", "class": "safe",
				"decision": map[string]any{"action": "allow", "reason": "OK", "requires": "allow"},
			}))
		}, "W_DANGLING"},
		{"observer_gap", func(l *ledger.Ledger, s *ldtest.Session) {
			s.Emit(l, "observer", "observer.gap", ldtest.Body("observer.gap", nil))
		}, "W_OBSERVER_GAP"},
		{"unparsed", func(l *ledger.Ledger, s *ldtest.Session) {
			s.Emit(l, "broker", "intent.unparsed", ldtest.Body("intent.unparsed", nil))
		}, "W_UNPARSED"},
		{"partial_commit", func(l *ledger.Ledger, s *ldtest.Session) {
			s.Emit(l, "world", "commit.closed", ldtest.Body("commit.closed", map[string]any{
				"commit_id": "k9", "outcome": "partial",
			}))
		}, "W_PARTIAL_COMMIT"},
		{"apply_unknown", func(l *ledger.Ledger, s *ldtest.Session) {
			s.Emit(l, "world", "commit.applied", ldtest.Body("commit.applied", map[string]any{
				"commit_id": "k9", "entry_id": "en9", "outcome": "unknown", "via_effect": "e1",
			}))
		}, "W_APPLY_UNKNOWN"},
		{"undo_conflict", func(l *ledger.Ledger, s *ldtest.Session) {
			s.Emit(l, "world", "undo.closed", ldtest.Body("undo.closed", map[string]any{
				"undo_id": "u9", "restored": 0, "conflicts": 1, "not_compensable": 0, "failed": 0,
			}))
		}, "W_UNDO_CONFLICT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, s := sealedSession(t, c.emit)
			res := ledger.VerifyBundle2(m, s.Manifest)
			hasCode(res.Warnings, c.code, t)
		})
	}

	t.Run("unclean_emitter", func(t *testing.T) {
		dir := t.TempDir()
		s := ldtest.New(names.APIGroup + "/log/test")
		l, err := ledger.Open(dir, s.Origin, s.LogSigner)
		if err != nil {
			t.Fatal(err)
		}
		s.Open(l, "enforce")
		s.Emit(l, "broker", "effect.exec", ldtest.Body("effect.exec", nil))
		s.Emit(l, "world", "world.rewound", ldtest.Body("world.rewound", nil))
		s.Emit(l, "observer", "effect.exec", ldtest.Body("effect.exec", nil))
		s.Emit(l, "world", "world.closed", ldtest.Body("world.closed", map[string]any{
			"outcome": "committed", "commits": []string{},
		}))
		s.EmitterSeal(l, "world")
		s.EmitterSeal(l, "observer")
		// session.seal claims the broker emitter unclean.
		var ems []evidence.SealEmitter
		for _, role := range []string{"controller", "broker", "world", "observer"} {
			es, hh := s.Head(role)
			ems = append(ems, evidence.SealEmitter{
				Emitter:   s.Emitters[role].Name(),
				FinalEseq: es, HeadHash: hh,
				Clean: role != "broker",
			})
		}
		s.Emit(l, "controller", "session.seal", ldtest.Body("session.seal", map[string]any{
			"emitters": ems, "counts": map[string]any{},
		}))
		b, err := l.ExportBundle(s.ID, s.Manifest, s.Extras())
		if err != nil {
			t.Fatal(err)
		}
		_ = l.Close()
		m, err := ledger.ReadBundle(b)
		if err != nil {
			t.Fatal(err)
		}
		res := ledger.VerifyBundle2(m, s.Manifest)
		hasCode(res.Warnings, "W_UNCLEAN_EMITTER", t)
	})
}

// TestC147_ReaderRejects is the deterministic half of C1.4.7: every
// archive defect class is E_BUNDLE — never a panic, never an
// out-of-range allocation.
func TestC147_ReaderRejects(t *testing.T) {
	members, s := sealedSession(t, nil)
	trusted := s.Manifest
	good := writeTarForTest(members)
	if res := ledger.VerifyBundle(good, trusted); len(res.Errors) != 0 {
		t.Fatalf("baseline bundle not clean: %v", res.Errors)
	}

	// tarBlock returns a 512-byte header block for a member claiming
	// size bytes; built through tar.Writer's own encoder.
	tarBlock := func(name string, size int64) []byte {
		var hb bytes.Buffer
		tw := tar.NewWriter(&hb)
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: size, Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("header build: %v", err)
		}
		return hb.Bytes()[:512]
	}
	pad512 := func(b []byte) []byte {
		rem := len(b) % 512
		if rem == 0 {
			return append([]byte(nil), b...)
		}
		return append(append([]byte(nil), b...), make([]byte, 512-rem)...)
	}
	end := make([]byte, 1024)
	small := []byte("{}")
	// bigMember: header claims `claimed` bytes but only `small` is present.
	bigMember := func(claimed int64) []byte {
		return bytes.Join([][]byte{
			tarBlock("manifest.json", claimed), pad512(small), end,
		}, nil)
	}

	for _, tc := range []struct {
		name   string
		bundle []byte
	}{
		{"truncated_header", good[:len(good)-200]},
		{"truncated_member", good[:len(good)/2]},
		{"trailing_garbage", append(append([]byte(nil), good...), 'X', 'Y', 'Z')},
		{"bad_checksum", func() []byte {
			b := append([]byte(nil), good...)
			b[154] = '9' // corrupt first header checksum digit
			return b
		}()},
		{"giant_claimed_size", bigMember(1 << 60)},
		{"over_member_cap", bigMember(ledger.MaxMemberBytes + 1)},
		{"missing_required", bytes.Join([][]byte{
			tarBlock("manifest.json", int64(len(small))), pad512(small), end,
		}, nil)},
		{"duplicate_member", bytes.Join([][]byte{
			tarBlock("manifest.json", int64(len(small))), pad512(small),
			tarBlock("manifest.json", int64(len(small))), pad512(small), end,
		}, nil)},
		{"non_regular_member", func() []byte {
			var hb bytes.Buffer
			tw := tar.NewWriter(&hb)
			if err := tw.WriteHeader(&tar.Header{
				Name: "manifest.json", Mode: 0o644, Typeflag: tar.TypeDir,
			}); err != nil {
				t.Fatal(err)
			}
			return append(hb.Bytes()[:512], end...)
		}()},
		{"extra_member", func() []byte {
			m := clone(members)
			m["evil.bin"] = []byte{1, 2, 3}
			return writeTarForTest(m)
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := ledger.VerifyBundle(tc.bundle, trusted)
			hasCode(res.Errors, "E_BUNDLE", t)
			if res.Verdict != "INVALID" {
				t.Fatalf("verdict %s ≠ INVALID", res.Verdict)
			}
		})
	}
}

// writeTarForTest mirrors ExportBundle's deterministic tar for tests.
func writeTarForTest(members map[string][]byte) []byte {
	names := make([]string, 0, len(members))
	for n := range members {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range names {
		data := members[n]
		if err := tw.WriteHeader(&tar.Header{
			Name: n, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg,
		}); err != nil {
			panic(err)
		}
		if _, err := tw.Write(data); err != nil {
			panic(err)
		}
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
