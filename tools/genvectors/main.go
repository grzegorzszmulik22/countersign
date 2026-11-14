// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// genvectors regenerates the golden evidence bundles under
// test/vectors/evidence/: <name>.tar, <name>.keys.json, <name>.expected.json.
// Each golden is produced by building a real session in a scratch ledger,
// exporting, then applying a targeted mutation. The expected file is the
// verifier output at generation time, asserted against the verdict and
// codes baked into the recipe so a wrong verifier fails here, loudly.
package main

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/ledger"
	"github.com/countersign/countersign/internal/ledger/ldtest"
)

const origin = "countersign.dev/log/test"

type recipe struct {
	name    string
	build   func(*ldtest.Session, *ledger.Ledger)
	mutate  func(members map[string][]byte, keysJSON []byte) (map[string][]byte, []byte)
	verdict string
	codes   []string // codes that must appear in errors
	warns   []string // codes that must appear in warnings
}

func main() {
	dir := "test/vectors/evidence"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fatal(err)
	}

	recipes := []recipe{
		{name: "clean", verdict: "CLEAN",
			build: func(s *ldtest.Session, l *ledger.Ledger) { ldtest.CleanAllTypes(l, s) }},
		{name: "denials", verdict: "CLEAN_WITH_DENIALS",
			build: func(s *ldtest.Session, l *ledger.Ledger) {
				s.Open(l, "enforce")
				s.Emit(l, "broker", "effect.denied", ldtest.Body("effect.denied", map[string]any{
					"reason": "DENY_GRANT", "detail": "policy",
				}))
				s.Emit(l, "world", "world.closed", ldtest.Body("world.closed", map[string]any{"outcome": "empty"}))
				s.EmitterSeal(l, "broker")
				s.EmitterSeal(l, "world")
				s.EmitterSeal(l, "observer")
				s.Seal(l)
			}},
		{name: "unsealed", verdict: "UNSEALED",
			build: func(s *ldtest.Session, l *ledger.Ledger) {
				s.Open(l, "enforce")
				s.Emit(l, "broker", "effect.http", ldtest.Body("effect.http", map[string]any{
					"effect_id": "e1",
					"decision":  map[string]any{"action": "allow", "reason": "OK", "requires": "allow"},
				}))
				s.Emit(l, "broker", "effect.http.result", ldtest.Body("effect.http.result", map[string]any{"effect_id": "e1"}))
			}},
		{name: "dangling", verdict: "CLEAN", warns: []string{"W_DANGLING"},
			build: func(s *ldtest.Session, l *ledger.Ledger) {
				s.Open(l, "enforce")
				s.Emit(l, "broker", "effect.http", ldtest.Body("effect.http", map[string]any{
					"effect_id": "e9",
					"decision":  map[string]any{"action": "allow", "reason": "OK", "requires": "allow"},
				}))
				s.Emit(l, "world", "world.closed", ldtest.Body("world.closed", map[string]any{"outcome": "empty"}))
				s.EmitterSeal(l, "broker")
				s.EmitterSeal(l, "world")
				s.EmitterSeal(l, "observer")
				s.Seal(l)
			}},
		{name: "multi-emitter", verdict: "CLEAN",
			build: func(s *ldtest.Session, l *ledger.Ledger) { ldtest.CleanAllTypes(l, s) }},
		{name: "e_bundle", verdict: "INVALID", codes: []string{"E_BUNDLE"},
			build: func(s *ldtest.Session, l *ledger.Ledger) { ldtest.CleanAllTypes(l, s) },
			mutate: func(m map[string][]byte, k []byte) (map[string][]byte, []byte) {
				delete(m, "checkpoint.txt")
				return m, k
			}},
		{name: "e_schema", verdict: "INVALID", codes: []string{"E_SCHEMA"},
			build: func(s *ldtest.Session, l *ledger.Ledger) { ldtest.CleanAllTypes(l, s) },
			mutate: func(m map[string][]byte, k []byte) (map[string][]byte, []byte) {
				lines := bytes.Split(m["records.jsonl"], []byte("\n"))
				// Corrupt the second line's JSON syntax.
				l2 := append([]byte(nil), lines[1]...)
				l2[10] = '{'
				lines[1] = l2
				m["records.jsonl"] = bytes.Join(lines, []byte("\n"))
				return m, k
			}},
		{name: "e_sig", verdict: "INVALID", codes: []string{"E_SIG"},
			build: func(s *ldtest.Session, l *ledger.Ledger) { ldtest.CleanAllTypes(l, s) },
			mutate: func(m map[string][]byte, k []byte) (map[string][]byte, []byte) {
				lines := bytes.Split(m["records.jsonl"], []byte("\n"))
				env, err := evidence.UnmarshalEnvelope(lines[1])
				if err != nil {
					panic(err)
				}
				env.Signatures[0].Sig[0] ^= 1
				b, err := evidence.MarshalEnvelope(env)
				if err != nil {
					panic(err)
				}
				lines[1] = b
				m["records.jsonl"] = bytes.Join(lines, []byte("\n"))
				return m, k
			}},
		{name: "e_key", verdict: "INVALID", codes: []string{"E_KEY"},
			build: func(s *ldtest.Session, l *ledger.Ledger) { ldtest.CleanAllTypes(l, s) },
			mutate: func(m map[string][]byte, k []byte) (map[string][]byte, []byte) {
				man, err := keys.UnmarshalManifest(k)
				if err != nil {
					panic(err)
				}
				// The trusted manifest claims the broker key is emitter:world.
				for i := range man {
					if man[i].Role == "emitter:broker" {
						man[i].Role = "emitter:world"
					}
				}
				out, err := keys.MarshalManifest(man)
				if err != nil {
					panic(err)
				}
				return m, out
			}},
		{name: "e_session", verdict: "INVALID", codes: []string{"E_SESSION"},
			build: func(s *ldtest.Session, l *ledger.Ledger) { ldtest.CleanAllTypes(l, s) },
			mutate: func(m map[string][]byte, k []byte) (map[string][]byte, []byte) {
				var man map[string]any
				if err := json.Unmarshal(m["manifest.json"], &man); err != nil {
					panic(err)
				}
				man["session"] = "01K7D7JQ9Y8T4X2Z6B4H4F4F4E"
				b, err := json.Marshal(man)
				if err != nil {
					panic(err)
				}
				m["manifest.json"] = append(b, '\n')
				return m, k
			}},
		{name: "e_chain", verdict: "INVALID", codes: []string{"E_CHAIN"},
			build: func(s *ldtest.Session, l *ledger.Ledger) { ldtest.CleanAllTypes(l, s) },
			mutate: func(m map[string][]byte, k []byte) (map[string][]byte, []byte) {
				// Swap two adjacent broker records (lines and index entries).
				lines := bytes.Split(m["records.jsonl"], []byte("\n"))
				idx, err := ledger.ParseIndex(m["index.json"])
				if err != nil {
					panic(err)
				}
				// find two consecutive same-emitter records
				for i := 1; i+1 < len(lines); i++ {
					_, _, r1, e1 := evidence.DecodeRecordLine(lines[i])
					_, _, r2, e2 := evidence.DecodeRecordLine(lines[i+1])
					if e1 == nil && e2 == nil && r1.Emitter == r2.Emitter {
						lines[i], lines[i+1] = lines[i+1], lines[i]
						idx[i], idx[i+1] = idx[i+1], idx[i]
						break
					}
				}
				m["records.jsonl"] = bytes.Join(lines, []byte("\n"))
				b, _ := json.Marshal(idx)
				m["index.json"] = append(b, '\n')
				return m, k
			}},
		{name: "e_checkpoint", verdict: "INVALID", codes: []string{"E_CHECKPOINT"},
			build: func(s *ldtest.Session, l *ledger.Ledger) { ldtest.CleanAllTypes(l, s) },
			mutate: func(m map[string][]byte, k []byte) (map[string][]byte, []byte) {
				cp := append([]byte(nil), m["checkpoint.txt"]...)
				// Flip one bit inside the signature line.
				i := bytes.LastIndexByte(cp, ' ')
				cp[i+3] ^= 1
				m["checkpoint.txt"] = cp
				return m, k
			}},
		{name: "e_inclusion", verdict: "INVALID", codes: []string{"E_INCLUSION"},
			build: func(s *ldtest.Session, l *ledger.Ledger) { ldtest.CleanAllTypes(l, s) },
			mutate: func(m map[string][]byte, k []byte) (map[string][]byte, []byte) {
				idx, err := ledger.ParseIndex(m["index.json"])
				if err != nil {
					panic(err)
				}
				if len(idx[1].InclusionProof) == 0 {
					idx[1].InclusionProof = []string{base64.StdEncoding.EncodeToString(make([]byte, 32))}
				} else {
					b, _ := base64.StdEncoding.DecodeString(idx[1].InclusionProof[0])
					b[0] ^= 1
					idx[1].InclusionProof[0] = base64.StdEncoding.EncodeToString(b)
				}
				b, _ := json.Marshal(idx)
				m["index.json"] = append(b, '\n')
				return m, k
			}},
		{name: "e_open", verdict: "INVALID", codes: []string{"E_OPEN"},
			build: func(s *ldtest.Session, l *ledger.Ledger) { ldtest.CleanAllTypes(l, s) },
			mutate: func(m map[string][]byte, k []byte) (map[string][]byte, []byte) {
				// Remove the first record (session.open) and its index row.
				lines := bytes.Split(m["records.jsonl"], []byte("\n"))
				m["records.jsonl"] = bytes.Join(lines[1:], []byte("\n"))
				idx, _ := ledger.ParseIndex(m["index.json"])
				b, _ := json.Marshal(idx[1:])
				m["index.json"] = append(b, '\n')
				return m, k
			}},
		{name: "e_policy", verdict: "INVALID", codes: []string{"E_POLICY"},
			build: func(s *ldtest.Session, l *ledger.Ledger) { ldtest.CleanAllTypes(l, s) },
			mutate: func(m map[string][]byte, k []byte) (map[string][]byte, []byte) {
				p := append([]byte(nil), m["policy.yaml"]...)
				p[0] ^= 1
				m["policy.yaml"] = p
				return m, k
			}},
		{name: "e_seal", verdict: "INVALID", codes: []string{"E_SEAL"},
			build: func(s *ldtest.Session, l *ledger.Ledger) {
				// Seal claims a wrong final_eseq for the broker emitter.
				s.Open(l, "enforce")
				s.Emit(l, "world", "world.closed", ldtest.Body("world.closed", map[string]any{"outcome": "empty"}))
				s.EmitterSeal(l, "broker")
				s.EmitterSeal(l, "world")
				s.EmitterSeal(l, "observer")
				var ems []evidence.SealEmitter
				for _, role := range []string{"controller", "broker", "world", "observer"} {
					em := s.Emitters[role]
					// heads are internal; rebuild from emitted lines via a
					// chain check is overkill here — claim eseq+5 for broker.
					fe, hh := s.Head(role)
					if role == "broker" {
						fe += 5
					}
					ems = append(ems, evidence.SealEmitter{Emitter: em.Name(), FinalEseq: fe, HeadHash: hh, Clean: true})
				}
				s.Emit(l, "controller", "session.seal", ldtest.Body("session.seal", map[string]any{
					"emitters": ems, "counts": map[string]any{},
				}))
			}},
		{name: "e_structure", verdict: "INVALID", codes: []string{"E_STRUCTURE"},
			build: func(s *ldtest.Session, l *ledger.Ledger) {
				// intent.result BEFORE its intent.declared — valid chain,
				// structure violation.
				s.Open(l, "enforce")
				s.Emit(l, "broker", "effect.http", ldtest.Body("effect.http", map[string]any{
					"effect_id": "e1",
					"decision":  map[string]any{"action": "allow", "reason": "OK", "requires": "allow"},
				}))
				s.Emit(l, "broker", "intent.result", ldtest.Body("intent.result", map[string]any{
					"intent_id": "i1", "via_effect": "e1",
				}))
				s.Emit(l, "broker", "intent.declared", ldtest.Body("intent.declared", map[string]any{
					"intent_id": "i1", "via_effect": "e1",
				}))
				s.Emit(l, "broker", "effect.http.result", ldtest.Body("effect.http.result", map[string]any{"effect_id": "e1"}))
				s.Emit(l, "world", "world.closed", ldtest.Body("world.closed", map[string]any{"outcome": "empty"}))
				s.EmitterSeal(l, "broker")
				s.EmitterSeal(l, "world")
				s.EmitterSeal(l, "observer")
				s.Seal(l)
			}},
	}

	for _, r := range recipes {
		if err := gen(dir, r); err != nil {
			fatal(fmt.Errorf("%s: %w", r.name, err))
		}
	}
	fmt.Printf("wrote %d golden bundles to %s\n", len(recipes), dir)
}

// gen builds the session, exports the bundle, mutates, verifies, asserts.
func gen(dir string, r recipe) error {
	tmp, err := os.MkdirTemp("", "genvec")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	s := ldtest.New(origin)
	l, err := ledger.Open(tmp, origin, s.LogSigner)
	if err != nil {
		return err
	}
	r.build(s, l)
	bundle, err := l.ExportBundle(s.ID, s.Manifest, s.Extras())
	if err != nil {
		return err
	}
	_ = l.Close()

	keysJSON, err := keys.MarshalManifest(s.Manifest)
	if err != nil {
		return err
	}
	members, err := ledger.ReadBundle(bundle)
	if err != nil {
		return err
	}
	if r.mutate != nil {
		members, keysJSON = r.mutate(members, keysJSON)
		bundle = writeMembers(members)
	}
	if err := os.WriteFile(filepath.Join(dir, r.name+".tar"), bundle, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, r.name+".keys.json"), keysJSON, 0o644); err != nil {
		return err
	}

	man, err := keys.UnmarshalManifest(keysJSON)
	if err != nil {
		return err
	}
	res := ledger.VerifyBundle(bundle, man)
	if res.Verdict != r.verdict {
		return fmt.Errorf("verdict %s, want %s (errors %v)", res.Verdict, r.verdict, res.Errors)
	}
	got := codes(res.Errors)
	for _, want := range r.codes {
		if !got[want] {
			return fmt.Errorf("missing error code %s (got %v)", want, res.Errors)
		}
	}
	gotW := codes(res.Warnings)
	for _, want := range r.warns {
		if !gotW[want] {
			return fmt.Errorf("missing warning %s (got %v)", want, res.Warnings)
		}
	}
	exp, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, r.name+".expected.json"), append(exp, '\n'), 0o644)
}

func codes(fs []ledger.Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range fs {
		out[f.Code] = true
	}
	return out
}

// writeMembers re-packs mutated members into a deterministic tar.
func writeMembers(members map[string][]byte) []byte {
	names := make([]string, 0, len(members))
	for n := range members {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range names {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(members[n])), Typeflag: tar.TypeReg})
		_, _ = tw.Write(members[n])
	}
	_ = tw.Close()
	return buf.Bytes()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "genvectors:", err)
	os.Exit(1)
}
