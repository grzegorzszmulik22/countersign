// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Package ldtest builds realistic sessions for ledger tests and the
// test-vector generator. Test support only — not part of the ledger.
package ldtest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/evidence/evtest"
	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/ledger"
)

const TS = "2026-11-14T00:00:00.000000000Z"

// Session is a builder emitting one session's records into a ledger.
type Session struct {
	ID        string
	Origin    string
	Signers   map[string]keys.Signer
	Emitters  map[string]*keys.Emitter
	LogSigner keys.Signer
	Manifest  keys.Manifest
	Policy    []byte
	Contracts map[string][]byte
	Reviews   map[string][]byte
	heads     map[string]head
}

type head struct {
	eseq uint64
	hash string
}

// New creates emitters for the four roles plus a log key and a manifest
// covering all of them. origin is the ledger's checkpoint origin.
func New(origin string) *Session {
	s := &Session{
		ID: evidence.NewULID(nil), Origin: origin,
		Signers: map[string]keys.Signer{}, Emitters: map[string]*keys.Emitter{},
		heads:  map[string]head{},
		Policy: []byte("rules:\n  - class: control\n    autonomy: deny\n"),
		Contracts: map[string][]byte{
			"contracts/fs.yaml": []byte("api: fs\nargs:\n  path: string\n"),
		},
		Reviews: map[string][]byte{},
	}
	ents := []keys.ManifestEntry{}
	mk := func(seed byte, role string) keys.Signer {
		sg := keys.NewSigner(bytes.Repeat([]byte{seed}, 32))
		ents = append(ents, keys.ManifestEntry{
			Role: keys.EmitterRole(role), Signer: sg, NotBefore: "2020-01-01T00:00:00Z",
		})
		s.Signers[role] = sg
		return sg
	}
	for i, role := range []string{"controller", "broker", "world", "observer"} {
		sg := mk(byte(0x10+i), role)
		s.Emitters[role] = keys.NewEmitter(role, s.ID, sg)
	}
	s.LogSigner = keys.NewSigner(bytes.Repeat([]byte{0x77}, 32))
	ents = append(ents, keys.ManifestEntry{
		Role: "log", Signer: s.LogSigner, NotBefore: "2020-01-01T00:00:00Z",
	})
	m, err := keys.NewManifest(ents)
	if err != nil {
		panic(err)
	}
	s.Manifest = m
	return s
}

// Body returns a sample body of the type with the named overrides applied
// through a JSON merge (field names as in 03 §4).
func Body(t string, over map[string]any) any {
	b, err := evtest.Sample(t)
	if err != nil {
		panic(err)
	}
	if len(over) == 0 {
		return b
	}
	raw, err := json.Marshal(b)
	if err != nil {
		panic(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		panic(err)
	}
	for k, v := range over {
		m[k] = v
	}
	raw, err = json.Marshal(m)
	if err != nil {
		panic(err)
	}
	fresh, ok := evidence.NewBody(t)
	if !ok {
		panic(t)
	}
	if err := json.Unmarshal(raw, fresh); err != nil {
		panic(fmt.Errorf("%s overrides: %w", t, err))
	}
	return fresh
}

// Emit signs one record through the role's emitter and appends it to l.
func (s *Session) Emit(l *ledger.Ledger, role, typ string, body any) []byte {
	line, rec, err := s.Emitters[role].Emit(typ, body, TS)
	if err != nil {
		panic(err)
	}
	if _, err := l.Append(line); err != nil {
		panic(err)
	}
	env, _, _, err := evidence.DecodeRecordLine(line)
	if err != nil {
		panic(err)
	}
	roleName, _, _ := evidence.EmitterRole(rec.Emitter)
	s.heads[roleName] = head{rec.Eseq, evidence.RecordHash(env)}
	return line
}

// Head returns the emitter's current chain head (eseq, record hash).
func (s *Session) Head(role string) (uint64, string) {
	h := s.heads[role]
	return h.eseq, h.hash
}

// EmitterSeal emits the emitter.seal record for role.
func (s *Session) EmitterSeal(l *ledger.Ledger, role string) {
	s.Emit(l, role, "emitter.seal", Body("emitter.seal", nil))
}

// Seal writes session.seal from the controller. For each non-sealing
// emitter the entry lists its current chain head; the sealing emitter's
// entry lists its head immediately before the seal record (a record can
// never contain its own hash).
func (s *Session) Seal(l *ledger.Ledger) {
	var ems []evidence.SealEmitter
	for _, role := range []string{"controller", "broker", "world", "observer"} {
		em := s.Emitters[role]
		h := s.heads[role]
		ems = append(ems, evidence.SealEmitter{
			Emitter: em.Name(), FinalEseq: h.eseq, HeadHash: h.hash, Clean: true,
		})
	}
	s.Emit(l, "controller", "session.seal", Body("session.seal", map[string]any{
		"emitters": ems,
		"counts":   map[string]any{},
	}))
}

// Open emits the session.open record with digests matching Policy/Contracts.
func (s *Session) Open(l *ledger.Ledger, mode string) {
	sum := sha256.Sum256(s.Policy)
	var digests []string
	for _, c := range s.Contracts {
		h := sha256.Sum256(c)
		digests = append(digests, hex.EncodeToString(h[:]))
	}
	s.Emit(l, "controller", "session.open", Body("session.open", map[string]any{
		"kind": "agent", "mode": mode,
		"policy_digest":    hex.EncodeToString(sum[:]),
		"contract_digests": digests,
		"log_origin":       s.Origin,
		"principal":        map[string]any{"subject": "agent", "issuer": "countersign", "method": "enrollment"},
		"sandbox":          map[string]any{"namespace": "ns", "pod": "p", "pod_uid": "u", "node": "n", "image_digest": fmt.Sprintf("%x", sha256.Sum256([]byte("img")))},
		"ca_cert_sha256":   fmt.Sprintf("%x", sha256.Sum256([]byte("ca"))),
		"world":            map[string]any{"id": s.ID},
		"tape":             map[string]any{"enabled": false},
	}))
}

// Extras returns the bundle extras map for ExportBundle.
func (s *Session) Extras() map[string][]byte {
	out := map[string][]byte{"policy.yaml": s.Policy}
	for n, b := range s.Contracts {
		out[n] = b
	}
	for n, b := range s.Reviews {
		out["reviews/"+n+".json"] = b
	}
	return out
}
