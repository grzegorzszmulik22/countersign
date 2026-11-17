// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"fmt"

	"github.com/countersign/countersign/internal/evidence"
)

// Emitter assigns eseq/eprev and signs records for one
// "<role>/<instance>" chain (02 §4). A restart creates a new instance
// ULID and a fresh chain at eseq 0.
type Emitter struct {
	role     string
	session  string
	instance string
	signer   Signer
	eseq     uint64
	eprev    string
	sealed   bool
	lines    [][]byte
}

// NewEmitter starts a fresh chain. role is broker|controller|world|observer.
func NewEmitter(role, session string, signer Signer) *Emitter {
	return &Emitter{
		role:     role,
		session:  session,
		instance: evidence.NewULID(nil),
		signer:   signer,
		eprev:    evidence.ZeroHash,
	}
}

// Instance is this emitter instance's ULID.
func (e *Emitter) Instance() string { return e.instance }

// Name is "<role>/<instance>" — the record emitter field.
func (e *Emitter) Name() string { return e.role + "/" + e.instance }

// Lines returns every emitted record line, in order (for tests/tools).
func (e *Emitter) Lines() [][]byte { return e.lines }

// Emit builds, signs, and returns the canonical record line (JSON, no
// trailing newline — the newline is added by the ledger, not the emitter).
func (e *Emitter) Emit(typeName string, body any, ts string) ([]byte, *evidence.Record, error) {
	if e.sealed {
		return nil, nil, fmt.Errorf("%s: emit after emitter.seal", e.Name())
	}
	r := &evidence.Record{
		V: 1, Type: typeName, ID: evidence.NewULID(nil),
		Session: e.session, Emitter: e.Name(),
		Eseq: e.eseq, Eprev: e.eprev, TS: ts,
		Body: body,
	}
	pred, err := evidence.MarshalPredicate(r)
	if err != nil {
		return nil, nil, err
	}
	stBytes, err := evidence.MarshalStatement(evidence.NewStatement(r.Session, pred))
	if err != nil {
		return nil, nil, err
	}
	env := &evidence.Envelope{PayloadType: evidence.PayloadType, Payload: stBytes}
	env.Signatures = []evidence.Signature{{
		KeyID: e.signer.KeyID(),
		Sig:   e.signer.Sign(env.PAE()),
	}}
	line, err := evidence.MarshalEnvelope(env)
	if err != nil {
		return nil, nil, err
	}
	e.eprev = evidence.RecordHash(env)
	e.eseq++
	if typeName == "emitter.seal" {
		e.sealed = true
	}
	e.lines = append(e.lines, line)
	return line, r, nil
}
