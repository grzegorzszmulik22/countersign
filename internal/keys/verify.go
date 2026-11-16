// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/countersign/countersign/internal/evidence"
)

// Verification error classes (03 §10). The verifier maps these to codes.
var (
	ErrKey   = errors.New("E_KEY")
	ErrSig   = errors.New("E_SIG")
	ErrChain = errors.New("E_CHAIN")
)

// VerifyRecord checks a record against the trusted manifest (V3 + role check).
// Role rule: an emitter:<role> key may sign only records whose emitter is
// "<role>/<instance>"; log/attestor/reviewer/witness roles may not sign
// emitter records at all.
func VerifyRecord(env *evidence.Envelope, r *evidence.Record, m Manifest) error {
	sig := env.Signatures[0]
	entry, ok := m.Find(sig.KeyID)
	if !ok {
		return fmt.Errorf("%w: unknown key %s", ErrKey, sig.KeyID)
	}
	role, _, err := evidence.EmitterRole(r.Emitter)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrKey, err)
	}
	if entry.Role != EmitterRole(role) {
		return fmt.Errorf("%w: key %s role %q cannot sign %s", ErrKey, sig.KeyID, entry.Role, r.Emitter)
	}
	if !entry.CoversTS(r.TS) {
		return fmt.Errorf("%w: key %s not valid at %s", ErrKey, sig.KeyID, r.TS)
	}
	pub, err := entry.Public()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrKey, err)
	}
	if !ed25519.Verify(pub, env.PAE(), sig.Sig) {
		return fmt.Errorf("%w: signature on %s invalid", ErrSig, r.ID)
	}
	return nil
}
