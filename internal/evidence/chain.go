// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// ZeroHash is the eprev of every emitter's first record (03 §2).
const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// RecordHash is the record hash of 03 §3: SHA-256 of the PAE bytes.
func RecordHash(env *Envelope) string {
	sum := sha256.Sum256(env.PAE())
	return hex.EncodeToString(sum[:])
}

// EmitterRole splits "<role>/<instance>" (03 §2).
func EmitterRole(emitter string) (role, instance string, err error) {
	role, instance, ok := strings.Cut(emitter, "/")
	if !ok || role == "" || !ValidULID(instance) {
		return "", "", fmt.Errorf("malformed emitter %q", emitter)
	}
	switch role {
	case "broker", "controller", "world", "observer":
	default:
		return "", "", fmt.Errorf("unknown emitter role %q", role)
	}
	return role, instance, nil
}

// ChainHead reports one emitter chain's state after verification.
type ChainHead struct {
	Emitter         string
	FinalEseq       uint64
	HeadHash        string
	SealedByEmitter bool // last record is emitter.seal (03 §4.1)
	Records         int
}

// ChainChecker verifies per-emitter eseq/eprev chains in log order (V5).
type ChainChecker struct {
	heads   map[string]*ChainHead
	order   []string
	lastTyp map[string]string
}

func NewChainChecker() *ChainChecker {
	return &ChainChecker{
		heads:   map[string]*ChainHead{},
		lastTyp: map[string]string{},
	}
}

// Add folds one decoded record into its emitter chain.
func (c *ChainChecker) Add(env *Envelope, r *Record) error {
	h, ok := c.heads[r.Emitter]
	if !ok {
		h = &ChainHead{Emitter: r.Emitter}
		c.heads[r.Emitter] = h
		c.order = append(c.order, r.Emitter)
		if r.Eseq != 0 {
			return fmt.Errorf("%s: first eseq is %d, want 0", r.Emitter, r.Eseq)
		}
		if r.Eprev != ZeroHash {
			return fmt.Errorf("%s: first eprev is not 64 zeros", r.Emitter)
		}
	} else {
		if r.Eseq != h.FinalEseq+1 {
			return fmt.Errorf("%s: eseq gap or reuse at %d after %d", r.Emitter, r.Eseq, h.FinalEseq)
		}
		if r.Eprev != h.HeadHash {
			return fmt.Errorf("%s: eprev mismatch at eseq %d", r.Emitter, r.Eseq)
		}
	}
	h.FinalEseq = r.Eseq
	h.HeadHash = RecordHash(env)
	h.Records++
	h.SealedByEmitter = r.Type == "emitter.seal"
	return nil
}

// Heads returns the emitter chain heads in first-seen order.
func (c *ChainChecker) Heads() []ChainHead {
	out := make([]ChainHead, 0, len(c.order))
	for _, e := range c.order {
		out = append(out, *c.heads[e])
	}
	return out
}
