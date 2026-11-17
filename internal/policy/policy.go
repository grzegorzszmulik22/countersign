// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// Digest returns the policy digest: SHA-256 over the exact file bytes
// (04 §1). A whitespace-only change therefore alters it.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Load parses and validates one SessionPolicy document. Unknown fields are
// rejected: fields defined by 05 (autonomy, world, commit, budgets, tape,
// attest at spec level; class, stager, compensate, tools, egress on grants)
// are out of scope until their milestones and must fail here.
//
// The loader must never panic on untrusted input (C3.1.5). yaml.v3's merge
// handling can panic on adversarial documents ("<<:" with a non-mapping
// value panics in decoder.merge), so a decode panic becomes an error.
func Load(data []byte) (p *SessionPolicy, err error) {
	defer func() {
		if r := recover(); r != nil {
			p, err = nil, fmt.Errorf("policy: malformed document: %v", r)
		}
	}()
	var doc SessionPolicy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, errors.New("policy: only one document allowed")
		}
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := validate(&doc); err != nil {
		return nil, err
	}
	doc.digest = Digest(data)
	return &doc, nil
}

// DigestHex is the digest of the bytes the policy was loaded from.
func (p *SessionPolicy) DigestHex() string { return p.digest }
