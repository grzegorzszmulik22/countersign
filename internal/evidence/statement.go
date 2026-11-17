// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/countersign/countersign/internal/names"
)

// StatementType is the in-toto Statement v1 _type (03 §1).
const StatementType = "https://in-toto.io/Statement/v1"

// PredicateTypeURI is the only predicateType of the record format (03 §1).
func PredicateTypeURI() string {
	return "https://" + names.APIGroup + "/record/v1"
}

// Subject is one in-toto subject entry.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Statement is the in-toto Statement v1 payload of 03 §1.
type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// SessionSubject returns the subject a record for session carries:
// name "countersign:session:<id>", digest sha256 of the UTF-8 session ID.
func SessionSubject(session string) Subject {
	sum := sha256.Sum256([]byte(session))
	return Subject{
		Name:   "countersign:session:" + session,
		Digest: map[string]string{"sha256": hex.EncodeToString(sum[:])},
	}
}

// MarshalStatement encodes a statement.
func MarshalStatement(s *Statement) ([]byte, error) {
	if s.Type != StatementType {
		return nil, fmt.Errorf("wrong _type %q", s.Type)
	}
	if s.PredicateType != PredicateTypeURI() {
		return nil, fmt.Errorf("wrong predicateType %q", s.PredicateType)
	}
	if len(s.Subject) != 1 {
		return nil, fmt.Errorf("statement must have exactly one subject, got %d", len(s.Subject))
	}
	if len(s.Predicate) == 0 {
		return nil, errors.New("empty predicate")
	}
	return marshalCanonical(s)
}

// NewStatement wraps predicate bytes in a Statement for session.
func NewStatement(session string, predicate []byte) *Statement {
	return &Statement{
		Type:          StatementType,
		Subject:       []Subject{SessionSubject(session)},
		PredicateType: PredicateTypeURI(),
		Predicate:     json.RawMessage(predicate),
	}
}

// UnmarshalStatement decodes a statement, enforcing the two constant fields.
func UnmarshalStatement(data []byte) (*Statement, error) {
	var s Statement
	if err := unmarshalStrict(data, &s); err != nil {
		return nil, err
	}
	if s.Type != StatementType {
		return nil, fmt.Errorf("wrong _type %q", s.Type)
	}
	if s.PredicateType != PredicateTypeURI() {
		return nil, fmt.Errorf("wrong predicateType %q", s.PredicateType)
	}
	if len(s.Subject) != 1 {
		return nil, fmt.Errorf("statement must have exactly one subject, got %d", len(s.Subject))
	}
	if len(s.Predicate) == 0 {
		return nil, errors.New("empty predicate")
	}
	return &s, nil
}
