// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Package evidence implements the record format of spec 03: DSSE v1 envelopes
// carrying in-toto Statement v1 payloads, strict decoding, the PAE signing
// input, and every record type of 03 §4.
package evidence

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// PayloadType is the only DSSE payload type this system emits or accepts.
const PayloadType = "application/vnd.in-toto+json"

// b64 is a byte slice whose JSON form is canonical standard base64
// (03 §1: standard base64 only; a verifier-side re-encode must reproduce the
// input string exactly, so padding and alphabet are checked).
type b64 []byte

func (b b64) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(b))
}

func (b *b64) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("invalid base64: %w", err)
	}
	if base64.StdEncoding.EncodeToString(raw) != s {
		return errors.New("non-canonical base64")
	}
	*b = raw
	return nil
}

// Signature is one DSSE signature entry. Exactly one is permitted per
// envelope (03 §1).
type Signature struct {
	KeyID string `json:"keyid" cs:"keyid"`
	Sig   b64    `json:"sig"`
}

// Envelope is the DSSE v1 envelope of 03 §1.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     b64         `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// PAE is the DSSE v1 pre-authentication encoding:
// "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body.
func PAE(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	fmt.Fprintf(&b, "%d", len(payloadType))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	fmt.Fprintf(&b, "%d", len(payload))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// PAE returns the signing input for this envelope.
func (e *Envelope) PAE() []byte {
	return PAE(e.PayloadType, e.Payload)
}

// MarshalEnvelope produces the stored-line form (one line of JSON, no
// trailing newline). Exactly one signature is required.
func MarshalEnvelope(e *Envelope) ([]byte, error) {
	if e.PayloadType != PayloadType {
		return nil, fmt.Errorf("unsupported payloadType %q", e.PayloadType)
	}
	if len(e.Signatures) != 1 {
		return nil, fmt.Errorf("envelope must carry exactly one signature, got %d", len(e.Signatures))
	}
	if len(e.Signatures[0].Sig) != 64 {
		return nil, fmt.Errorf("signature is %d bytes, want 64", len(e.Signatures[0].Sig))
	}
	if !validKeyID(e.Signatures[0].KeyID) {
		return nil, fmt.Errorf("malformed keyid %q", e.Signatures[0].KeyID)
	}
	return marshalCanonical(e)
}

// UnmarshalEnvelope decodes one stored line, enforcing every envelope rule of
// 03 §1: strict JSON, single line, canonical base64, exactly one signature.
func UnmarshalEnvelope(line []byte) (*Envelope, error) {
	if bytes.IndexByte(line, '\n') >= 0 {
		return nil, errors.New("record line contains a newline")
	}
	var e Envelope
	if err := unmarshalStrict(line, &e); err != nil {
		return nil, err
	}
	if e.PayloadType != PayloadType {
		return nil, fmt.Errorf("unsupported payloadType %q", e.PayloadType)
	}
	if len(e.Signatures) != 1 {
		return nil, fmt.Errorf("envelope must carry exactly one signature, got %d", len(e.Signatures))
	}
	if len(e.Signatures[0].Sig) != 64 {
		return nil, fmt.Errorf("signature is %d bytes, want 64", len(e.Signatures[0].Sig))
	}
	if !validKeyID(e.Signatures[0].KeyID) {
		return nil, fmt.Errorf("malformed keyid %q", e.Signatures[0].KeyID)
	}
	return &e, nil
}

func validKeyID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// marshalCanonical is the single encode path for every stored byte:
// encoding/json field order, HTML escaping off (deterministic), RawMessage
// compacted.
func marshalCanonical(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}
