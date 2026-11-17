// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Roles of the key manifest (03 §7).
const (
	RoleLog              = "log"
	RoleAttestor         = "attestor"
	RoleReviewer         = "reviewer"
	RoleReviewerDelegate = "reviewer:delegate"
	RoleWitness          = "witness"
)

// EmitterRole is the manifest role of an emitter key for a component role.
func EmitterRole(role string) string { return "emitter:" + role }

// ManifestEntry is one row of keys.json.
type ManifestEntry struct {
	KeyID     string   `json:"key_id"`
	Role      string   `json:"role"`
	PublicKey string   `json:"public_key"` // standard base64 of the 32-byte key
	NotBefore string   `json:"not_before"`
	NotAfter  *string  `json:"not_after"`
	RpID      *string  `json:"rp_id"`   // reviewer only
	Origins   []string `json:"origins"` // reviewer only

	Signer Signer `json:"-"`
}

// Manifest is the trusted key manifest (03 §7).
type Manifest []ManifestEntry

// NewManifest builds a manifest from signer+cole entries.
func NewManifest(entries []ManifestEntry) (Manifest, error) {
	out := make(Manifest, 0, len(entries))
	for _, e := range entries {
		if e.Signer == nil {
			return nil, errors.New("manifest entry missing signer")
		}
		if _, err := time.Parse(time.RFC3339Nano, e.NotBefore); err != nil {
			return nil, fmt.Errorf("not_before: %w", err)
		}
		if e.NotAfter != nil {
			if _, err := time.Parse(time.RFC3339Nano, *e.NotAfter); err != nil {
				return nil, fmt.Errorf("not_after: %w", err)
			}
		}
		e.KeyID = e.Signer.KeyID()
		e.PublicKey = base64.StdEncoding.EncodeToString(e.Signer.Public())
		out = append(out, e)
	}
	return out, nil
}

// Find returns the entry for a key ID.
func (m Manifest) Find(keyID string) (ManifestEntry, bool) {
	for _, e := range m {
		if e.KeyID == keyID {
			return e, true
		}
	}
	return ManifestEntry{}, false
}

// Public decodes the entry's public key.
func (e ManifestEntry) Public() (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(e.PublicKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad public_key for %s", e.KeyID)
	}
	return ed25519.PublicKey(b), nil
}

// CoversTS reports whether the entry's validity covers the RFC3339 ts.
func (e ManifestEntry) CoversTS(ts string) bool {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return false
	}
	nb, err := time.Parse(time.RFC3339Nano, e.NotBefore)
	if err != nil || t.Before(nb) {
		return false
	}
	if e.NotAfter != nil {
		na, err := time.Parse(time.RFC3339Nano, *e.NotAfter)
		if err != nil || t.After(na) {
			return false
		}
	}
	return true
}

// MarshalManifest produces the canonical keys.json bytes.
func MarshalManifest(m Manifest) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalManifest decodes a keys.json.
func UnmarshalManifest(data []byte) (Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// LoadManifest reads keys.json.
func LoadManifest(path string) (Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return UnmarshalManifest(b)
}

// SaveManifest writes keys.json.
func SaveManifest(m Manifest, path string) error {
	b, err := MarshalManifest(m)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
