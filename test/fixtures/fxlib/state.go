// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package fxlib

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// StateDigest returns a deterministic digest of a fixture's externally
// visible state (M0.3, world oracle). The state must be a JSON-marshalable
// value; encoding/json renders map keys in sorted order, making the digest
// stable across identical state. Returns "sha256:<hex>".
func StateDigest(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "sha256:marshal-error"
	}
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}
