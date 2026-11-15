// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package fxlib

import (
	"crypto/sha256"
	"strings"
)

// Canary returns a deterministic token matching the canary pattern
// CANARY_[A-Z0-9]{32} (06-agent-loop.md §11). name scopes the value, e.g.
// Canary("github-agent").
func Canary(name string) string {
	s := sha256.Sum256([]byte("countersign-fixture-canary:" + name))
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var b strings.Builder
	b.WriteString("CANARY_")
	for i := 0; i < 32; i++ {
		b.WriteByte(alpha[s[i]%36])
	}
	return b.String()
}
