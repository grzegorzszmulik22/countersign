// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package creds

import (
	"bytes"
	"testing"
)

func BenchmarkScrubWrite(b *testing.B) {
	secret := "cs-canary-anthropic-0123456789abcdef-XYZ"
	s := NewScrubber(Patterns(secret), []byte("PLACEHOLDER_VALUE_0123"))
	chunk := bytes.Repeat([]byte{'0'}, 32*1024)
	emit := func(p []byte) {}
	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Write(chunk, emit)
	}
}
