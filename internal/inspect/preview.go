// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"unicode/utf8"

	"github.com/countersign/countersign/internal/creds"
)

// PreviewMax is the 03 §8 preview cap: 256 bytes.
const PreviewMax = 256

// InputPreview produces the input_preview of an intent.declared body
// (M8.5): the input's raw serialization, passed through the
// credential-shape redactor (04 §4.4 — [REDACTED:<shape>] markers), then
// truncated to at most 256 bytes without splitting a UTF-8 character.
//
// The digest and length recorded beside the preview always describe the
// ORIGINAL bytes, never this redacted form. ok=false disables previews
// entirely (privacy.previews) — the field is then omitted, not empty.
func InputPreview(raw []byte, ok bool) (preview string, present bool) {
	if !ok {
		return "", false
	}
	r := creds.RedactNamed(raw)
	if len(r) > PreviewMax {
		r = r[:utf8SafeLen(r, PreviewMax)]
	}
	return string(r), true
}

// utf8SafeLen is the largest n <= max such that b[:n] ends on a rune
// boundary. Invalid bytes are treated as 1-byte runes so a malformed
// input still truncates deterministically.
func utf8SafeLen(b []byte, max int) int {
	if len(b) <= max {
		return len(b)
	}
	n := 0
	for n < len(b) {
		_, size := utf8.DecodeRune(b[n:])
		if n+size > max {
			return n
		}
		n += size
	}
	return n
}
