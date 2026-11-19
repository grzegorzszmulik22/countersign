// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestPreviewRedacts: credential shapes become [REDACTED:<shape>] and
// the marker can extend past the original span.
func TestPreviewRedacts(t *testing.T) {
	raw := []byte(`{"command":"use AKIAIOSFODNN7EXAMPLE here"}`)
	p, ok := InputPreview(raw, true)
	if !ok {
		t.Fatal("preview disabled?")
	}
	if strings.Contains(p, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("secret leaked: %q", p)
	}
	if !strings.Contains(p, "[REDACTED:") {
		t.Fatalf("no redaction marker: %q", p)
	}
}

// TestPreviewCap: 256-byte cap, no split runes.
func TestPreviewCap(t *testing.T) {
	pad := strings.Repeat("x", 200)
	tail := strings.Repeat("", 100) // 300 bytes
	raw := []byte(`{"command":"` + pad + tail + `"}`)
	p, ok := InputPreview(raw, true)
	if !ok {
		t.Fatal("preview disabled?")
	}
	if len(p) > PreviewMax {
		t.Fatalf("preview %d bytes > %d", len(p), PreviewMax)
	}
	if !utf8.ValidString(p) {
		t.Fatal("preview is not valid UTF-8")
	}
	// The last byte must end a rune boundary: appending the next source
	// rune must not be required for validity (checked by ValidString).
	if strings.HasSuffix(p, "") == false && strings.HasSuffix(p, "x") == false &&
		strings.HasSuffix(p, `"}`) == false && strings.HasSuffix(p, `"`) == false {
		t.Fatalf("odd preview tail: %q", p[len(p)-4:])
	}
}

// TestPreviewDisabled: privacy.previews=false omits the field entirely.
func TestPreviewDisabled(t *testing.T) {
	p, ok := InputPreview([]byte(`{"a":1}`), false)
	if ok || p != "" {
		t.Fatalf("disabled preview returned %q", p)
	}
}

// TestPreviewBoundaryInputs: empty/short/exact-cap inputs.
func TestPreviewBoundaryInputs(t *testing.T) {
	for _, raw := range [][]byte{
		{}, []byte("x"), []byte(strings.Repeat("y", PreviewMax)),
		[]byte(strings.Repeat("y", PreviewMax+1)),
	} {
		p, ok := InputPreview(raw, true)
		if !ok || len(p) > PreviewMax {
			t.Fatalf("len %d -> %d", len(raw), len(p))
		}
	}
}
