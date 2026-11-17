// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package creds

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Placeholder grammar (04 §4): csph_<8 hex>_<grant-id>_<22 base62> —
// a session tag, the grant id verbatim, and ~131 bits of randomness.
// The tag is the first 8 hex chars of SHA-256(session-id).
const (
	placeholderPrefix = "csph_"
	placeholderRandN  = 22
	base62            = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// SessionTag is the 8-hex session component of every placeholder the
// session mints.
func SessionTag(sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	return hex.EncodeToString(sum[:4])
}

// NewPlaceholder returns the per-(session, grant) placeholder. Randomness
// comes from crypto/rand via rejection sampling; a rng failure panics —
// a placeholder that cannot be generated must never silently degrade.
func NewPlaceholder(sessionID, grantID string) string {
	out := make([]byte, 0, placeholderRandN)
	var buf [32]byte
	for len(out) < placeholderRandN {
		if _, err := rand.Read(buf[:]); err != nil {
			panic(fmt.Sprintf("creds: placeholder rng: %v", err))
		}
		for _, b := range buf {
			if b >= 248 { // 62*4: drop tail bytes so %62 is unbiased
				continue
			}
			out = append(out, base62[int(b)%62])
			if len(out) == placeholderRandN {
				break
			}
		}
	}
	return placeholderPrefix + SessionTag(sessionID) + "_" + grantID + "_" + string(out)
}

// IsPlaceholder reports whether s has exactly the placeholder shape
// (prefix, 8-hex tag, grant id, "_", 22 base62 chars). Grammar only: a
// well-formed string is still not a credential — ownership and exact
// equality with the session's value decide what it authorizes (04 §4.3–4.4).
func IsPlaceholder(s string) bool { return parseGrant(s) != "" }

// parseGrant returns the grant-id component if s is a well-formed
// placeholder, else "". Grant ids may contain "_" so the last "_" before
// the 22-char tail is the delimiter.
func parseGrant(s string) (grant string) {
	if !strings.HasPrefix(s, placeholderPrefix) {
		return ""
	}
	rest := s[len(placeholderPrefix):]
	if len(rest) < 8+1+1+1+placeholderRandN {
		return ""
	}
	for i := 0; i < 8; i++ {
		if !isHex(rest[i]) {
			return ""
		}
	}
	if rest[8] != '_' {
		return ""
	}
	tail := rest[9:]
	if len(tail) < 1+1+placeholderRandN {
		return ""
	}
	grantEnd := len(tail) - placeholderRandN - 1
	if tail[grantEnd] != '_' {
		return ""
	}
	for i := grantEnd + 1; i < len(tail); i++ {
		if !isB62(tail[i]) {
			return ""
		}
	}
	return tail[:grantEnd]
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f')
}

func isB62(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}
