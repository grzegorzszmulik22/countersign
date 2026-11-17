// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// ULID per 03 §2: 26-char Crockford base32, 48-bit ms timestamp + 80-bit random.
const ulidAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID returns a fresh ULID. When entropy is nil, crypto/rand is used and
// the time is now.
func NewULID(entropy []byte) string {
	var b [16]byte
	if entropy == nil {
		ms := uint64(time.Now().UnixMilli())
		binary.BigEndian.PutUint64(b[0:8], ms<<16)
		if _, err := rand.Read(b[6:]); err != nil {
			panic(err)
		}
	} else {
		copy(b[:], entropy)
	}
	// 128 bits → 26 base32 chars.
	var out [26]byte
	v := uint64(0)
	bits := 0
	i := 25
	for _, by := range b {
		v = (v << 8) | uint64(by)
		bits += 8
		for bits >= 5 && i >= 0 {
			out[i] = ulidAlphabet[(v>>(bits-5))&31]
			bits -= 5
			i--
		}
	}
	for i >= 0 {
		out[i] = ulidAlphabet[(v<<(5-bits-1))&31]
		i--
	}
	return string(out[:])
}

// ValidULID reports whether s is a well-formed ULID.
func ValidULID(s string) bool {
	if len(s) != 26 {
		return false
	}
	for _, c := range s {
		ok := (c >= '0' && c <= '9') || (c >= 'A' && c <= 'H') ||
			(c >= 'J' && c <= 'M') || (c >= 'N' && c <= 'P') ||
			(c >= 'Q' && c <= 'T') || (c >= 'V' && c <= 'Z')
		if !ok {
			return false
		}
	}
	return true
}
