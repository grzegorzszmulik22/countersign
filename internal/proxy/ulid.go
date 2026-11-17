// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/rand"
	"sync"
	"time"
)

// ULIDs per spec/03 §2: 26 chars, Crockford base32, 48-bit ms timestamp then
// 80 bits of randomness. Monotonic within the process.
const ulidAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var ulidState struct {
	mu   sync.Mutex
	last int64
	rand [10]byte
}

// newULID returns a unique, monotonically increasing ULID.
func newULID() string {
	now := time.Now().UnixMilli()
	ulidState.mu.Lock()
	defer ulidState.mu.Unlock()
	if now <= ulidState.last {
		now = ulidState.last + 1
	}
	ulidState.last = now
	if _, err := rand.Read(ulidState.rand[:]); err != nil {
		panic(err)
	}
	var out [26]byte
	t := uint64(now)
	for i := 9; i >= 0; i-- {
		out[i] = ulidAlphabet[t&0x1f]
		t >>= 5
	}
	t = uint64(ulidState.rand[0]) | uint64(ulidState.rand[1])<<8 |
		uint64(ulidState.rand[2])<<16 | uint64(ulidState.rand[3])<<24 |
		uint64(ulidState.rand[4])<<32
	for i := 19; i >= 10; i-- {
		out[i] = ulidAlphabet[t&0x1f]
		t >>= 5
	}
	t = uint64(ulidState.rand[5]) | uint64(ulidState.rand[6])<<8 |
		uint64(ulidState.rand[7])<<16 | uint64(ulidState.rand[8])<<24 |
		uint64(ulidState.rand[9])<<32
	for i := 25; i >= 20; i-- {
		out[i] = ulidAlphabet[t&0x1f]
		t >>= 5
	}
	return string(out[:])
}
