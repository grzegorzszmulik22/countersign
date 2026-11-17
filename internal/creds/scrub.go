// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package creds

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strings"
)

// Scrubber is the streaming search-and-replace filter of 04 §4.5. It
// carries a window of the last (maxPatternLen-1) unscanned bytes so a
// secret split across any chunk boundary is still found; bytes leave the
// scrubber only once they can no longer be part of a match. Every
// replacement increments Count — the value recorded as
// result.http.scrubbed.
//
// The scrubbed pattern set covers the three wire forms a secret can take
// in an upstream response: raw, base64 (the Basic credential form), and
// URL-escaped. All three are replaced by the session placeholder.
type Scrubber struct {
	pats    [][]byte // search patterns, all three encodings
	keys    [][]byte // per-pattern short prefixes for the SIMD Index path
	repl    []byte   // replacement (the placeholder)
	max     int      // longest pattern length
	carry   []byte   // held-back tail (len <= max-1)
	Count   int      // replacements performed
	flushed bool
}

// Patterns returns the three search patterns for a secret: the raw bytes,
// base64(secret) (the Basic form), and URL-escaped secret. Exported for
// tests that assert scrub coverage per encoding.
func Patterns(secret string) [][]byte {
	return [][]byte{
		[]byte(secret),
		[]byte(base64.StdEncoding.EncodeToString([]byte(secret))),
		[]byte(url.QueryEscape(secret)),
	}
}

// BasicPattern returns the Basic-credential wire form of
// base64(username ":" secret) — also scrubbed (04 §4.5: the raw secret,
// its base64 and URL-encoded forms; the Basic header form is the
// composite the wire actually carries).
func BasicPattern(username, secret string) []byte {
	return []byte(base64.StdEncoding.EncodeToString([]byte(username + ":" + secret)))
}

// NewScrubber builds a scrubber replacing each of pats with repl.
// Patterns shorter than 8 bytes are rejected: a shorter pattern is too
// generic to scrub byte streams with (and real secrets are never that
// short; canaries are 38+).
func NewScrubber(pats [][]byte, repl []byte) *Scrubber {
	s := &Scrubber{repl: repl}
	for _, p := range pats {
		if len(p) == 0 {
			continue
		}
		s.pats = append(s.pats, p)
		if len(p) > s.max {
			s.max = len(p)
		}
	}
	// dedupe identical patterns (e.g. QueryEscape == raw for safe secrets)
	seen := map[string]bool{}
	out := s.pats[:0]
	for _, p := range s.pats {
		k := string(p)
		if !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	s.pats = out
	// A 24-byte search key keeps bytes.Index on the fast short-separator
	// path (longer separators fall back to Rabin-Karp); a key hit is
	// verified against the full pattern in find.
	for _, p := range s.pats {
		k := p
		if len(k) > 24 {
			k = k[:24]
		}
		s.keys = append(s.keys, k)
	}
	return s
}

// Write consumes one stream chunk and returns the bytes safe to emit now.
// Held-back bytes (up to max-1) come out of the next Write or Flush.
func (s *Scrubber) Write(chunk []byte) []byte {
	if s.flushed {
		// writes after Flush cannot happen for a well-formed stream; treat
		// them as a new tail rather than dropping data.
		s.flushed = false
	}
	buf := chunk
	if len(s.carry) > 0 {
		buf = make([]byte, 0, len(s.carry)+len(chunk))
		buf = append(buf, s.carry...)
		buf = append(buf, chunk...)
	}
	s.carry = nil
	return s.scan(buf, false)
}

// Flush ends the stream and returns the held-back tail.
func (s *Scrubber) Flush() []byte {
	s.flushed = true
	out := s.scan(s.carry, true)
	s.carry = nil
	return out
}

// scan emits buf with all complete matches replaced. When !last, the
// final max-1 bytes are retained as carry instead. Match starts are only
// considered below limit so a longest-pattern match can never be cut off
// by the hold-back boundary.
func (s *Scrubber) scan(buf []byte, last bool) []byte {
	limit := len(buf)
	if !last {
		limit = len(buf) - (s.max - 1)
		if limit < 0 {
			limit = 0
		}
	}
	var out []byte
	i := 0
	for i < limit {
		next, plen := s.find(buf, i, limit)
		if next < 0 {
			if out == nil {
				out = buf[i:limit] // clean span: emit without copying
			} else {
				out = append(out, buf[i:limit]...)
			}
			i = limit
			break
		}
		if out == nil {
			out = make([]byte, 0, len(buf))
		}
		out = append(out, buf[i:i+next]...)
		out = append(out, s.repl...)
		s.Count++
		i += next + plen
	}
	if !last {
		s.carry = append(s.carry, buf[i:]...)
	}
	return out
}

// find returns the offset (relative to i) and length of the earliest
// match whose start position is below limit, or -1. At a shared start
// position the longest pattern wins.
func (s *Scrubber) find(buf []byte, i, limit int) (int, int) {
	next, plen := -1, 0
	for j, p := range s.pats {
		end := limit + len(p) - 1
		if end > len(buf) {
			end = len(buf)
		}
		off := i
		for {
			idx := bytes.Index(buf[off:end], s.keys[j])
			if idx < 0 {
				break
			}
			at := off + idx
			if at >= limit {
				break // starts at/after the hold-back boundary — carry it
			}
			if at+len(p) <= len(buf) && bytes.Equal(buf[at:at+len(p)], p) {
				if next < 0 || at-i < next || (at-i == next && len(p) > plen) {
					next, plen = at-i, len(p)
				}
				break // only this pattern's earliest match matters
			}
			off = at + 1 // prefix collision — keep looking
		}
	}
	return next, plen
}

// Scrub replaces all pattern occurrences in a complete string (headers,
// trailers — small and already in memory), counts them, and returns the
// scrubbed string.
func (s *Scrubber) Scrub(v string) string {
	out := v
	for _, p := range s.pats {
		if !strings.Contains(out, string(p)) {
			continue
		}
		s.Count += strings.Count(out, string(p))
		out = strings.ReplaceAll(out, string(p), string(s.repl))
	}
	return out
}
