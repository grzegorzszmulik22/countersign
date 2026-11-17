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
	pats   [][]byte // search patterns, all three encodings
	repl   []byte   // replacement (the placeholder)
	max    int      // longest pattern length
	carry  []byte   // held-back tail (len <= max-1)
	Count  int      // replacements performed
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
	buf := append(s.carry, chunk...)
	s.carry = nil
	out := s.scan(buf, false)
	return out
}

// Flush ends the stream and returns the held-back tail.
func (s *Scrubber) Flush() []byte {
	s.flushed = true
	out := s.scan(s.carry, true)
	s.carry = nil
	return out
}

// scan emits buf with all complete matches replaced. When !last, the
// final max-1 bytes are retained as carry instead.
func (s *Scrubber) scan(buf []byte, last bool) []byte {
	var out []byte
	i := 0
	for i < len(buf) {
		if !last && i+s.max > len(buf) {
			break // tail cannot yet be proven safe — hold it
		}
		plen := s.matchAt(buf, i)
		if plen == 0 {
			out = append(out, buf[i])
			i++
			continue
		}
		out = append(out, s.repl...)
		s.Count++
		i += plen
	}
	if !last {
		s.carry = append(s.carry, buf[i:]...)
	}
	return out
}

// matchAt returns the length of the longest pattern matching at buf[i],
// or 0. Longest-first so a pattern that is a prefix of another wins the
// longer replacement.
func (s *Scrubber) matchAt(buf []byte, i int) int {
	best := 0
	for _, p := range s.pats {
		if len(p) <= best || len(buf)-i < len(p) {
			continue
		}
		if bytes.Equal(buf[i:i+len(p)], p) {
			best = len(p)
		}
	}
	return best
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
