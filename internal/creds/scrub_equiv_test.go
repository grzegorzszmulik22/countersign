// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package creds

import (
	"bytes"
	"math/rand"
	"testing"
)

// refScrubber reproduces the pre-refactor single-buffer algorithm:
// concat carry+chunk, scan for matches starting below len-(max-1),
// emit up to the match end / limit, retain the tail.
type refScrubber struct {
	pats  [][]byte
	repl  []byte
	max   int
	carry []byte
	Count int
}

func newRef(pats [][]byte, repl []byte) *refScrubber {
	r := &refScrubber{repl: repl}
	seen := map[string]bool{}
	for _, p := range pats {
		if len(p) == 0 || seen[string(p)] {
			continue
		}
		seen[string(p)] = true
		r.pats = append(r.pats, p)
		if len(p) > r.max {
			r.max = len(p)
		}
	}
	return r
}

func (r *refScrubber) find(buf []byte, i, limit int) (int, int) {
	next, plen := -1, 0
	for _, p := range r.pats {
		idx := bytes.Index(buf[i:min(limit+len(p)-1, len(buf))], p[:min(24, len(p))])
		_ = idx
		break
	}
	// simple per-pattern scan matching find() semantics
	for _, p := range r.pats {
		end := limit + len(p) - 1
		if end > len(buf) {
			end = len(buf)
		}
		key := p
		if len(key) > 24 {
			key = key[:24]
		}
		off := i
		for {
			k := bytes.Index(buf[off:end], key)
			if k < 0 {
				break
			}
			at := off + k
			if at >= limit {
				break
			}
			if at+len(p) <= len(buf) && bytes.Equal(buf[at:at+len(p)], p) {
				if next < 0 || at-i < next || (at-i == next && len(p) > plen) {
					next, plen = at-i, len(p)
				}
				break
			}
			off = at + 1
		}
	}
	return next, plen
}

func (r *refScrubber) Write(chunk []byte) []byte {
	buf := chunk
	if len(r.carry) > 0 {
		buf = append(append([]byte{}, r.carry...), chunk...)
	}
	r.carry = nil
	return r.scan(buf, false)
}

func (r *refScrubber) Flush() []byte {
	out := r.scan(r.carry, true)
	r.carry = nil
	return out
}

func (r *refScrubber) scan(buf []byte, last bool) []byte {
	limit := len(buf)
	if !last {
		limit = len(buf) - (r.max - 1)
		if limit < 0 {
			limit = 0
		}
	}
	var out []byte
	i := 0
	for i < limit {
		next, plen := r.find(buf, i, limit)
		if next < 0 {
			if out == nil {
				out = buf[i:limit]
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
		out = append(out, r.repl...)
		r.Count++
		i += next + plen
	}
	if !last {
		r.carry = append(r.carry, buf[i:]...)
	}
	return out
}

func collect() (func([]byte), *bytes.Buffer) {
	b := &bytes.Buffer{}
	return func(p []byte) { b.Write(p) }, b
}

func TestScrubberEquiv(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	repl := []byte("csph_repl_0000")
	for iter := 0; iter < 4000; iter++ {
		slen := 8 + rng.Intn(40)
		secret := make([]byte, slen)
		for i := range secret {
			secret[i] = byte('a' + rng.Intn(26))
		}
		pats := Patterns(string(secret))
		if rng.Intn(3) == 0 {
			pats = append(pats, BasicPattern("u", string(secret)))
		}
		// build a random body, sometimes embedding secret forms
		var body []byte
		n := 1 + rng.Intn(6)
		for i := 0; i < n; i++ {
			body = append(body, []byte("pad-")...)
			if rng.Intn(2) == 0 {
				body = append(body, pats[rng.Intn(len(pats))]...)
			}
		}
		if rng.Intn(4) == 0 {
			body = append(body, pats[0]...) // tail secret exercises holdback
		}
		// random chunking incl. empty chunks
		var chunks [][]byte
		for len(body) > 0 {
			k := rng.Intn(len(body) + 1)
			chunks = append(chunks, body[:k])
			body = body[k:]
		}
		a := newRef(pats, repl)
		b := NewScrubber(pats, repl)
		emit, buf := collect()
		var ao []byte
		for _, c := range chunks {
			body = append(body, c...)
			ao = append(ao, a.Write(c)...)
			b.Write(c, emit)
		}
		ao = append(ao, a.Flush()...)
		b.Flush(emit)
		bo := buf.Bytes()
		if !bytes.Equal(ao, bo) {
			t.Fatalf("iter %d mismatch:\n old %q\n new %q", iter, ao, bo)
		}
		if a.Count != b.Count {
			t.Fatalf("iter %d count old %d new %d", iter, a.Count, b.Count)
		}
	}
}
