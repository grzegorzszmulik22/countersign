// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package creds

import (
	"bytes"
	"encoding/base64"
	"regexp"
)

// Credential-shape detection (04 §4.4): a fixed list of token shapes. It is
// a string match, never entropy estimation — a string that does not match
// a listed shape is not a credential for this check, and no shape may be
// added beyond 04 §4.4 (M3 denied item).
//
// A match is a shape occurrence whose left edge is a token boundary
// (start of input, or a preceding character that cannot be part of the
// token). The right edge need not be checked: extra continuation
// characters only make the value more credential-like.

// span is a matched region [start,end) within scanned input.
type span struct {
	lo, hi int
	name   string
}

// tokenChar is the alphabet of credential continuations.
func tokenChar(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') ||
		c == '-' || c == '_' || c == '.'
}

// leftBoundary reports whether position i of b may start a token: start of
// input, or preceded by a character outside the continuation alphabet.
func leftBoundary(b []byte, i int) bool {
	return i == 0 || !tokenChar(b[i-1])
}

// litShape is a literal-prefix shape: prefix followed by at least contN
// continuation characters.
type litShape struct {
	name   string
	prefix []byte
	contN  int
	// cont, if non-nil, overrides tokenChar for the continuation alphabet
	// (e.g. AWS keys accept only [A-Z0-9]).
	cont func(byte) bool
}

var litShapes = []litShape{
	{"sk-ant", []byte("sk-ant-"), 20, nil},
	{"sk-proj", []byte("sk-proj-"), 20, nil},
	{"openai-legacy", []byte("sk-"), 20, nil},
	{"ghp", []byte("ghp_"), 16, nil},
	{"gho", []byte("gho_"), 16, nil},
	{"ghu", []byte("ghu_"), 16, nil},
	{"ghs", []byte("ghs_"), 16, nil},
	{"github-pat", []byte("github_pat_"), 16, nil},
	{"aws-akid", []byte("AKIA"), 16, func(c byte) bool {
		return ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9')
	}},
	{"aws-asia", []byte("ASIA"), 16, func(c byte) bool {
		return ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9')
	}},
}

// matchSlack: xox[baprs]- followed by >=10 token chars.
func matchSlack(b []byte, i int) (end int, ok bool) {
	if i+5 > len(b) || b[i] != 'x' || b[i+1] != 'o' || b[i+2] != 'x' {
		return 0, false
	}
	switch b[i+3] {
	case 'b', 'a', 'p', 'r', 's':
	default:
		return 0, false
	}
	if b[i+4] != '-' {
		return 0, false
	}
	j := i + 5
	n := 0
	for j < len(b) && tokenChar(b[j]) {
		j++
		n++
	}
	if n < 10 {
		return 0, false
	}
	return j, true
}

var jwtRE = regexp.MustCompile(`[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)

// matchPEM scans for -----BEGIN <LABEL> PRIVATE KEY----- starting at i.
// The label is [A-Z0-9 ]* and may be empty (PKCS#8 "BEGIN PRIVATE KEY");
// the tail marker is found first so the label cannot swallow "PRIVATE".
func matchPEM(b []byte, i int) (end int, ok bool) {
	const begin = "-----BEGIN "
	const tail = "PRIVATE KEY-----"
	if i+len(begin) > len(b) || string(b[i:i+len(begin)]) != begin {
		return 0, false
	}
	rem := b[i+len(begin):]
	idx := bytes.Index(rem, []byte(tail))
	if idx < 0 || idx > 24 {
		return 0, false
	}
	for _, c := range rem[:idx] {
		if !(('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || c == ' ') {
			return 0, false
		}
	}
	return i + len(begin) + idx + len(tail), true
}

// matchJWT: at i, three dot-separated base64url runs; the first decodes to
// a JSON object containing "alg".
func matchJWT(b []byte, i int) (end int, ok bool) {
	j := i
	var seg1 []byte
	for seg := 0; seg < 3; seg++ {
		start := j
		for j < len(b) && (('0' <= b[j] && b[j] <= '9') || ('a' <= b[j] && b[j] <= 'z') ||
			('A' <= b[j] && b[j] <= 'Z') || b[j] == '-' || b[j] == '_') {
			j++
		}
		if j-start < 10 {
			return 0, false
		}
		if seg == 0 {
			seg1 = b[start:j]
		}
		if seg < 2 {
			if j >= len(b) || b[j] != '.' {
				return 0, false
			}
			j++
		}
	}
	var dec []byte
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding} {
		d := make([]byte, enc.DecodedLen(len(seg1)))
		n, err := enc.Decode(d, seg1)
		if err == nil {
			dec = d[:n]
			break
		}
	}
	if dec == nil || !bytes.Contains(dec, []byte(`"alg"`)) {
		return 0, false
	}
	return j, true
}

// findShapes returns every shape span in b, merged for overlaps and
// ordered by start. Returned names identify which shape matched.
func findShapes(b []byte) []span {
	var out []span

	for _, ls := range litShapes {
		cont := ls.cont
		if cont == nil {
			cont = tokenChar
		}
		from := 0
		for {
			k := bytes.Index(b[from:], ls.prefix)
			if k < 0 {
				break
			}
			i := from + k
			from = i + 1
			if !leftBoundary(b, i) {
				continue
			}
			j := i + len(ls.prefix)
			n := 0
			for j < len(b) && cont(b[j]) {
				j++
				n++
			}
			if n < ls.contN {
				continue
			}
			out = append(out, span{lo: i, hi: j, name: ls.name})
		}
	}

	// slack literal scan: every "xox" start.
	for from := 0; ; {
		k := bytes.Index(b[from:], []byte("xox"))
		if k < 0 {
			break
		}
		i := from + k
		from = i + 1
		if !leftBoundary(b, i) {
			continue
		}
		if end, ok := matchSlack(b, i); ok {
			out = append(out, span{lo: i, hi: end, name: "slack"})
		}
	}

	// PEM: every "-----BEGIN" start.
	for from := 0; ; {
		k := bytes.Index(b[from:], []byte("-----BEGIN "))
		if k < 0 {
			break
		}
		i := from + k
		from = i + 1
		if !leftBoundary(b, i) {
			continue
		}
		if end, ok := matchPEM(b, i); ok {
			out = append(out, span{lo: i, hi: end, name: "pem"})
		}
	}

	// JWT: regex candidates, then boundary + decode check.
	for _, m := range jwtRE.FindAllIndex(b, -1) {
		if !leftBoundary(b, m[0]) {
			continue
		}
		if end, ok := matchJWT(b, m[0]); ok && end >= m[1] {
			out = append(out, span{lo: m[0], hi: end, name: "jwt"})
		}
	}

	return mergeSpans(out)
}

func mergeSpans(in []span) []span {
	if len(in) == 0 {
		return nil
	}
	// insertion sort by lo — span sets are tiny.
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j-1].lo > in[j].lo; j-- {
			in[j-1], in[j] = in[j], in[j-1]
		}
	}
	out := in[:1]
	for _, s := range in[1:] {
		last := &out[len(out)-1]
		if s.lo <= last.hi {
			if s.hi > last.hi {
				last.hi = s.hi
			}
			if s.name != "" && last.name == "" {
				last.name = s.name
			}
			continue
		}
		out = append(out, s)
	}
	return out
}

// Detect returns the names of credential shapes found in b (04 §4.4).
// Empty means the input carries no credential-shaped material.
func Detect(b []byte) []string {
	spans := findShapes(b)
	if len(spans) == 0 {
		return nil
	}
	var seen map[string]bool
	var names []string
	for _, s := range spans {
		if seen == nil {
			seen = map[string]bool{}
		}
		if !seen[s.name] {
			seen[s.name] = true
			names = append(names, s.name)
		}
	}
	return names
}

// Match reports whether b contains any credential-shaped string.
func Match(b []byte) bool { return len(findShapes(b)) > 0 }

// redactToken is the marker previews substitute for credential-shaped
// substrings (04 §4.4: redacted, never quoted, in any preview).
const redactToken = "[credential-redacted]"

// Redact returns b with every credential-shaped span replaced by the
// redaction marker. Preview writers must pass untrusted strings through
// this before storing them in records.
func Redact(b []byte) []byte {
	spans := findShapes(b)
	if len(spans) == 0 {
		return append([]byte(nil), b...)
	}
	out := make([]byte, 0, len(b))
	pos := 0
	for _, s := range spans {
		out = append(out, b[pos:s.lo]...)
		out = append(out, redactToken...)
		pos = s.hi
	}
	out = append(out, b[pos:]...)
	return out
}
