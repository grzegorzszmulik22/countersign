// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/countersign/countersign/internal/policy"
)

// hopByHop are the RFC 2616 §13.5.1 hop-by-hop header names the broker
// always strips, plus the proxy-authentication pair (02 §3: the session
// token identifies the sandbox to the broker only; it is never forwarded).
var hopByHop = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// stripHopByHop returns the headers that may cross the proxy boundary: the
// fixed hop-by-hop list plus every name the Connection token lists. The
// returned header is a copy; h is untouched.
func stripHopByHop(h http.Header) http.Header {
	out := make(http.Header, len(h))
	extra := map[string]bool{}
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if n := http.CanonicalHeaderKey(strings.TrimSpace(name)); n != "" {
				extra[n] = true
			}
		}
	}
	for name, vals := range h {
		if hopByHop[name] || extra[name] {
			continue
		}
		cp := make([]string, len(vals))
		copy(cp, vals)
		out[name] = cp
	}
	return out
}

// headerNames returns the sorted header names recorded in effect records.
func headerNames(h http.Header) []string {
	out := make([]string, 0, len(h))
	for name := range h {
		out = append(out, strings.ToLower(name))
	}
	sort.Strings(out)
	return out
}

// parseSize parses the policy size syntax (04 §1: 1048576, 512Ki, 1Mi).
// Plain numbers are bytes; K/M/G are decimal SI, Ki/Mi/Gi binary.
func parseSize(s string) (int64, error) {
	if s == "" {
		return 0, errSize
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	num, unit := s[:i], s[i:]
	if num == "" {
		return 0, errSize
	}
	var n int64
	for _, c := range []byte(num) {
		if c < '0' || c > '9' {
			return 0, errSize
		}
		n = n*10 + int64(c-'0')
	}
	var mul int64
	switch unit {
	case "", "B":
		mul = 1
	case "K":
		mul = 1000
	case "Ki":
		mul = 1 << 10
	case "M":
		mul = 1000 * 1000
	case "Mi":
		mul = 1 << 20
	case "G":
		mul = 1000 * 1000 * 1000
	case "Gi":
		mul = 1 << 30
	default:
		return 0, errSize
	}
	return n * mul, nil
}

var errSize = errors.New("invalid size")

// bufferLimit returns the grant's effective buffer limit in bytes
// (04 §1: grant override, else spec.bufferLimit, else 1 MiB — and
// 32 MiB for inspect: inference grants, M8.3).
func bufferLimit(p *policy.SessionPolicy, g *policy.Grant) int64 {
	s := ""
	if g != nil && g.BufferLimit != "" {
		s = g.BufferLimit
	} else if p.Spec.BufferLimit != "" {
		s = p.Spec.BufferLimit
	}
	if s == "" {
		return defaultBufferLimit(g)
	}
	n, err := parseSize(s)
	if err != nil || n < 0 {
		return defaultBufferLimit(g)
	}
	return n
}

// defaultBufferLimit is the unset-limit default: 32 MiB for
// inspect: inference grants (04 §1), 1 MiB otherwise.
func defaultBufferLimit(g *policy.Grant) int64 {
	if g != nil && g.Inspect == "inference" {
		return 32 << 20
	}
	return 1 << 20
}
