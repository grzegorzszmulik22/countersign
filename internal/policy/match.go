// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"net/netip"
	"slices"
	"strings"
)

// Request is a normalized request as seen by the broker (04 §2).
type Request struct {
	Method  string `json:"method" yaml:"method"`
	Scheme  string `json:"scheme" yaml:"scheme"` // "" means https
	Host    string `json:"host" yaml:"host"`
	Port    int    `json:"port" yaml:"port"` // 0 means the scheme default
	Path    string `json:"path" yaml:"path"` // raw path as received; "" is treated as "/"
	Query   string `json:"query" yaml:"query"`
	SNI     string `json:"sni" yaml:"sni"`         // "" means same as Host
	Connect string `json:"connect" yaml:"connect"` // "" means same as Host
}

// Result is the outcome of §2 steps 1–2: the selected grant's ID plus a
// denial reason, or a pre-check reason.
type Result struct {
	Grant  string `json:"grant"`
	Reason string `json:"reason"`
}

// Denial reasons produced by steps 1–2 of 04 §2.
const (
	ReasonNoGrant          = "NO_GRANT"
	ReasonDenyGrant        = "DENY_GRANT"
	ReasonSmugglingSuspect = "SMUGGLING_SUSPECT"
)

// Match evaluates spec/04 §2 steps 1 (pre-checks) and 2 (grant selection in
// document order) for a single request. Steps 3–6 (upstream address check,
// limits, credential rules, class and condition) belong to later chunks.
//
// A grant whose match carries the git-smart-http semantic matcher replaces
// the methods/paths test with gitSmartHTTPMatch (M3.6); hosts, scheme and
// ports still apply first. A deny grant that matches yields ReasonDenyGrant.
func (p *SessionPolicy) Match(r *Request) Result {
	// §2.1 pre-checks. CONNECT authority, TLS SNI and HTTP Host must be
	// identical after lowercasing; an absent field defaults to Host.
	lhost := strings.ToLower(r.Host)
	for _, alt := range []string{r.SNI, r.Connect} {
		if alt != "" && strings.ToLower(alt) != lhost {
			return Result{Reason: ReasonSmugglingSuspect}
		}
	}
	host := normHost(r.Host)
	raw := r.Path
	if raw == "" {
		raw = "/"
	}
	if smugglingPath(raw) {
		return Result{Reason: ReasonSmugglingSuspect}
	}
	path := decodeUnreserved(raw)

	scheme := r.Scheme
	if scheme == "" {
		scheme = "https"
	}
	port := r.Port
	if port == 0 {
		port = 443
		if scheme == "http" {
			port = 80
		}
	}

	// §2.2 grant selection: document order, first match wins.
	for _, g := range p.Spec.Grants {
		m := g.Match
		gscheme := m.Scheme
		if gscheme == "" {
			gscheme = "https"
		}
		if scheme != gscheme {
			continue
		}
		gports := m.Ports
		if gports == nil {
			gports = []int{443}
			if gscheme == "http" {
				gports = []int{80}
			}
		}
		if !slices.Contains(gports, port) {
			continue
		}
		ok := false
		for _, pat := range m.Hosts {
			if hostMatch(normHost(pat), host) {
				ok = true
				break
			}
		}
		if !ok {
			continue
		}
		if m.Matcher != nil {
			// A semantic matcher replaces methods/paths (04 §1): validation
			// guarantees the two never appear together.
			if m.Matcher.GitSmartHTTP == nil ||
				!gitSmartHTTPMatch(m.Matcher.GitSmartHTTP, r.Method, path, r.Query) {
				continue
			}
		} else {
			if m.Methods != nil && !slices.Contains(m.Methods, r.Method) {
				continue
			}
			paths := m.Paths
			if paths == nil {
				paths = []string{"/**"}
			}
			ok = false
			for _, glob := range paths {
				if pathMatch(glob, path) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		if g.Action == "deny" {
			return Result{Grant: g.ID, Reason: ReasonDenyGrant}
		}
		return Result{Grant: g.ID}
	}
	return Result{Reason: ReasonNoGrant}
}

// normHost lowercases the name, drops surrounding IPv6 brackets and removes
// one trailing root dot (04 §1: host with trailing dot normalized).
func normHost(h string) string {
	h = strings.ToLower(h)
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	return strings.TrimSuffix(h, ".")
}

// hostMatch implements the host column of the defaults table: "*" alone
// matches any host that is not an IP literal; "*.dom" matches one or more
// labels below dom but never the apex; anything else is a literal. A request
// host given as an IP literal matches only a grant listing that literal
// (04 §2 step 1).
func hostMatch(pat, host string) bool {
	if isIPLiteral(host) {
		return pat == host
	}
	if pat == "*" {
		return true
	}
	if strings.HasPrefix(pat, "*.") {
		return strings.HasSuffix(host, pat[1:])
	}
	return pat == host
}

func isIPLiteral(h string) bool {
	_, err := netip.ParseAddr(h)
	return err == nil
}

// smugglingPath reports whether a raw path hits the §2 step-1 rejects: dot
// segments, backslash, control characters, or the percent-encoded forms
// %2e %2f %5c %00 in any letter case.
func smugglingPath(raw string) bool {
	if strings.Contains(raw, "\\") {
		return true
	}
	for i := 0; i+2 < len(raw); i++ {
		if raw[i] != '%' {
			continue
		}
		if eqFold2(raw[i+1], '0') && (eqFold2(raw[i+2], '0')) ||
			eqFold2(raw[i+1], '2') && (eqFold2(raw[i+2], 'e') || eqFold2(raw[i+2], 'f')) ||
			eqFold2(raw[i+1], '5') && eqFold2(raw[i+2], 'c') {
			return true
		}
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return true
		}
	}
	for _, seg := range strings.Split(raw, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

func eqFold2(b, c byte) bool {
	if 'A' <= b && b <= 'Z' {
		b += 'a' - 'A'
	}
	if 'A' <= c && c <= 'Z' {
		c += 'a' - 'A'
	}
	return b == c
}

// decodeUnreserved decodes percent-encoded unreserved characters (RFC 3986
// normal form); all other escapes stay literal.
func decodeUnreserved(p string) string {
	if !strings.Contains(p, "%") {
		return p
	}
	var b strings.Builder
	b.Grow(len(p))
	for i := 0; i < len(p); {
		if p[i] == '%' && i+2 < len(p) && isHex(p[i+1]) && isHex(p[i+2]) {
			c := unhex(p[i+1], p[i+2])
			if isUnreserved(c) {
				b.WriteByte(c)
			} else {
				b.WriteString(p[i : i+3])
			}
			i += 3
			continue
		}
		b.WriteByte(p[i])
		i++
	}
	return b.String()
}

func isHex(b byte) bool {
	return ('0' <= b && b <= '9') || ('a' <= b && b <= 'f') || ('A' <= b && b <= 'F')
}

func unhex(a, b byte) byte {
	v := func(x byte) byte {
		switch {
		case x >= 'a':
			return x - 'a' + 10
		case x >= 'A':
			return x - 'A' + 10
		default:
			return x - '0'
		}
	}
	return v(a)<<4 | v(b)
}

func isUnreserved(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') ||
		c == '-' || c == '_' || c == '.' || c == '~'
}

// pathMatch matches a "/" -rooted glob against a decoded path: "*" is a
// wildcard inside a segment; "**" spans any number of whole segments,
// including zero (04 §1).
func pathMatch(glob, path string) bool {
	return matchSegs(strings.Split(glob, "/"), strings.Split(path, "/"))
}

func matchSegs(gs, ps []string) bool {
	if len(gs) == 0 {
		return len(ps) == 0
	}
	if gs[0] == "**" {
		for k := 0; k <= len(ps); k++ {
			if matchSegs(gs[1:], ps[k:]) {
				return true
			}
		}
		return false
	}
	return len(ps) > 0 && segMatch(gs[0], ps[0]) && matchSegs(gs[1:], ps[1:])
}

// segMatch matches one path segment; '*' is any run of characters inside the
// segment (which never contains '/').
func segMatch(pat, seg string) bool {
	px, sx, star, mark := 0, 0, -1, -1
	for sx < len(seg) {
		if px < len(pat) && pat[px] == '*' {
			star, mark = px, sx
			px++
			continue
		}
		if px < len(pat) && pat[px] == seg[sx] {
			px++
			sx++
			continue
		}
		if star != -1 {
			px = star + 1
			mark++
			sx = mark
			continue
		}
		return false
	}
	for px < len(pat) && pat[px] == '*' {
		px++
	}
	return px == len(pat)
}
