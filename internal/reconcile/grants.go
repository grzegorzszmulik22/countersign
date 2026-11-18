// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Grant selection (spec/04 §2), reversibility class (spec/05 §1) and the
// autonomy condition (spec/05 §2). Request objects are the abstract form
// {method, scheme, authority, path, query, sni?, connect?, websocket?,
// mcp?}; queries are the litQuery/digestQuery abstraction of §6.5.
package reconcile

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

var readMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}

const boundaryHost = "countersign.internal"

// condOrder is spec/05 §2's strictness order (deny most strict).
var condOrder = map[string]int{"allow": 0, "intent": 1, "review": 2, "deny": 3}

func isIP(h string) bool {
	_, err := netip.ParseAddr(h)
	return err == nil
}

// splitAuthority splits host[:port]; brackets kept out of host. A
// non-numeric port is part of the host.
func splitAuthority(authority string, defPort int) (string, int) {
	a := strings.ToLower(authority)
	if strings.HasPrefix(a, "[") {
		if end := strings.Index(a, "]"); end != -1 {
			host, rest := a[1:end], a[end+1:]
			if strings.HasPrefix(rest, ":") {
				if p, err := strconv.Atoi(rest[1:]); err == nil {
					return host, p
				}
			}
			return host, defPort
		}
	}
	if i := strings.LastIndex(a, ":"); i >= 0 {
		if p := a[i+1:]; isAllDigits(p) {
			if n, err := strconv.Atoi(p); err == nil {
				return a[:i], n
			}
		}
	}
	return a, defPort
}

func normHost(h string) string {
	h = strings.ToLower(h)
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	return strings.TrimSuffix(h, ".")
}

// hostOK: an IP literal matches its listing only; "*.x" is one or more
// labels, never the apex ("x" itself does not end in ".x").
func hostOK(pat, h string) bool {
	if isIP(h) {
		return pat == h
	}
	if pat == "*" {
		return true
	}
	if strings.HasPrefix(pat, "*.") {
		return strings.HasSuffix(h, pat[1:])
	}
	return pat == h
}

func smugglePath(p string) bool {
	if strings.Contains(p, "\\") {
		return true
	}
	for i := 0; i+2 < len(p); i++ {
		if p[i] != '%' {
			continue
		}
		if v, ok := hexVal(p[i+1], p[i+2]); ok &&
			(v == 0x2e || v == 0x2f || v == 0x5c || v == 0x00) {
			return true
		}
	}
	for _, c := range p {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	for _, s := range strings.Split(p, "/") {
		if s == "." || s == ".." {
			return true
		}
	}
	return false
}

func hexVal(a, b byte) (int, bool) {
	hi, ok1 := unhexNibble(a)
	lo, ok2 := unhexNibble(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	return hi*16 + lo, true
}

func unhexNibble(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}

func isHexDigit(c byte) bool {
	_, ok := unhexNibble(c)
	return ok
}

func isUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~'
}

// pctDecodeUnres decodes %XX escapes for RFC 3986 unreserved characters
// and upper-cases any escape left undecoded.
func pctDecodeUnres(p string) string {
	if !strings.Contains(p, "%") {
		return p
	}
	var b strings.Builder
	for i := 0; i < len(p); {
		if p[i] == '%' && i+2 < len(p) && isHexDigit(p[i+1]) && isHexDigit(p[i+2]) {
			v, _ := hexVal(p[i+1], p[i+2])
			if c := byte(v); isUnreserved(c) {
				b.WriteByte(c)
			} else {
				b.WriteByte('%')
				b.WriteByte(toUpper(p[i+1]))
				b.WriteByte(toUpper(p[i+2]))
			}
			i += 3
		} else {
			b.WriteByte(p[i])
			i++
		}
	}
	return b.String()
}

func toUpper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 32
	}
	return c
}

// segMatch: '*' inside a segment matches any run of non-'/' characters.
func segMatch(pat, seg string) bool {
	parts := strings.Split(pat, "*")
	if len(parts) == 1 {
		return pat == seg
	}
	if !strings.HasPrefix(seg, parts[0]) {
		return false
	}
	if !strings.HasSuffix(seg, parts[len(parts)-1]) {
		return false
	}
	pos := len(parts[0])
	end := len(seg) - len(parts[len(parts)-1])
	if pos > end {
		return false
	}
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(seg[pos:end], parts[i])
		if idx < 0 {
			return false
		}
		pos += idx + len(parts[i])
	}
	return true
}

// pathMatch: '*' inside a segment; '**' is a whole segment matching zero or
// more segments (spec/04 §1 match.paths).
func pathMatch(glob, path string) bool {
	gs := strings.Split(glob, "/")
	ps := strings.Split(path, "/")
	var m func(gi, pi int) bool
	m = func(gi, pi int) bool {
		if gi == len(gs) {
			return pi == len(ps)
		}
		if gs[gi] == "**" {
			for k := 0; k <= len(ps)-pi; k++ {
				if m(gi+1, pi+k) {
					return true
				}
			}
			return false
		}
		return pi < len(ps) && segMatch(gs[gi], ps[pi]) && m(gi+1, pi+1)
	}
	return m(0, 0)
}

// gitSeg strips one optional ".git" transport suffix.
func gitSeg(seg string) string {
	return strings.TrimSuffix(seg, ".git")
}

// gitOp classifies a request as a git smart-HTTP op per spec/04 §2, or nil.
// Scheme is not constrained here; grant matching handles it.
type gitOpT struct {
	access string // "read" or "write"
	owner  string
	repo   string
}

func gitOp(req map[string]any, q query) *gitOpT {
	p := strOr(mget(req, "path"), "/")
	var segs []string
	if strings.HasPrefix(p, "/") {
		segs = strings.Split(p[1:], "/")
	} else {
		segs = strings.Split(p, "/")
	}
	var need string
	switch {
	case len(segs) == 4 && segs[2] == "info" && segs[3] == "refs":
		if str(mget(req, "method")) != "GET" {
			return nil
		}
		switch {
		case q.equal("service=git-upload-pack"):
			need = "read"
		case q.equal("service=git-receive-pack"):
			need = "write"
		default:
			return nil
		}
	case len(segs) == 3 && (segs[2] == "git-upload-pack" || segs[2] == "git-receive-pack"):
		if str(mget(req, "method")) != "POST" || !q.equal("") {
			return nil
		}
		need = "read"
		if segs[2] == "git-receive-pack" {
			need = "write"
		}
	default:
		return nil
	}
	owner, name := segs[0], gitSeg(segs[1])
	if owner == "" || name == "" {
		return nil
	}
	return &gitOpT{need, owner, name}
}

// gitGrantOK: matcher["git-smart-http"] {access, repos:["owner/repo"]}.
// A write op requires access == "write"; the repo list entries compare
// after stripping one ".git" transport suffix.
func gitGrantOK(matcher map[string]any, op *gitOpT) bool {
	git := mdict(matcher, "git-smart-http")
	if git == nil {
		return false
	}
	if op.access == "write" && str(mget(git, "access")) != "write" {
		return false
	}
	for _, e := range asStrList(mget(git, "repos")) {
		parts := strings.Split(e, "/")
		if len(parts) == 2 && parts[0] == op.owner && gitSeg(parts[1]) == op.repo {
			return true
		}
	}
	return false
}

// reqQuery reads the query representation of an abstract request.
func reqQuery(req map[string]any) query {
	if q, ok := req["x-query"].(query); ok {
		return q
	}
	return litQuery(str(mget(req, "query")))
}

// grantMatch: does this grant's `match` select the request? (04 §2 step 2)
func grantMatch(g map[string]any, req map[string]any, q query) bool {
	m := mdict(g, "match")
	scheme := strOr(mget(req, "scheme"), "https")
	if scheme != strOr(mget(m, "scheme"), "https") {
		return false
	}
	defPort := 443
	if scheme == "http" {
		defPort = 80
	}
	host, port := splitAuthority(str(mget(req, "authority")), defPort)
	host = normHost(host)
	ports := mget(m, "ports")
	if ports == nil {
		ports = []any{float64(defPort)}
	}
	if !numInList(ports, float64(port)) {
		return false
	}
	ok := false
	for _, x := range asStrList(mget(m, "hosts")) {
		if hostOK(normHost(x), host) {
			ok = true
		}
	}
	if !ok {
		return false
	}
	if mget(m, "matcher") != nil {
		op := gitOp(req, q)
		return op != nil && gitGrantOK(mdict(m, "matcher"), op)
	}
	if mget(m, "methods") != nil && !inList(mget(m, "methods"), mget(req, "method")) {
		return false
	}
	paths := mget(m, "paths")
	if paths == nil {
		paths = []any{"/**"}
	}
	path := pctDecodeUnres(strOr(mget(req, "path"), "/"))
	for _, x := range asStrList(paths) {
		if pathMatch(x, path) {
			return true
		}
	}
	return false
}

func numInList(v any, n float64) bool {
	for _, e := range asList(v) {
		if f, ok := jsonNum(e); ok && f == n {
			return true
		}
	}
	return false
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

// inList is Python `item in list` for JSON values (identity/==).
func inList(v any, item any) bool {
	for _, e := range asList(v) {
		if jsonDeepEqual(e, item) {
			return true
		}
	}
	return false
}

// selectGrant implements spec/04 §2 steps 1–2: pre-checks, then the first
// matching grant in document order (a deny grant fires only when it is the
// first match). Returns (grant, reason).
func selectGrant(policy map[string]any, req map[string]any) (map[string]any, string) {
	scheme := strOr(mget(req, "scheme"), "https")
	defPort := 443
	if scheme == "http" {
		defPort = 80
	}
	host, _ := splitAuthority(str(mget(req, "authority")), defPort)
	for _, k := range []string{"sni", "connect"} {
		if v := mget(req, k); v != nil {
			if s, ok := v.(string); ok && normHost(s) != normHost(host) {
				return nil, "SMUGGLING_SUSPECT"
			}
		}
	}
	raw := strOr(mget(req, "path"), "/")
	if smugglePath(raw) {
		return nil, "SMUGGLING_SUSPECT"
	}
	grants := mlist(policy, "grants")
	if isIP(host) {
		found := false
		for _, gr := range grants {
			g, _ := gr.(map[string]any)
			for _, x := range asStrList(mget(mdict(g, "match"), "hosts")) {
				nx := normHost(x)
				if isIP(nx) && nx == normHost(host) {
					found = true
				}
			}
		}
		if !found {
			return nil, "NO_GRANT"
		}
	}
	for _, gr := range grants {
		g, ok := gr.(map[string]any)
		if !ok {
			continue
		}
		if grantMatch(g, req, reqQuery(req)) {
			if mget(g, "action") == "deny" {
				return g, "DENY_GRANT"
			}
			return g, ""
		}
	}
	return nil, "NO_GRANT"
}

// stagerStages is spec/05 §1 rule 4: is this request one the grant's
// stager stages?
func stagerStages(grant map[string]any, req map[string]any, q query) bool {
	st := mdict(grant, "stager")
	if len(st) == 0 {
		return false
	}
	if _, ok := st["git"]; ok {
		op := gitOp(req, q)
		return op != nil && op.access == "write" &&
			gitGrantOK(mdict(mdict(grant, "match"), "matcher"), op)
	}
	if _, ok := st["outbox"]; ok {
		// A deferred-send outbox stores requests that are not reads.
		return !readMethods[str(mget(req, "method"))]
	}
	return false
}

func mcpCall(req map[string]any) map[string]any {
	mcp := mdict(req, "mcp")
	if mcp != nil && str(mget(mcp, "method")) == "tools/call" {
		return mcp
	}
	return nil
}

// classify implements spec/05 §1's ordered class rules; the first rule
// that applies wins.
func classify(grant map[string]any, req map[string]any) string {
	mcp := mdict(req, "mcp")
	authHost, _ := splitAuthority(str(mget(req, "authority")), 443)
	if str(mget(grant, "inspect")) == "inference" ||
		normHost(authHost) == boundaryHost ||
		(str(mget(grant, "inspect")) == "mcp" && mcp != nil &&
			str(mget(mcp, "method")) != "tools/call") {
		return "control"
	}
	if cls := mget(grant, "class"); cls != nil && truthy(cls) {
		return str(cls)
	}
	if str(mget(grant, "mode")) == "passthrough" || truthy(mget(req, "websocket")) {
		return "irreversible"
	}
	if stagerStages(grant, req, reqQuery(req)) {
		return "staged"
	}
	if mget(mdict(grant, "match"), "matcher") != nil {
		if op := gitOp(req, reqQuery(req)); op != nil && op.access == "read" &&
			gitGrantOK(mdict(mdict(grant, "match"), "matcher"), op) {
			return "safe"
		}
	}
	if readMethods[str(mget(req, "method"))] {
		return "safe"
	}
	if call := mcpCall(req); call != nil {
		if str(mget(grant, "calls")) == "serialized" { // brokered server, 05 §12
			return "control"
		}
		if str(mget(grant, "inspect")) == "mcp" {
			tool := str(mget(call, "tool"))
			if cls, ok := mget(mdict(grant, "tools"), tool).(string); ok {
				return cls
			}
			return "irreversible"
		}
	}
	if comp := mdict(grant, "compensate"); comp != nil {
		for _, rule := range []string{"restore", "deleteCreated"} {
			methods := mget(mdict(comp, rule), "methods")
			if methods != nil && inList(methods, mget(req, "method")) {
				return "compensable"
			}
		}
	}
	return "irreversible"
}

// condition implements spec/05 §2: strictest of autonomy[class] and the
// grant's requires. `requires: none` ranks as `allow` for strictness.
// Unknown condition names are a trace/policy error (the reference raises).
func condition(policy, grant map[string]any, cls string) (string, error) {
	cond := mget(mdict(policy, "autonomy"), cls)
	if !truthy(cond) {
		cond = "allow"
	}
	conds, ok := cond.(string)
	if !ok {
		return "", fmt.Errorf("autonomy condition for %q is not a string", cls)
	}
	cn, ok := condOrder[conds]
	if !ok {
		return "", fmt.Errorf("unknown autonomy condition %q", conds)
	}
	req := mget(grant, "requires")
	if req == nil || req == "none" {
		req = "allow"
	}
	reqs, ok := req.(string)
	if !ok {
		return "", fmt.Errorf("grant requires is not a string: %v", req)
	}
	rn, ok := condOrder[reqs]
	if !ok {
		return "", fmt.Errorf("unknown grant requires %q", reqs)
	}
	if rn > cn {
		return reqs, nil
	}
	return conds, nil
}
