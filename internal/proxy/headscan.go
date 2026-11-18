// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// The raw request-head inspector (04 §2 step 1, M2.5): net/http accepts
// framing anomalies the spec forbids — bare LF, obsolete line folding,
// Content-Length beside Transfer-Encoding — so the broker inspects the
// first request head on every connection itself, before net/http sees a
// byte. Everything malformed is SMUGGLING_SUSPECT at the connection layer,
// before any grant is consulted. Requests after the first on a conn go
// uninspected per C2.5.1 (pipelined bytes cross verbatim once the first
// head is validated).
//
// The same inspector covers the decrypted conns inside CONNECT tunnels:
// there it additionally sniffs the HTTP/2 connection preface so an
// h2-negotiated inner server passes through unexamined (its framing is
// binary; the parsed-layer checks in handleInner cover it).

package proxy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// maxHeadBytes is the M2.5 per-session header-block limit: 64 KiB.
const maxHeadBytes = 64 * 1024

// h2Preface is the HTTP/2 client connection preface (RFC 9113 §3.4).
const h2Preface = "PRI * HTTP/2.0\r\n\r\n"

// errHeadDenied is returned from Read once a conn-level denial has been
// written; net/http abandons the conn on any read error.
var errHeadDenied = errors.New("countersign: request head denied")

// headDeny is a conn-level rejection: reason is the record/response code
// (SMUGGLING_SUSPECT unless the head exceeded the 64 KiB cap).
type headDeny struct {
	reason, detail string
}

// headInfo is the validated first request head: the fields the conn-level
// denial path needs for attribution and records.
type headInfo struct {
	method    string
	target    string
	host      string // raw Host header value (may be "")
	proxyAuth string // raw Proxy-Authorization value (may be "")
}

// innerScope marks a decrypted CONNECT-tunnel conn: its session and
// CONNECT authority are already known, and its stream may begin with the
// HTTP/2 preface instead of an HTTP/1 head.
type innerScope struct {
	sess      *Session
	authority string
}

// inspectedConn is a net.Conn that validates the first request head before
// releasing a single byte to net/http.
type inspectedConn struct {
	net.Conn
	srv    *Server
	cID    string
	client ClientAddr
	inner  *innerScope
	slot   *connSlot

	buf       []byte // withheld head bytes; after pass, the release queue
	pos       int    // scan offset into buf
	lineStart int    // start of the current line inside buf
	sniffDone bool   // inner: preface decision made
	headDone  bool   // head validated and released (or conn denied)
	denied    *headDeny
	scratch   [8192]byte
}

// connSlot returns a held connection slot to its pool (256/session, plus a
// global unattributed pool). Release is idempotent.
type connSlot struct{ once func() }

func (s *connSlot) Release() {
	if s != nil && s.once != nil {
		s.once()
	}
}

// newInspectedConn wraps c for first-head inspection. cID is the conn's
// record identity; slot releases the session/anon conn budget on close.
func (s *Server) newInspectedConn(c net.Conn, inner *innerScope, cID string, slot *connSlot) *inspectedConn {
	return &inspectedConn{
		Conn:   c,
		srv:    s,
		cID:    cID,
		client: connClient(c),
		inner:  inner,
		slot:   slot,
	}
}

// connClient renders the conn's remote address for records.
func connClient(c net.Conn) ClientAddr {
	host, port := splitHostPort(c.RemoteAddr().String())
	return ClientAddr{IP: host, Port: port}
}

// markOpaque releases inspection entirely: the conn has become a tunnel
// (CONNECT accepted) and everything after this point crosses verbatim.
func (c *inspectedConn) markOpaque() { c.headDone = true }

// Read withholds bytes until the first request head validates, then
// releases the head and everything after it verbatim. On denial it writes
// the response itself and reports a read error so net/http drops the conn.
func (c *inspectedConn) Read(p []byte) (int, error) {
	for {
		if c.denied != nil {
			return 0, errHeadDenied
		}
		if c.headDone {
			if len(c.buf) > 0 {
				n := copy(p, c.buf)
				c.buf = c.buf[n:]
				return n, nil
			}
			return c.Conn.Read(p)
		}
		n, err := c.Conn.Read(c.scratch[:])
		if n > 0 {
			c.buf = append(c.buf, c.scratch[:n]...)
			c.feed()
		}
		if c.denied != nil {
			return 0, errHeadDenied
		}
		if err != nil {
			return 0, err
		}
	}
}

// feed scans newly arrived head bytes: bare LF and the 64 KiB cap are
// checked per byte, line ends on CRLF, the empty line ends the head. Inner
// conns first sniff the h2 preface.
func (c *inspectedConn) feed() {
	for c.pos < len(c.buf) {
		if c.inner != nil && !c.sniffDone {
			n := len(c.buf)
			if n < len(h2Preface) && string(c.buf[:n]) == h2Preface[:n] {
				return // still a candidate preface: wait for more
			}
			c.sniffDone = true
			if n >= len(h2Preface) && string(c.buf[:len(h2Preface)]) == h2Preface {
				c.headDone = true // opaque: h2 takes over
				return
			}
			// Not the preface: scan the buffered bytes as HTTP/1.
		}
		b := c.buf[c.pos]
		c.pos++
		if b == '\n' {
			if c.pos < 2 || c.buf[c.pos-2] != '\r' {
				c.fail(&headDeny{"SMUGGLING_SUSPECT", "bare LF in request head"})
				return
			}
			if c.pos-c.lineStart == 2 {
				c.finishHead()
				return
			}
			c.lineStart = c.pos
		}
		if len(c.buf) > maxHeadBytes {
			c.fail(&headDeny{"LIMIT_HEADER", "request head exceeds 64 KiB"})
			return
		}
	}
}

// finishHead validates the complete first head (buf[:pos]).
func (c *inspectedConn) finishHead() {
	_, deny := checkHead(c.buf[:c.pos], c.inner != nil)
	if deny != nil {
		c.fail(deny)
		return
	}
	c.headDone = true
}

// fail writes the denial response on the raw conn, records it when a
// session can be attributed, and marks the conn dead.
func (c *inspectedConn) fail(d *headDeny) {
	c.denied = d
	info, _ := checkHead(c.buf, c.inner != nil) // best effort for attribution
	sess, authority := c.attribution(info)
	if sess != nil {
		body := DeniedBody{
			ConnID:    c.cID,
			Client:    c.client,
			Authority: authority,
			Reason:    d.reason,
			Detail:    d.detail,
		}
		if err := c.srv.appendRecord(sess, "effect.denied", body); err != nil {
			c.srv.Logf("conn deny record append failed: %v", err)
		}
	} else {
		c.srv.Logf("conn %s from %s denied %s (%s), no session attributable",
			c.cID, c.client.IP, d.reason, d.detail)
	}
	msg := "request denied: " + d.reason + "\n"
	resp := fmt.Sprintf("HTTP/1.1 403 Forbidden\r\nX-Countersign-Reason: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		d.reason, len(msg), msg)
	_, _ = io.WriteString(c.Conn, resp)
}

// attribution resolves the session a conn-level denial can be recorded
// against: the known session inside a tunnel, else the head's
// Proxy-Authorization token plus source-address check.
func (c *inspectedConn) attribution(info *headInfo) (*Session, string) {
	if c.inner != nil {
		authority := c.inner.authority
		if info != nil && info.host != "" {
			authority = info.host
		}
		return c.inner.sess, authority
	}
	if info == nil || info.proxyAuth == "" {
		return nil, ""
	}
	user, token, ok := parseProxyAuth(info.proxyAuth)
	if !ok || user != "cs" {
		return nil, ""
	}
	sess := c.srv.sessions[token]
	if sess == nil {
		return nil, ""
	}
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return nil, ""
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !sess.admits(ip) {
		return sess, info.target // token matched, wrong address: attributable
	}
	return sess, info.target
}

// Close releases the conn slot once, then closes.
func (c *inspectedConn) Close() error {
	c.slot.Release()
	return c.Conn.Close()
}

// ConnectionState surfaces the negotiated TLS state so net/http can pick
// the h2 path for inner (decrypted) conns — the interface method does not
// promote through the embedded net.Conn.
func (c *inspectedConn) ConnectionState() tls.ConnectionState {
	type stater interface{ ConnectionState() tls.ConnectionState }
	if t, ok := c.Conn.(stater); ok {
		return t.ConnectionState()
	}
	return tls.ConnectionState{}
}

// checkHead validates a complete request head (bytes up to and including
// the terminal CRLF). inner=true applies the tunnel rules (CONNECT is
// nonsense, the h2 preface was sniffed earlier). On success it returns the
// fields conn-level code needs; on failure a headDeny.
func checkHead(head []byte, inner bool) (*headInfo, *headDeny) {
	if len(head) < 4 || !bytes.HasSuffix(head, []byte("\r\n\r\n")) {
		return nil, &headDeny{"SMUGGLING_SUSPECT", "truncated request head"}
	}
	lines := bytes.Split(head[:len(head)-2], []byte("\r\n"))
	// lines ends with the empty line that closes the head.
	if len(lines) < 2 || len(lines[len(lines)-1]) != 0 {
		return nil, &headDeny{"SMUGGLING_SUSPECT", "malformed request head"}
	}
	info := &headInfo{}

	// Request line: METHOD SP TARGET SP VERSION, single spaces.
	parts := bytes.Split(lines[0], []byte(" "))
	if len(parts) != 3 || len(parts[0]) == 0 || len(parts[1]) == 0 || len(parts[2]) == 0 {
		return info, &headDeny{"SMUGGLING_SUSPECT", "malformed request line"}
	}
	info.method = string(parts[0])
	info.target = string(parts[1])
	if !isToken(info.method) {
		return info, &headDeny{"SMUGGLING_SUSPECT", "invalid method token"}
	}
	if v := string(parts[2]); v != "HTTP/1.1" && v != "HTTP/1.0" {
		return info, &headDeny{"SMUGGLING_SUSPECT", "unsupported HTTP version " + v}
	}
	if bytes.IndexByte(parts[1], '#') >= 0 || hasCtl(parts[1]) {
		return info, &headDeny{"SMUGGLING_SUSPECT", "request target carries a fragment or control byte"}
	}

	var hostVals, clVals, teVals []string
	for _, raw := range lines[1 : len(lines)-1] {
		if len(raw) == 0 {
			continue
		}
		if raw[0] == ' ' || raw[0] == '\t' {
			return info, &headDeny{"SMUGGLING_SUSPECT", "obsolete line folding in request head"}
		}
		colon := bytes.IndexByte(raw, ':')
		if colon <= 0 {
			return info, &headDeny{"SMUGGLING_SUSPECT", "header line without a colon"}
		}
		name := string(raw[:colon])
		if !isToken(name) {
			return info, &headDeny{"SMUGGLING_SUSPECT", "invalid header name"}
		}
		val := strings.Trim(string(raw[colon+1:]), " \t")
		if hasBadValueByte(val) {
			return info, &headDeny{"SMUGGLING_SUSPECT", "control byte in header value"}
		}
		switch strings.ToLower(name) {
		case "host":
			hostVals = append(hostVals, val)
			info.host = val
		case "content-length":
			clVals = append(clVals, val)
		case "transfer-encoding":
			teVals = append(teVals, val)
		case "proxy-authorization":
			info.proxyAuth = val
		case "connection":
			for _, tok := range strings.Split(val, ",") {
				// An empty element ("a,,b", leading or trailing comma)
				// is a generator bug smugglers lean on — deny it with
				// the malformed tokens.
				if tok = strings.TrimSpace(tok); tok == "" || !isToken(tok) {
					return info, &headDeny{"SMUGGLING_SUSPECT", "malformed Connection token"}
				}
			}
		}
	}

	// Host: at most one. A missing Host is not ambiguous — net/http
	// answers it with 400 itself (or takes the absolute-form authority).
	// Two differing Host headers are a genuine smuggling suspect.
	if len(hostVals) > 1 {
		return info, &headDeny{"SMUGGLING_SUSPECT", "duplicate Host header"}
	}

	// Content-Length: every element of every field must be digits and
	// they must all be the same value.
	clSet := map[string]bool{}
	for _, v := range clVals {
		for _, e := range strings.Split(v, ",") {
			e = strings.TrimSpace(e)
			if !allDigits(e) {
				return info, &headDeny{"SMUGGLING_SUSPECT", "malformed Content-Length"}
			}
			clSet[e] = true
		}
	}
	if len(clSet) > 1 {
		return info, &headDeny{"SMUGGLING_SUSPECT", "differing Content-Length values"}
	}
	// Transfer-Encoding: exactly "chunked", once, and never beside CL.
	if len(teVals) > 0 {
		if len(clSet) > 0 {
			return info, &headDeny{"SMUGGLING_SUSPECT", "Content-Length with Transfer-Encoding"}
		}
		var teList []string
		for _, v := range teVals {
			for _, e := range strings.Split(v, ",") {
				if e = strings.TrimSpace(e); e != "" {
					teList = append(teList, e)
				}
			}
		}
		if len(teList) != 1 || !strings.EqualFold(teList[0], "chunked") {
			return info, &headDeny{"SMUGGLING_SUSPECT", "unsupported Transfer-Encoding"}
		}
	}

	// Request-target form (RFC 9112 §3.2): authority-form only for
	// CONNECT, asterisk-form never on a forward proxy, absolute-form
	// allowed with a matching Host, everything else must be origin-form.
	// 04 §2 step 1's path rules (C2.5.2) apply to the path part only —
	// the query may carry encoded separators as data.
	target := info.target
	pathPart := ""
	switch {
	case info.method == http.MethodConnect:
		if inner {
			return info, &headDeny{"SMUGGLING_SUSPECT", "CONNECT inside a tunnel"}
		}
		if strings.Contains(target, "/") || strings.Contains(target, "#") || target == "" {
			return info, &headDeny{"SMUGGLING_SUSPECT", "malformed CONNECT authority"}
		}
	case target == "*":
		return info, &headDeny{"SMUGGLING_SUSPECT", "asterisk-form request target"}
	case strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://"):
		rest := target[strings.Index(target, "://")+3:]
		auth := rest
		if i := strings.IndexAny(auth, "/?"); i >= 0 {
			auth = auth[:i]
		}
		if auth == "" || hasCtl([]byte(auth)) {
			return info, &headDeny{"SMUGGLING_SUSPECT", "empty absolute-form authority"}
		}
		if len(hostVals) == 1 && !authorityMatch(auth, hostVals[0], target[:strings.Index(target, "://")]) {
			return info, &headDeny{"SMUGGLING_SUSPECT", "absolute-form authority conflicts with Host"}
		}
		pathPart = rest[len(auth):]
		if pathPart == "" || pathPart[0] == '?' {
			pathPart = "/" + pathPart
		}
	case strings.HasPrefix(target, "/"):
		pathPart = target
	default:
		return info, &headDeny{"SMUGGLING_SUSPECT", "request target is not a known form"}
	}
	if pathPart != "" {
		if i := strings.IndexByte(pathPart, '?'); i >= 0 {
			pathPart = pathPart[:i]
		}
		if bannedPath(pathPart) {
			return info, &headDeny{"SMUGGLING_SUSPECT", "path form rejected by 04 §2 step 1"}
		}
	}
	return info, nil
}

// parsedHeadDeny re-applies the smuggling rules still detectable after
// Go's parser ran — the conn-level inspector covers the first head on a
// conn (and an inner h1 conn), but pipelined requests and h2 streams
// reach the handler uninspected. CL+TE and non-chunked TE are denied here
// before grant evaluation, as 04 §2 step 1 requires.
func parsedHeadDeny(r *http.Request) *headDeny {
	// Go's parser drains both headers into struct fields — r.TransferEncoding
	// and r.ContentLength are what survives, not the raw header lines.
	te := r.TransferEncoding
	cl := r.Header.Values("Content-Length")
	if len(te) > 0 {
		if len(cl) > 0 || r.ContentLength > 0 {
			return &headDeny{"SMUGGLING_SUSPECT", "Content-Length with Transfer-Encoding"}
		}
		var list []string
		for _, v := range te {
			for _, e := range strings.Split(v, ",") {
				if e = strings.TrimSpace(e); e != "" {
					list = append(list, e)
				}
			}
		}
		if len(list) != 1 || !strings.EqualFold(list[0], "chunked") {
			return &headDeny{"SMUGGLING_SUSPECT", "unsupported Transfer-Encoding"}
		}
	}
	if len(cl) > 1 {
		set := map[string]bool{}
		for _, v := range cl {
			set[strings.TrimSpace(v)] = true
		}
		if len(set) > 1 {
			return &headDeny{"SMUGGLING_SUSPECT", "differing Content-Length values"}
		}
	}
	if r.URL != nil {
		p := r.URL.EscapedPath()
		if r.URL.RawPath != "" {
			p = r.URL.RawPath
		}
		if bannedPath(p) {
			return &headDeny{"SMUGGLING_SUSPECT", "path form rejected by 04 §2 step 1"}
		}
	}
	return nil
}

// bannedPath applies 04 §2 step 1's path-form rules (C2.5.2): no dot
// segments, no backslash, no control bytes, and none of the
// percent-encoded forms %2e %2f %5c %00 in any letter case — checked
// again after one decode round so a double-encoded form still dies.
func bannedPath(p string) bool {
	if bannedPathOnce(p) {
		return true
	}
	if d := pctDecode(p); d != p {
		return bannedPathOnce(d)
	}
	return false
}

func bannedPathOnce(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f || c == '\\' {
			return true
		}
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		v, ok := byte(0), false
		if i+2 < len(s) {
			v, ok = pctVal(s[i+1], s[i+2])
		}
		if !ok {
			return true // a bare % is not a valid path byte
		}
		// A triplet decoding to '.', '/', '\', NUL or a control byte is
		// a banned encoded form (spec lists %2e %2f %5c %00).
		if v == '.' || v == '/' || v == '\\' || v < 0x20 || v == 0x7f {
			return true
		}
		i += 2
	}
	return false
}

// pctDecode decodes every valid %XX triplet in s.
func pctDecode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, ok := pctVal(s[i+1], s[i+2]); ok {
				b.WriteByte(v)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func pctVal(hi, lo byte) (byte, bool) {
	h, ok1 := hexVal(hi)
	l, ok2 := hexVal(lo)
	if !ok1 || !ok2 {
		return 0, false
	}
	return h<<4 | l, true
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// authorityMatch reports whether an absolute-form authority and a Host
// value name the same endpoint (name folded, default port per scheme).
func authorityMatch(authority, host, scheme string) bool {
	def := 80
	if scheme == "https" {
		def = 443
	}
	ahost, aport := splitHostPort(authority)
	hhost, hport := splitHostPort(host)
	if aport == 0 {
		aport = def
	}
	if hport == 0 {
		hport = def
	}
	return aport == hport && normName(ahost) == normName(hhost)
}

// isToken reports whether s is an RFC 9110 token (tchar+).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// hasCtl reports whether b carries a control byte or DEL.
func hasCtl(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// hasBadValueByte reports whether a header value carries bytes outside
// SP/HTAB/VCHAR/obs-text.
func hasBadValueByte(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\t' || (c >= 0x20 && c != 0x7f) {
			continue
		}
		return true
	}
	return false
}

// allDigits reports whether s is a nonempty string of ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
