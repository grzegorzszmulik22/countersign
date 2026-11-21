// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/countersign/countersign/internal/policy"
)

// handleConnect processes CONNECT authority requests (M2.1/M2.5): the
// first grant matching the authority's host+port wins; its mode chooses
// TLS interception (M2.2) or an opaque passthrough relay (M2.5). No match
// is NO_GRANT; a host match on a wrong port is PROTOCOL_DENIED.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	sess, attributed := s.identifySession(r)
	if sess == nil || attributed {
		s.denyNoSession(w, r, sess, attributed, r.Host)
		return
	}
	host, port := splitHostPort(r.Host)
	if host == "" || port == 0 {
		s.recordDenied(sess, r, r.Host, "PROTOCOL_DENIED", "malformed CONNECT authority")
		w.Header().Set("X-Countersign-Reason", "PROTOCOL_DENIED")
		http.Error(w, "bad CONNECT authority", http.StatusForbidden)
		return
	}
	grant, reason := connectGrant(sess.Policy, host, port)
	if reason != "" {
		s.recordDenied(sess, r, r.Host, reason, "CONNECT outside granted host/port")
		w.Header().Set("X-Countersign-Reason", reason)
		http.Error(w, "tunnel denied: "+reason, http.StatusForbidden)
		return
	}

	if grant != nil && grant.Mode == "passthrough" {
		s.passthrough(w, r, sess, grant, host, port)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	cli, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	if _, err := buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		// Best effort: the write failed, so the tunnel conn is already dead.
		_ = cli.Close()
		return
	}
	if err := buf.Flush(); err != nil {
		// Best effort: the flush failed, so the tunnel conn is already dead.
		_ = cli.Close()
		return
	}
	// The tunnel is opaque from here: release head inspection and reattach
	// any bytes the server read past the CONNECT line.
	if ic, ok := cli.(*inspectedConn); ok {
		ic.markOpaque()
	}
	s.intercept(&bufConn{Conn: cli, r: buf.Reader}, sess, connID(r), clientAddr(r), r.Host, host, port)
}

// bufConn re-feeds bytes a bufio.Reader already pulled past the request
// head (a pipelined TLS ClientHello after CONNECT) before the raw conn.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(b []byte) (int, error) {
	if c.r.Buffered() > 0 {
		return c.r.Read(b)
	}
	return c.Conn.Read(b)
}

// connectGrant evaluates the CONNECT-time slice of 04 §2 grant selection:
// the authority port against each grant's ports, the host against each
// grant's host patterns, and the first full match wins. An intercept-mode
// grant requires scheme https (default); a passthrough grant matches on
// host+port alone — its tunnel is opaque TCP, so scheme does not apply.
// Returns the winning grant, or "" plus the deny reason.
func connectGrant(p *policy.SessionPolicy, host string, port int) (*policy.Grant, string) {
	hostMatch := false
	for i := range p.Spec.Grants {
		g := &p.Spec.Grants[i]
		m := g.Match
		scheme := m.Scheme
		if scheme == "" {
			scheme = "https"
		}
		if g.Mode != "passthrough" && scheme != "https" {
			continue
		}
		if !grantHostMatch(m.Hosts, host) {
			continue
		}
		hostMatch = true
		ports := m.Ports
		if ports == nil {
			ports = []int{443}
		}
		for _, gp := range ports {
			if gp == port {
				return g, ""
			}
		}
	}
	if hostMatch {
		return nil, "PROTOCOL_DENIED"
	}
	return nil, "NO_GRANT"
}

// passthrough relays an opaque CONNECT tunnel under a mode:passthrough
// grant (M2.5): resolve-once + range check + dial the authority, then the
// client's first flight is peeked for a TLS ClientHello so the recorded
// SNI lands in the write-ahead effect.tunnel before a byte relays — a
// counted byte splice with the idle bound ends in effect.tunnel.result.
func (s *Server) passthrough(w http.ResponseWriter, r *http.Request, sess *Session, grant *policy.Grant, host string, port int) {
	up, _, err := s.dialUpstream(r.Context(), sess, grant, "tcp", r.Host)
	if err != nil {
		reason := "UPSTREAM"
		var ub *errUpstreamBlocked
		if errors.As(err, &ub) {
			reason = "UPSTREAM_BLOCKED"
		}
		s.recordDenied(sess, r, r.Host, reason, "passthrough dial failed: "+err.Error())
		w.Header().Set("X-Countersign-Reason", reason)
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = up.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	cli, buf, err := hj.Hijack()
	if err != nil {
		_ = up.Close()
		return
	}
	if _, err := buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = up.Close()
		_ = cli.Close()
		return
	}
	if err := buf.Flush(); err != nil {
		_ = up.Close()
		_ = cli.Close()
		return
	}
	if ic, ok := cli.(*inspectedConn); ok {
		ic.markOpaque()
	}
	// Peek the client's first flight: a TLS ClientHello yields the SNI
	// the record carries (C2.5.5). Bytes stay buffered for the relay.
	sni := peekClientHelloSNI(buf.Reader, cli, 3*time.Second)

	effectID := newULID()
	start := time.Now()
	result := &TunnelResultBody{EffectID: effectID}
	defer func() {
		result.DurationMS = float64(time.Since(start).Microseconds()) / 1000.0
		if aerr := s.appendRecord(sess, "effect.tunnel.result", result); aerr != nil {
			s.Logf("tunnel result append failed for %s: %v", r.Host, aerr)
		}
	}()

	// Write-ahead: the effect.tunnel (with whatever SNI the client
	// offered) is durable before a byte crosses to upstream.
	err = s.appendRecordBound(sess, "effect.tunnel", TunnelBody{
		EffectID:  effectID,
		Authority: r.Host,
		SNI:       sni,
		Kind:      "passthrough",
		Decision: DecisionRecord{
			Action: "allow", Reason: "OK", Requires: "allow", Grant: grant.ID, Creds: []string{},
		},
	})
	if err != nil {
		_ = up.Close()
		_ = cli.Close()
		s.Logf("record append failed for passthrough %s: %v", r.Host, err)
		result.Error = "ledger"
		return
	}

	if !s.trackTunnel(cli) {
		_ = up.Close()
		_ = cli.Close()
		result.Error = "broker-closed"
		return
	}
	defer s.untrackTunnel(cli)
	up64, down64, rerr := relayTunnel(&bufConn{Conn: cli, r: buf.Reader}, up, idleTunnelMax)
	result.BytesUp = up64
	result.BytesDown = down64
	if rerr != nil {
		result.Error = rerr.Error()
	}
}

// peekClientHelloSNI watches the first bytes of a passthrough conn for a
// TLS ClientHello and returns its SNI ("" for non-TLS or a deadline miss).
// Peek never consumes bytes: everything the client sent crosses verbatim.
func peekClientHelloSNI(br *bufio.Reader, c net.Conn, budget time.Duration) string {
	// The deadline is what bounds the peek; if it cannot be set the
	// Peek could block past the budget, so report no SNI.
	if err := c.SetReadDeadline(time.Now().Add(budget)); err != nil {
		return ""
	}
	// Best effort: clearing the peek deadline; the conn proceeds under
	// the tunnel's own deadlines or is closing anyway.
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	hdr, err := br.Peek(5)
	if err != nil || hdr[0] != 0x16 {
		return ""
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen <= 0 || recLen > 16384+2048 {
		return ""
	}
	buf, err := br.Peek(5 + recLen)
	if err != nil {
		return ""
	}
	if sni := parseClientHelloSNI(buf[5:]); sni != "" {
		return sni
	}
	// Hello may span records; look one record further.
	extra, err := br.Peek(5 + recLen + 5)
	if err != nil || len(extra) < 5+recLen+5 || extra[5+recLen] != 0x16 {
		return ""
	}
	recLen2 := int(extra[5+recLen+3])<<8 | int(extra[5+recLen+4])
	buf2, err := br.Peek(5 + recLen + 5 + recLen2)
	if err != nil {
		return ""
	}
	if sni := parseClientHelloSNI(buf2[5+recLen+5:]); sni != "" {
		return sni
	}
	return ""
}

// parseClientHelloSNI extracts the server_name extension from a TLS
// ClientHello handshake message (RFC 6066 §3 / RFC 8446).
func parseClientHelloSNI(hs []byte) string {
	if len(hs) < 4 || hs[0] != 0x01 {
		return ""
	}
	n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if n+4 > len(hs) {
		n = len(hs) - 4
	}
	b := hs[4 : 4+n]
	if len(b) < 34 {
		return ""
	}
	b = b[34:] // version + random
	if len(b) < 1 {
		return ""
	}
	sidLen := int(b[0])
	b = b[1:]
	if len(b) < sidLen+2 {
		return ""
	}
	b = b[sidLen:]
	csLen := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) < csLen+1 {
		return ""
	}
	b = b[csLen:]
	compLen := int(b[0])
	b = b[1:]
	if len(b) < compLen+2 {
		return ""
	}
	b = b[compLen:]
	extLen := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) < extLen {
		return ""
	}
	b = b[:extLen]
	for len(b) >= 4 {
		et := int(b[0])<<8 | int(b[1])
		el := int(b[2])<<8 | int(b[3])
		b = b[4:]
		if len(b) < el {
			return ""
		}
		if et == 0x0000 {
			d := b[:el]
			if len(d) < 2 {
				return ""
			}
			listLen := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) < listLen {
				return ""
			}
			d = d[:listLen]
			for len(d) >= 3 {
				nt := d[0]
				nl := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nl {
					return ""
				}
				if nt == 0 {
					return string(d[:nl])
				}
				d = d[nl:]
			}
			return ""
		}
		b = b[el:]
	}
	return ""
}

// grantHostMatch mirrors internal/policy's host matching (04 §1): "*"
// matches any non-IP host, "*.dom" one or more labels below dom (never the
// apex), anything else a literal; IP literals match only an identical
// literal. Kept here because the CONNECT decision is host+port only — the
// package's matcher is not exported for this slice.
func grantHostMatch(patterns []string, host string) bool {
	host = strings.ToLower(host)
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	host = strings.TrimSuffix(host, ".")
	isIP := net.ParseIP(host) != nil
	for _, pat := range patterns {
		pat = strings.ToLower(strings.TrimSuffix(pat, "."))
		if isIP {
			if pat == host {
				return true
			}
			continue
		}
		if pat == "*" {
			return true
		}
		if strings.HasPrefix(pat, "*.") {
			if strings.HasSuffix(host, pat[1:]) {
				return true
			}
			continue
		}
		if pat == host {
			return true
		}
	}
	return false
}

// errSNIMismatch aborts the client TLS handshake when the requested SNI
// disagrees with the CONNECT authority (04 §2 step 1, C2.2.4).
var errSNIMismatch = errors.New("proxy: SNI does not match CONNECT authority")

// normName folds an authority host name for the 04 §2 step 1 identity
// cross-checks ("must be identical after lowercasing", with the trailing
// root dot treated as the same name — the conventional equivalence every
// TLS stack already applies).
func normName(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// intercept runs the M2.2 pipeline on an accepted CONNECT tunnel: the
// client handshake is terminated under the session CA (leaf minted per
// SNI host, verified there equal to the CONNECT authority), then the
// decrypted stream is served by a per-tunnel http.Server so each inner
// request goes through the policy match, write-ahead record and forward
// pipeline like a plain-listener request.
//
// The tunnel conn is tracked so shutdown can break it; the inner server is
// tracked so shutdown closes it too. Intercept returns when the conn dies.
func (s *Server) intercept(cli net.Conn, sess *Session, cID string, client ClientAddr, authority, host string, port int) {
	if !s.trackTunnel(cli) {
		// Best effort: the server is shutting down; nothing reads this conn.
		_ = cli.Close()
		return
	}
	defer s.untrackTunnel(cli)
	// Best effort: intercept always owns this conn to its end; a close
	// error here can only repeat an already-known teardown.
	defer func() { _ = cli.Close() }()

	var (
		sni         string
		sniMismatch bool
	)
	wantName := normName(host)
	tcfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// X25519 only: the standard mandatory TLS 1.3 group — skips the
		// hybrid ML-KEM key exchange whose cost dominates handshakes on
		// this host.
		CurvePreferences: []tls.CurveID{tls.X25519},
		// ALPN offer to the client is fixed: h2 and http/1.1 (M2.2). The
		// upstream side negotiates independently on its own TLS conn.
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni = normName(hello.ServerName)
			if sni != wantName {
				sniMismatch = true
				return nil, errSNIMismatch
			}
			return sess.mintLeaf(sni)
		},
	}
	tc := tls.Server(cli, tcfg)
	if err := tc.Handshake(); err != nil {
		if sniMismatch {
			// A denial that fails to record breaks write-ahead
			// completeness: surface the append failure as a broker
			// error rather than dropping it.
			if aerr := s.appendRecord(sess, "effect.denied", DeniedBody{
				ConnID:    cID,
				Client:    client,
				Authority: authority,
				Reason:    "SMUGGLING_SUSPECT",
				Detail:    "TLS SNI " + sni + " != CONNECT authority " + authority,
			}); aerr != nil {
				s.Logf("record append failed for SMUGGLING_SUSPECT denial (authority %s): %v", authority, aerr)
			}
		}
		return
	}

	// The per-tunnel server: TLSConfig's NextProtos marker is what makes
	// http.Server wire the h2 path for *tls.Conn conns this listener hands
	// it (net/http: Serve configures HTTP/2 when TLSConfig names "h2" or is
	// nil; an explicit list documents intent).
	inner := &http.Server{
		Handler: s.admit(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			s.handleInner(w, req, sess, cID, client, authority, host, port, sni)
		})),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, cID)
		},
		ErrorLog:          log.New(writerFunc(func(b []byte) (int, error) { s.Logf("%s", strings.TrimSpace(string(b))); return len(b), nil }), "", 0),
		TLSConfig:         &tls.Config{NextProtos: []string{"h2", "http/1.1"}},
		ReadHeaderTimeout: 30 * time.Second,
	}
	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		// Best effort: shutdown already began; the close error adds nothing.
		_ = tc.Close()
		return
	}
	s.tlsSrv[inner] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.tlsSrv, inner)
		s.mu.Unlock()
	}()

	dc := watchConn(tc)
	// The decrypted conn gets the same first-head inspection as the outer
	// listener (M2.5), plus the h2-preface sniff — an inner h2 conn passes
	// through uninspected once the preface matches.
	ic := s.newInspectedConn(dc, &innerScope{sess: sess, authority: authority}, cID, nil)
	wln := &oneConnListener{serve: ic, dead: dc.(*deadConn)}
	serr := inner.Serve(wln)
	if derr := dc.(*deadConn).err; derr != nil || serr != nil {
		s.Logf("tunnel %s inner serve: %v (conn err: %v)", cID, serr, derr)
	}
	// Best effort: Serve already returned; Close can only fail on work
	// that is already torn down.
	_ = inner.Close()
}

// writerFunc adapts a function to io.Writer (for http.Server.ErrorLog).
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

// handleInner applies 04 §2 to one decrypted request inside a CONNECT
// tunnel: the Host/:authority cross-check (SMUGGLING_SUSPECT), then the
// grant match, then forward — same as the plain listener, at scheme https.
// On HTTP/2 a literal Host header inside the stream must agree with
// :authority too — Go's h2 layer keeps the header while r.Host follows
// :authority (M2.5).
func (s *Server) handleInner(w http.ResponseWriter, r *http.Request, sess *Session, cID string, client ClientAddr, authority, connectHost string, connectPort int, sni string) {
	env := &forwardEnv{sess: sess, connID: cID, client: client, connect: connectHost, sni: sni, tlsClient: true}
	// One request per inner h1 conn, matching the outer posture: a
	// pipelined head is uninspectable post-parse. h2 is untouched — the
	// header is a no-op on h2 responses.
	if r.ProtoMajor < 2 {
		w.Header().Set("Connection", "close")
	}
	path, rawQuery, forceQ := wirePathQuery(r)
	// Inner h2 streams (and any pipelined h1 request past the first) reach
	// here uninspected: re-apply the parsed-layer smuggling rules before
	// the grant is consulted.
	if deny := parsedHeadDeny(r); deny != nil {
		s.denyRequest(w, r, env, deny.reason, "https", r.Host, path, rawQuery, "")
		return
	}
	hhost, hport := splitHostPort(r.Host)
	if hport == 0 {
		hport = connectPort
	}
	// 04 §2 step 1: Host/:authority, the CONNECT authority and the SNI
	// must be identical (after case/dot folding). Anything less — a
	// different name, a different port, an absent Host — is a smuggling
	// suspect. sni arrived normalized from the handshake check.
	bad := hport != connectPort || normName(hhost) != normName(connectHost) || normName(hhost) != sni
	if !bad {
		if v := r.Header.Get("Host"); v != "" {
			hh, hp := splitHostPort(v)
			if hp == 0 {
				hp = connectPort
			}
			bad = hp != connectPort || normName(hh) != normName(connectHost)
		}
	}
	if bad {
		s.denyRequest(w, r, env, "SMUGGLING_SUSPECT", "https", r.Host, path, rawQuery, "")
		return
	}
	res := sess.Policy.Match(policyRequest(r, "https", connectHost, connectPort, path, rawQuery, sni, connectHost))
	if res.Reason != "" {
		s.denyRequest(w, r, env, res.Reason, "https", r.Host, path, rawQuery, res.Grant)
		return
	}
	s.forward(w, r, env, forwardTarget{
		scheme:    "https",
		authority: r.Host,
		host:      connectHost,
		port:      connectPort,
		path:      path,
		rawQuery:  rawQuery,
		forceQ:    forceQ,
	}, res)
}

// oneConnListener adapts a single established conn to net.Listener for
// http.Server.Serve: the first Accept returns the conn; further Accepts
// block until the conn dies, then report the listener closed so Serve
// returns (the inner conn's handler goroutines unwind independently).
// serve is the conn handed to Serve (the head inspector); dead is the
// watcher that marks conn death.
type oneConnListener struct {
	serve net.Conn
	dead  *deadConn
	gave  bool
	mu    sync.Mutex
}

func watchConn(c net.Conn) net.Conn {
	return &deadConn{Conn: c, dead: make(chan struct{})}
}

// deadConn exposes dead, closed when the conn first fails or closes, and
// err, the first error that marked it.
type deadConn struct {
	net.Conn
	dead     chan struct{}
	deadOnce sync.Once
	err      error
}

func (c *deadConn) mark(err error) { c.deadOnce.Do(func() { c.err = err; close(c.dead) }) }

// ConnectionState surfaces the negotiated protocol so http.Server picks the
// h2 path for this conn (it probes c.rwc for the connectionStater
// interface; embedding net.Conn would hide *tls.Conn's method).
func (c *deadConn) ConnectionState() tls.ConnectionState {
	type stater interface{ ConnectionState() tls.ConnectionState }
	if t, ok := c.Conn.(stater); ok {
		return t.ConnectionState()
	}
	return tls.ConnectionState{}
}

func (c *deadConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		// A timeout is not conn death here: connReader.abortPendingRead
		// (called from response.finishRequest on every request) sets a
		// past deadline so the pending background read returns an i/o
		// timeout; net/http treats that error as an internal signal,
		// not a failure. Only real read errors mean the tunnel died.
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return n, err
		}
		c.mark(err)
	}
	return n, err
}

func (c *deadConn) Close() error {
	c.mark(nil)
	return c.Conn.Close()
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.gave {
		l.gave = true
		l.mu.Unlock()
		return l.serve, nil
	}
	l.mu.Unlock()
	<-l.dead.dead
	return nil, errors.New("listener closed")
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.serve.LocalAddr() }
