// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
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

// handleConnect processes CONNECT authority requests (M2.1): the grant's
// host+port+scheme must cover the target (NO_GRANT when no grant's hosts
// match, PROTOCOL_DENIED when a grant matches the host but not the port).
// The accepted tunnel is then TLS-intercepted under the session CA (M2.2).
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
	reason := connectDecision(sess.Policy, host, port)
	if reason != "" {
		s.recordDenied(sess, r, r.Host, reason, "CONNECT outside granted host/port")
		w.Header().Set("X-Countersign-Reason", reason)
		http.Error(w, "tunnel denied: "+reason, http.StatusForbidden)
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
	s.intercept(cli, sess, connID(r), clientAddr(r), r.Host, host, port)
}

// connectDecision evaluates the CONNECT-time slice of 04 §2 grant
// selection: scheme https, the authority port against each grant's ports,
// the host against each grant's host patterns (methods/paths apply to
// inner requests once the tunnel exists). Returns "" when allowed.
func connectDecision(p *policy.SessionPolicy, host string, port int) string {
	hostMatch := false
	for _, g := range p.Spec.Grants {
		m := g.Match
		scheme := m.Scheme
		if scheme == "" {
			scheme = "https"
		}
		if scheme != "https" {
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
				return ""
			}
		}
	}
	if hostMatch {
		return "PROTOCOL_DENIED"
	}
	return "NO_GRANT"
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
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			s.handleInner(w, req, sess, cID, client, authority, host, port, sni)
		}),
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
	wln := &oneConnListener{conn: dc}
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
func (s *Server) handleInner(w http.ResponseWriter, r *http.Request, sess *Session, cID string, client ClientAddr, authority, connectHost string, connectPort int, sni string) {
	env := &forwardEnv{sess: sess, connID: cID, client: client, connect: connectHost, sni: sni, tlsClient: true}
	path, rawQuery := plainPathQuery(r)
	hhost, hport := splitHostPort(r.Host)
	if hport == 0 {
		hport = connectPort
	}
	// 04 §2 step 1: Host/:authority, the CONNECT authority and the SNI
	// must be identical (after case/dot folding). Anything less — a
	// different name, a different port, an absent Host — is a smuggling
	// suspect. sni arrived normalized from the handshake check.
	if hport != connectPort || normName(hhost) != normName(connectHost) || normName(hhost) != sni {
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
	}, res)
}

// oneConnListener adapts a single established conn to net.Listener for
// http.Server.Serve: the first Accept returns the conn; further Accepts
// block until the conn dies, then report the listener closed so Serve
// returns (the inner conn's handler goroutines unwind independently).
type oneConnListener struct {
	conn net.Conn // a *deadConn
	gave bool
	mu   sync.Mutex
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
		return l.conn, nil
	}
	l.mu.Unlock()
	dc, ok := l.conn.(*deadConn)
	if !ok {
		return nil, errors.New("listener closed")
	}
	<-dc.dead
	return nil, errors.New("listener closed")
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
