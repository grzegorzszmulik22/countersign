// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Package proxy is the Countersign broker data plane (M2): an explicit
// forward proxy that authenticates clients to sessions, applies the
// session's policy to every request, intercepts TLS under a per-session CA,
// and writes evidence before anything is forwarded.
//
// Layout: proxy.go holds the listener, routing and session authentication;
// connect.go the CONNECT path and TLS interception; forward.go the upstream
// round trip, streaming relay and digests; session.go the session table;
// records.go the record sink; keystore.go the session-key store.
package proxy

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config configures a broker Server.
type Config struct {
	// SessionsFile is the local-mode session table (M2.1). Required.
	SessionsFile string
	// RecordsDir receives the broker's records (per-session JSONL plus
	// broker.log). Required.
	RecordsDir string
	// DialContext dials upstream addresses. nil uses the default dialer
	// (the fixture resolver under the fixtures build tag, 02 §8).
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// RootCAs verifies upstream certificates. nil uses the system pool
	// (plus the test root under the fixtures tag).
	RootCAs *x509.CertPool
	// Keys stores session CA keys; nil uses a MemoryKeyStore.
	Keys SessionKeyStore
	// Sink appends records; nil uses a FileRecordSink under RecordsDir.
	// Tests inject failing sinks to prove append failures surface.
	Sink RecordSink
	// Logf receives broker log lines (also mirrored to broker.log).
	// nil logs to stderr.
	Logf func(format string, args ...any)
}

// Server is one broker instance.
type Server struct {
	cfg       Config
	sessions  map[string]*Session // by token
	sink      RecordSink
	keys      SessionKeyStore
	emitter   string
	logf      func(format string, args ...any)
	brokerLog *os.File

	http      *http.Server
	transport *http.Transport
	ln        net.Listener
	mu        sync.Mutex
	tlsSrv    map[*http.Server]bool // per-tunnel inner servers
	conns     map[net.Conn]struct{} // hijacked tunnel conns (untracked by http.Server)
	isClosed  bool
	closed    chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
	// reqs counts request handlers (plain listener and every tunnel's
	// inner server). Close waits for them before closing the record sink:
	// an HTTP/2 handler outlives its tunnel's Serve, and a result record
	// written after the sink closed is evidence lost.
	reqs sync.WaitGroup
}

// NewServer loads the session table and prepares the broker. In local mode
// every table entry becomes an open session (policy loaded, CA minted).
func NewServer(cfg Config) (*Server, error) {
	if cfg.SessionsFile == "" {
		return nil, errors.New("proxy: SessionsFile required")
	}
	if cfg.RecordsDir == "" {
		return nil, errors.New("proxy: RecordsDir required")
	}
	keys := cfg.Keys
	if keys == nil {
		keys = NewMemoryKeyStore()
	}
	sessions, err := loadSessions(cfg.SessionsFile, keys)
	if err != nil {
		return nil, err
	}
	sink := cfg.Sink
	if sink == nil {
		var err error
		sink, err = NewFileRecordSink(cfg.RecordsDir)
		if err != nil {
			return nil, err
		}
	}
	s := &Server{
		cfg:      cfg,
		sessions: sessions,
		sink:     sink,
		keys:     keys,
		emitter:  "broker/" + newULID(),
		tlsSrv:   map[*http.Server]bool{},
		conns:    map[net.Conn]struct{}{},
		closed:   make(chan struct{}),
	}
	s.logf = cfg.Logf
	if s.logf == nil {
		s.logf = log.Printf
	}
	blog, err := os.OpenFile(filepath.Join(cfg.RecordsDir, "broker.log"),
		os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		// Best effort: construction failed; the close error cannot beat
		// the broker-log error we are already returning.
		_ = sink.Close()
		return nil, fmt.Errorf("broker log: %w", err)
	}
	s.brokerLog = blog
	s.http = &http.Server{
		Handler:           s.admit(http.HandlerFunc(s.route)),
		ReadHeaderTimeout: 30 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, newULID())
		},
	}
	s.transport = s.upstreamTransport()
	return s, nil
}

// route dispatches between CONNECT and forward-form requests.
func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handlePlain(w, r)
}

// Logf writes a broker log line (stderr and broker.log under RecordsDir).
func (s *Server) Logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	s.logf("%s", msg)
	if s.brokerLog != nil {
		if _, err := fmt.Fprintf(s.brokerLog, "%s %s\n", time.Now().UTC().Format(time.RFC3339Nano), msg); err != nil {
			s.logf("broker.log write failed: %v", err)
		}
	}
}

// Serve binds addr and serves until ctx is done or Close is called. It
// returns the bound address (relevant for addr "127.0.0.1:0").
func (s *Server) Serve(ctx context.Context, addr string) (net.Addr, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		// Close must not depend on the caller cancelling ctx: it waits on
		// wg, which holds this watcher.
		select {
		case <-ctx.Done():
			s.shutdown()
		case <-s.closed:
		}
	}()
	go func() {
		err := s.http.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			s.Logf("listener error: %v", err)
		}
	}()
	return ln.Addr(), nil
}

// Addr returns the bound listener address, or nil before Serve.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Session returns the open session with the given ID (nil if unknown).
func (s *Server) Session(id string) *Session {
	for _, sess := range s.sessions {
		if sess.ID == id {
			return sess
		}
	}
	return nil
}

// shutdown tears down the listener and every tracked connection, once.
// Safe to call from the ctx watcher and from Close concurrently.
func (s *Server) shutdown() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.isClosed = true
		close(s.closed)
		conns := make([]net.Conn, 0, len(s.conns))
		for c := range s.conns {
			conns = append(conns, c)
		}
		s.mu.Unlock()
		// Best effort: teardown force-closes each listener and conn; a
		// close error only repeats an already-dead transport.
		_ = s.http.Close()
		for _, c := range conns {
			_ = c.Close()
		}
		s.mu.Lock()
		for srv := range s.tlsSrv {
			_ = srv.Close()
		}
		s.mu.Unlock()
	})
}

// trackTunnel registers a hijacked conn + relay goroutine so shutdown can
// force it closed and Close can wait for it. ok=false when already shut.
func (s *Server) trackTunnel(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return false
	}
	s.wg.Add(1)
	s.conns[c] = struct{}{}
	return true
}

// admit wraps a handler so Close waits for it. A request that arrives
// after shutdown began is refused before any upstream effect.
func (s *Server) admit(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		if s.isClosed {
			s.mu.Unlock()
			http.Error(w, "broker shutting down", http.StatusServiceUnavailable)
			return
		}
		s.reqs.Add(1)
		s.mu.Unlock()
		defer s.reqs.Done()
		h.ServeHTTP(w, r)
	})
}

// untrackTunnel releases a conn from tracking.
func (s *Server) untrackTunnel(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	s.wg.Done()
}

// Close shuts the broker down: listener, tunnels and the record sink.
func (s *Server) Close() error {
	s.shutdown()
	s.wg.Wait()
	s.reqs.Wait()
	if s.brokerLog != nil {
		// Best effort: the log is being abandoned either way; only the
		// record sink's close error reaches the caller.
		_ = s.brokerLog.Close()
	}
	return s.sink.Close()
}

// identifySession authenticates the request per 02 §3: the
// Proxy-Authorization bearer token resolves the session AND the connection's
// source address must match the session's client address. Returns the
// session, or the denial code and whether the failure could be attributed
// to a session (a valid token from the wrong address can; a bad token
// cannot).
func (s *Server) identifySession(r *http.Request) (sess *Session, attributed bool) {
	user, token, ok := parseProxyAuth(r.Header.Get("Proxy-Authorization"))
	if !ok || user != "cs" {
		return nil, false
	}
	sess = s.sessions[token]
	if sess == nil {
		return nil, false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !sess.admits(ip) {
		return sess, true
	}
	return sess, false
}

// parseProxyAuth parses "Basic base64(user:password)" from Proxy-Authorization.
func parseProxyAuth(h string) (user, pass string, ok bool) {
	scheme, b64, found := strings.Cut(h, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", "", false
	}
	u, p, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	return u, p, true
}

// denyNoSession writes the 407 (and logs or records the denial per whether
// the failure was attributable to a session, M2.1).
func (s *Server) denyNoSession(w http.ResponseWriter, r *http.Request, sess *Session, attributed bool, authority string) {
	client := clientAddr(r)
	if attributed && sess != nil {
		s.recordDenied(sess, r, authority, "NO_SESSION",
			"session token matched but client address is not the session's client")
	} else {
		s.Logf("denied %s %s from %s: NO_SESSION (session not attributable)", r.Method, authority, client.IP)
	}
	w.Header().Set("Proxy-Authenticate", `Basic realm="countersign"`)
	w.Header().Set("X-Countersign-Reason", "NO_SESSION")
	http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
}

func clientAddr(r *http.Request) ClientAddr {
	host, port, _ := net.SplitHostPort(r.RemoteAddr)
	p := 0
	if v, err := strconv.Atoi(port); err == nil {
		p = v
	}
	return ClientAddr{IP: host, Port: p}
}

// recordDenied appends an effect.denied record to the session's log.
func (s *Server) recordDenied(sess *Session, r *http.Request, authority, reason, detail string) {
	body := DeniedBody{
		ConnID:    connID(r),
		Client:    clientAddr(r),
		Authority: authority,
		Reason:    reason,
		Detail:    detail,
	}
	if err := s.appendRecord(sess, "effect.denied", body); err != nil {
		s.Logf("record append failed for %s denial (authority %s): %v", reason, authority, err)
	}
}

// appendRecord serializes and durably appends one record on the session chain.
func (s *Server) appendRecord(sess *Session, rtype string, body any) error {
	sess.chainMu.Lock()
	rec, err := sess.chain.next(rtype, body, s.emitter, sess.ID)
	sess.chainMu.Unlock()
	if err != nil {
		return err
	}
	return s.sink.Append(sess.ID, rec)
}

// connID scopes effects to the connection that carried them.
type connKey struct{}

func connID(r *http.Request) string {
	if v := r.Context().Value(connKey{}); v != nil {
		return v.(string)
	}
	return ""
}

// splitHostPort splits a host:port into its parts for the upstream record.
func splitHostPort(addr string) (string, int) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	p := 0
	if v, err := strconv.Atoi(port); err == nil {
		p = v
	}
	return host, p
}
