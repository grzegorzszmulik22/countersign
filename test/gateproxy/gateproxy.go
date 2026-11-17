// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

// Package gateproxy is test infrastructure (M3.6): an HTTP CONNECT forward
// proxy that terminates TLS and applies (*policy.SessionPolicy).Match to
// every request — the spec/04 §2 step-1/2 decision path the broker runs. A
// request that matches an allow grant is relayed to the fixture that owns
// the host name (fxres); anything else is refused 403, the reason in the
// body, and never leaves this process. Every decision is recorded.
package gateproxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/countersign/countersign/internal/policy"
	"github.com/countersign/countersign/test/fixtures/fxlib"
	"github.com/countersign/countersign/test/fixtures/fxres"
)

// Decision is one evaluated request as recorded by the gate.
type Decision struct {
	Method string
	Host   string
	Path   string
	Query  string
	Grant  string
	Reason string
}

// Proxy is the policy gate: CONNECT in, TLS terminated, Match per request.
type Proxy struct {
	ln   net.Listener
	srv  *http.Server
	pol  *policy.SessionPolicy
	ca   *fxlib.CA
	up   *http.Transport
	mu   sync.Mutex
	decs []Decision
}

// New starts a gate enforcing pol, minting interception leaves from ca.
func New(t *testing.T, ca *fxlib.CA, pol *policy.SessionPolicy) *Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("gateproxy listen: %v", err)
	}
	p := &Proxy{
		ln:  ln,
		pol: pol,
		ca:  ca,
		up: &http.Transport{
			Proxy:                 nil,
			DialContext:           fxres.DialContext,
			TLSClientConfig:       &tls.Config{RootCAs: ca.Pool()},
			ForceAttemptHTTP2:     true,
			MaxConnsPerHost:       8,
			ResponseHeaderTimeout: 0,
		},
	}
	p.srv = &http.Server{Handler: http.HandlerFunc(p.onConnect)}
	go func() { _ = p.srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = p.srv.Close()
		p.up.CloseIdleConnections()
	})
	return p
}

// Addr is the host:port clients put in HTTPS_PROXY.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// Decisions returns every evaluated request in order.
func (p *Proxy) Decisions() []Decision {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Decision(nil), p.decs...)
}

// onConnect answers CONNECT host:port with a TLS-intercepted tunnel.
func (p *Proxy) onConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
		return
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
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
	if _, err = fmt.Fprint(buf, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = cli.Close()
		return
	}
	if err = buf.Flush(); err != nil {
		_ = cli.Close()
		return
	}
	cert, err := p.ca.Issue([]string{host})
	if err != nil {
		_ = cli.Close()
		return
	}
	go func() {
		defer func() { _ = cli.Close() }()
		tconn := tls.Server(cli, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})
		hs := &http.Server{Handler: http.HandlerFunc(p.onRequest)}
		_ = hs.Serve(&singleConn{conn: tconn, done: make(chan struct{})})
	}()
}

// onRequest runs inside a tunnel: Match the request, relay or refuse.
func (p *Proxy) onRequest(w http.ResponseWriter, r *http.Request) {
	host, port := r.Host, 443
	if h, ps, err := net.SplitHostPort(r.Host); err == nil {
		host = h
		if _, err := fmt.Sscanf(ps, "%d", &port); err != nil {
			port = 443
		}
	}
	res := p.pol.Match(&policy.Request{
		Method: r.Method, Scheme: "https", Host: host, Port: port,
		Path: r.URL.EscapedPath(), Query: r.URL.RawQuery,
		SNI: host, Connect: host,
	})
	p.mu.Lock()
	p.decs = append(p.decs, Decision{
		Method: r.Method, Host: host, Path: r.URL.EscapedPath(),
		Query: r.URL.RawQuery, Grant: res.Grant, Reason: res.Reason,
	})
	p.mu.Unlock()
	if res.Reason != "" {
		http.Error(w, "gateproxy: denied by policy: "+res.Reason, http.StatusForbidden)
		return
	}
	p.relay(w, r, host)
}

// relay forwards an allowed request to the owning fixture and streams the
// answer back, hop-by-hop headers dropped in both directions.
func (p *Proxy) relay(w http.ResponseWriter, r *http.Request, host string) {
	out := r.Clone(r.Context())
	out.URL = &url.URL{
		Scheme: "https", Host: host,
		Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery,
	}
	out.RequestURI = ""
	out.Host = ""
	for _, h := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "TE",
		"Transfer-Encoding", "Upgrade",
	} {
		out.Header.Del(h)
	}
	resp, err := p.up.RoundTrip(out)
	if err != nil {
		http.Error(w, "gateproxy: upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	for k, vv := range resp.Header {
		if strings.EqualFold(k, "Connection") || strings.EqualFold(k, "Keep-Alive") ||
			strings.EqualFold(k, "Transfer-Encoding") || strings.EqualFold(k, "TE") ||
			strings.EqualFold(k, "Trailer") {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

var errDone = errors.New("gateproxy: tunnel closed")

// singleConn adapts one net.Conn to net.Listener so http.Server can serve a
// keep-alive session inside the tunnel: Accept hands out the conn once, then
// blocks until Close releases it (when Serve exits and closes the listener).
type singleConn struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
}

func (s *singleConn) Accept() (net.Conn, error) {
	if s.conn != nil {
		c := s.conn
		s.conn = nil
		return c, nil
	}
	<-s.done
	return nil, errDone
}

func (s *singleConn) Close() error {
	s.once.Do(func() { close(s.done) })
	return nil
}

func (s *singleConn) Addr() net.Addr {
	if s.conn != nil {
		return s.conn.LocalAddr()
	}
	return nil
}
