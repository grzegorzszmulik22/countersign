// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

// Package sink plays the attacker (M0.3): HTTPS, HTTP, raw TCP, UDP, DNS
// (UDP+TCP, answers every name) and ICMP listeners. Every byte received is
// recorded with protocol and source. The captured bytes are the fixture's
// externally visible state.
package sink

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/countersign/countersign/test/fixtures/fxlib"
)

// Listeners names the six listeners of the spec row.
const (
	LHTTPS = "https"
	LHTTP  = "http"
	LTCP   = "tcp"
	LUDP   = "udp"
	LDNSU  = "dns-udp"
	LDNST  = "dns-tcp"
	LICMP  = "icmp"
)

// Server is the sink fixture.
type Server struct {
	Obs *fxlib.Obs

	mu    sync.Mutex
	bytes []captured // ordered captured bytes across listeners = world state

	cert    tls.Certificate
	closers []io.Closer
	errs    []error
}

type captured struct {
	Listener string `json:"listener"`
	Source   string `json:"source"`
	SHA      string `json:"sha256"`
	Len      int    `json:"len"`
}

// New returns a Server.
func New() *Server {
	return &Server{Obs: &fxlib.Obs{}}
}

// Handler exposes the admin endpoints for in-process tests.
func (s *Server) Handler() http.Handler {
	return fxlib.AdminHandler(s.Obs, s.state, s.reset)
}

func (s *Server) reset() {
	s.mu.Lock()
	s.bytes = nil
	s.mu.Unlock()
	s.Obs.Reset()
}

func (s *Server) state() any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]captured, len(s.bytes))
	copy(out, s.bytes)
	return map[string]any{"service": "sink", "captured": out}
}

func (s *Server) record(listener, proto, source string, data []byte, extra map[string]any) {
	s.Obs.AddBytes(listener, proto, source, data, extra)
	s.mu.Lock()
	s.bytes = append(s.bytes, captured{Listener: listener, Source: source, SHA: fxlib.DigestBytes(data), Len: len(data)})
	s.mu.Unlock()
}

// Errors returns listener startup errors (e.g. ICMP without CAP_NET_RAW).
func (s *Server) Errors() []error { return s.errs }

// Start opens the requested listeners. addrs maps listener name to address;
// missing names fall back to the defaults (loopback, high ports for local
// mode — the spec ports 443/80/9000/9001/53 bind in the cluster packaging).
func (s *Server) Start(ctx context.Context, cert tls.Certificate, addrs map[string]string) error {
	s.cert = cert
	get := func(name, def string) string {
		if a := addrs[name]; a != "" {
			return a
		}
		return def
	}
	if err := s.startTLS(ctx, get(LHTTPS, "127.0.0.1:0")); err != nil {
		return err
	}
	if err := s.startHTTP(ctx, get(LHTTP, "127.0.0.1:0")); err != nil {
		return err
	}
	if err := s.startTCP(ctx, get(LTCP, "127.0.0.1:0")); err != nil {
		return err
	}
	if err := s.startUDP(ctx, get(LUDP, "127.0.0.1:0")); err != nil {
		return err
	}
	if err := s.startDNS(ctx, get(LDNSU, "127.0.0.1:0"), get(LDNST, "127.0.0.1:0")); err != nil {
		return err
	}
	s.startICMP(ctx) // best effort; reports its own error
	return nil
}

// Addr returns the bound address of a listener by name.
func (s *Server) Addr(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.closers {
		if n, ok := c.(named); ok && n.name() == name {
			switch x := c.(type) {
			case net.Listener:
				return x.Addr().String()
			case namedUDP:
				return x.LocalAddr().String()
			case *net.UDPConn:
				return x.LocalAddr().String()
			}
		}
	}
	return ""
}

type named interface{ name() string }
type namedListener struct {
	net.Listener
	n string
}

func (n namedListener) name() string { return n.n }

type namedUDP struct {
	*net.UDPConn
	n string
}

func (n namedUDP) name() string { return n.n }

// --- HTTPS / HTTP -----------------------------------------------------------

func (s *Server) httpHandler(listener string) http.Handler {
	admin := fxlib.AdminHandler(s.Obs, s.state, s.reset)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The admin endpoints ride the HTTPS listener: they are logged as
		// received traffic but are not part of the captured-bytes state (so
		// __state stays stable across admin reads, C0.3.5).
		if listener == LHTTPS {
			switch r.URL.Path {
			case "/__observed", "/__state", "/__reset":
				_, _ = s.Obs.AddHTTP(r, listener, map[string]any{"admin": true})
				admin.ServeHTTP(w, r)
				return
			}
		}
		body, _ := s.readRequest(r, listener)
		s.record(listener, "http", r.RemoteAddr, append(requestLine(r), body...), map[string]any{
			"method": r.Method, "path": r.URL.RequestURI(), "host": r.Host,
		})
		w.WriteHeader(200)
		_, _ = fmt.Fprintln(w, "ok")
	})
}

func requestLine(r *http.Request) []byte {
	return []byte(fmt.Sprintf("%s %s %s\r\n", r.Method, r.URL.RequestURI(), r.Proto))
}

func (s *Server) readRequest(r *http.Request, listener string) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer func() { _ = r.Body.Close() }()
	return io.ReadAll(io.LimitReader(r.Body, 1<<20))
}

func (s *Server) startTLS(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("sink https: %w", err)
	}
	nl := namedListener{ln, LHTTPS}
	s.closers = append(s.closers, nl)
	srv := &http.Server{Handler: s.httpHandler(LHTTPS), TLSConfig: &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12}}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() { _ = srv.Serve(tls.NewListener(nl, srv.TLSConfig)) }()
	return nil
}

func (s *Server) startHTTP(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("sink http: %w", err)
	}
	nl := namedListener{ln, LHTTP}
	s.closers = append(s.closers, nl)
	srv := &http.Server{Handler: s.httpHandler(LHTTP)}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() { _ = srv.Serve(nl) }()
	return nil
}

// --- raw TCP / UDP ----------------------------------------------------------

func (s *Server) startTCP(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("sink tcp: %w", err)
	}
	nl := namedListener{ln, LTCP}
	s.closers = append(s.closers, nl)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serveTCP(conn)
		}
	}()
	return nil
}

func (s *Server) serveTCP(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 1<<20)
	n, err := conn.Read(buf)
	if n > 0 {
		s.record(LTCP, "tcp", conn.RemoteAddr().String(), buf[:n], nil)
		_, _ = conn.Write([]byte("ok\n"))
	}
	_ = err
}

func (s *Server) startUDP(ctx context.Context, addr string) error {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("sink udp: %w", err)
	}
	conn, err := net.ListenUDP("udp", a)
	if err != nil {
		return fmt.Errorf("sink udp: %w", err)
	}
	nl := namedUDP{conn, LUDP}
	s.closers = append(s.closers, nl)
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	go func() {
		buf := make([]byte, 1<<16)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			s.record(LUDP, "udp", src.String(), buf[:n], nil)
			_, _ = conn.WriteToUDP([]byte("ok\n"), src)
		}
	}()
	return nil
}

// --- DNS --------------------------------------------------------------------

func (s *Server) startDNS(ctx context.Context, uaddr, taddr string) error {
	a, err := net.ResolveUDPAddr("udp", uaddr)
	if err != nil {
		return fmt.Errorf("sink dns-udp: %w", err)
	}
	uconn, err := net.ListenUDP("udp", a)
	if err != nil {
		return fmt.Errorf("sink dns-udp: %w", err)
	}
	nu := namedUDP{uconn, LDNSU}
	s.closers = append(s.closers, nu)
	go func() {
		<-ctx.Done()
		_ = uconn.Close()
	}()
	go func() {
		buf := make([]byte, 1<<16)
		for {
			n, src, err := uconn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			name, _ := dnsQueryName(q)
			s.record(LDNSU, "dns-udp", src.String(), q, map[string]any{"name": name})
			if resp, err := dnsResponse(q); err == nil {
				_, _ = uconn.WriteToUDP(resp, src)
			}
		}
	}()

	ln, err := net.Listen("tcp", taddr)
	if err != nil {
		_ = uconn.Close()
		return fmt.Errorf("sink dns-tcp: %w", err)
	}
	nl := namedListener{ln, LDNST}
	s.closers = append(s.closers, nl)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serveDNSTCP(conn)
		}
	}()
	return nil
}

func (s *Server) serveDNSTCP(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var lb [2]byte
	if _, err := io.ReadFull(conn, lb[:]); err != nil {
		return
	}
	l := int(binary.BigEndian.Uint16(lb[:]))
	if l > 1<<16 {
		return
	}
	q := make([]byte, l)
	if _, err := io.ReadFull(conn, q); err != nil {
		return
	}
	name, _ := dnsQueryName(q)
	s.record(LDNST, "dns-tcp", conn.RemoteAddr().String(), q, map[string]any{"name": name})
	resp, err := dnsResponse(q)
	if err != nil {
		return
	}
	var out [2]byte
	binary.BigEndian.PutUint16(out[:], uint16(len(resp)))
	_, _ = conn.Write(out[:])
	_, _ = conn.Write(resp)
}

// --- ICMP -------------------------------------------------------------------

// startICMP is best-effort: ip4:icmp needs CAP_NET_RAW (present in the
// cluster packaging; typically absent for unprivileged local processes).
// Failure is recorded in s.errs so checks can report SKIPPED-ENV.
func (s *Server) startICMP(ctx context.Context) {
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		s.errs = append(s.errs, fmt.Errorf("sink icmp: %w", err))
		return
	}
	s.closers = append(s.closers, io.Closer(conn))
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	go func() {
		buf := make([]byte, 1<<16)
		for {
			n, src, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			s.record(LICMP, "icmp", src.String(), buf[:n], nil)
		}
	}()
}
