// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

// Package echo plays a generic upstream (M0.3). It echoes request details and
// serves /sse (timed events), /bytes (n streamed bytes), /status/<code>, and a
// WebSocket echo at /ws. TLS only, HTTP/1.1 and HTTP/2.
package echo

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/countersign/countersign/test/fixtures/fxlib"
)

// Server is the echo fixture. Hosts are the realistic names it answers under;
// Addr is the bound listener address once started.
type Server struct {
	Obs   *fxlib.Obs
	http  *http.Server
	ready chan struct{}

	mu     sync.Mutex
	writes int // non-safe-method request count (externally observable)
}

// New returns a Server with the routes wired. Call Serve to run it.
func New() *Server {
	s := &Server{Obs: &fxlib.Obs{}, ready: make(chan struct{})}
	mux := http.NewServeMux()
	mux.Handle("/ws", s.count(http.HandlerFunc(s.ws)))
	mux.Handle("/sse", s.count(http.HandlerFunc(s.sse)))
	mux.Handle("/bytes", s.count(http.HandlerFunc(s.bytes)))
	mux.Handle("/status/", s.count(http.HandlerFunc(s.status)))
	mux.Handle("/", s.count(http.HandlerFunc(s.echo)))
	s.http = &http.Server{Handler: fxlib.MountAdmin(s.Obs, s.state, s.reset, mux)}
	return s
}

// count wraps a route: it records the request, restores the consumed body for
// the handler, and counts non-safe methods as writes that move the state
// digest (GET/HEAD/OPTIONS do not, C0.3.5).
func (s *Server) count(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := s.Obs.AddHTTP(r, "https", nil)
		r.Body = io.NopCloser(bytes.NewReader(body))
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			s.mu.Lock()
			s.writes++
			s.mu.Unlock()
		}
		h.ServeHTTP(w, r)
	})
}

// Handler exposes the mounted handler for in-process tests.
func (s *Server) Handler() http.Handler { return s.http.Handler }

func (s *Server) reset() {
	s.mu.Lock()
	s.writes = 0
	s.mu.Unlock()
	s.Obs.Reset()
}

// state digests the write count — the only externally visible echo state.
func (s *Server) state() any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]any{"service": "echo", "writes": s.writes}
}

func (s *Server) echo(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	fxlib.WriteJSON(w, 200, map[string]any{
		"method":      r.Method,
		"path":        r.URL.RequestURI(),
		"proto":       r.Proto,
		"headers":     r.Header,
		"body_sha256": fxlib.DigestBytes(body),
		"body_len":    len(body),
	})
}

func (s *Server) sse(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	interval, _ := strconv.Atoi(r.URL.Query().Get("interval_ms"))
	if n < 1 || n > 10000 {
		n = 1
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(200)
	for i := 0; i < n; i++ {
		_, _ = fmt.Fprintf(w, "event: tick\ndata: {\"i\":%d,\"of\":%d}\n\n", i, n)
		fl.Flush()
		if interval > 0 && i+1 < n {
			select {
			case <-time.After(time.Duration(interval) * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		}
	}
}

func (s *Server) bytes(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n < 0 || n > 1<<26 {
		n = 0
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(n))
	w.WriteHeader(200)
	chunk := make([]byte, 8192)
	for i := range chunk {
		chunk[i] = byte(i)
	}
	for n > 0 {
		m := n
		if m > len(chunk) {
			m = len(chunk)
		}
		written, err := w.Write(chunk[:m])
		if err != nil {
			return
		}
		n -= written
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	code, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/status/"))
	if err != nil || code < 100 || code > 599 {
		code = 400
	}
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, "status %d\n", code)
}

func (s *Server) ws(w http.ResponseWriter, r *http.Request) {
	conn, rw, err := wsHandshake(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	wsServe(conn, rw)
}

// Serve binds addr (e.g. 127.0.0.1:0) and serves TLS with cert until ctx
// ends. It returns the bound address.
func (s *Server) Serve(ctx context.Context, addr string, cert tls.Certificate) (net.Addr, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() { _ = fxlib.ServeTLS(ctx, ln, cert, s.http.Handler) }()
	return ln.Addr(), nil
}
