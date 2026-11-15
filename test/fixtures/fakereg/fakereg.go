// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

// Package fakereg plays package registries (M0.3): a PyPI simple index with
// file downloads, and an npm registry with metadata and tarballs. A clean
// package set plus one `evilpkg` whose install script runs a configurable
// command; a /docs/ page that can carry an injection string.
package fakereg

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/countersign/countersign/test/fixtures/fxlib"
)

// Pkg is one published package (both ecosystems).
type Pkg struct {
	Name     string            `json:"name"`
	Version  string            `json:"version"`
	PyFile   string            `json:"py_file,omitempty"` // pypi file name
	PyBytes  []byte            `json:"-"`                 // wheel/sdist content
	PySHA    string            `json:"py_sha256,omitempty"`
	Kind     string            `json:"kind"` // "wheel" | "sdist"
	NpmBytes []byte            `json:"-"`    // .tgz content
	NpmSHA   string            `json:"npm_shasum,omitempty"`
	Scripts  map[string]string `json:"scripts,omitempty"` // npm lifecycle scripts
}

// Server is the fakereg fixture.
type Server struct {
	Obs *fxlib.Obs

	http *http.Server

	mu       sync.Mutex
	pkgs     map[string]*Pkg // normalized name -> pkg
	docsBody string
	evilCmd  string
}

// New returns a Server with seeded packages.
func New() *Server {
	s := &Server{Obs: &fxlib.Obs{}}
	s.seed()
	mux := http.NewServeMux()
	mux.HandleFunc("/__admin/", s.admin)
	mux.HandleFunc("/", s.route)
	s.http = &http.Server{Handler: fxlib.MountAdmin(s.Obs, s.state, s.reset, mux)}
	return s
}

// Handler exposes the mounted handler for in-process tests.
func (s *Server) Handler() http.Handler { return s.http.Handler }

// seed installs the clean set plus evilpkg with the default command.
func (s *Server) seed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkgs = map[string]*Pkg{}
	s.docsBody = "<h1>fixtures documentation</h1>"
	s.evilCmd = ""
	s.addLocked(cleanWheel("cleanlib", "1.0.0"))
	s.addLocked(cleanWheel("safe-dep", "2.3.1"))
	s.rebuildEvilLocked()
}

func (s *Server) addLocked(p *Pkg) { s.pkgs[normalize(p.Name)] = p }

// rebuildEvilLocked regenerates the evilpkg artifacts embedding s.evilCmd.
func (s *Server) rebuildEvilLocked() {
	p := evilPackage("evilpkg", "1.0.0", s.evilCmd)
	s.addLocked(p)
}

func (s *Server) reset() {
	s.seed()
	s.Obs.Reset()
}

func (s *Server) state() any {
	s.mu.Lock()
	defer s.mu.Unlock()
	pk := map[string]any{}
	for name, p := range s.pkgs {
		pk[name] = map[string]any{
			"name": p.Name, "version": p.Version, "kind": p.Kind,
			"py_sha256": p.PySHA, "npm_shasum": p.NpmSHA, "scripts": p.Scripts,
		}
	}
	return map[string]any{
		"service": "fakereg", "packages": pk,
		"docs_sha256": fxlib.DigestBytes([]byte(s.docsBody)),
	}
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/docs/" || p == "/docs":
		_, _ = s.Obs.AddHTTP(r, "https", map[string]any{"rest": "docs"})
		s.mu.Lock()
		body := s.docsBody
		s.mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, body)
	case len(p) >= 7 && p[:7] == "/simple":
		s.pypi(w, r)
	case len(p) >= 9 && p[:9] == "/packages":
		s.pypiFile(w, r)
	default:
		s.npm(w, r)
	}
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	_, _ = s.Obs.AddHTTP(r, "https", map[string]any{"admin": r.URL.Path})
	var in map[string]any
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fxlib.WriteJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	switch r.URL.Path {
	case "/__admin/injection":
		s.mu.Lock()
		if v, ok := in["text"].(string); ok {
			s.docsBody = "<h1>fixtures documentation</h1>\n" + v
		}
		s.mu.Unlock()
		w.WriteHeader(204)
	case "/__admin/evilpkg":
		s.mu.Lock()
		if v, ok := in["command"].(string); ok {
			s.evilCmd = v
			s.rebuildEvilLocked()
		}
		s.mu.Unlock()
		w.WriteHeader(204)
	default:
		fxlib.WriteJSON(w, 404, map[string]string{"error": "unknown admin endpoint"})
	}
}

// Serve binds addr and serves TLS with cert until ctx ends.
func (s *Server) Serve(ctx context.Context, addr string, cert tls.Certificate) (net.Addr, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() { _ = fxlib.ServeTLS(ctx, ln, cert, s.http.Handler) }()
	return ln.Addr(), nil
}
