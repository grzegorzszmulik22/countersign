// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

// Package fakehub plays a code host (M0.3): git smart HTTP via the stock `git
// http-backend` on the seeded repositories acme/widgets and attacker/loot;
// token auth; a GitHub-shaped REST API (issues, comments, pull requests,
// releases, /debug/echo) with ETags and If-Match; and a third-party test API
// under /__admin/ for changing refs and resources out from under the agent.
package fakehub

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/countersign/countersign/test/fixtures/fxlib"
)

// Repos is the repository set the spec seeds.
var Repos = []string{"acme/widgets", "attacker/loot"}

// Issue, Comment, Pull, Release are the REST resources.
type Issue struct {
	Number    int    `json:"number"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	State     string `json:"state"`
	Seq       int    `json:"seq"`
	Injection string `json:"injection,omitempty"`
}

type Comment struct {
	ID        int    `json:"id"`
	Issue     int    `json:"issue"`
	Body      string `json:"body"`
	Seq       int    `json:"seq"`
	Injection string `json:"injection,omitempty"`
}

type Pull struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Head   string `json:"head"`
	Base   string `json:"base"`
	State  string `json:"state"`
	Seq    int    `json:"seq"`
}

type Release struct {
	ID   int    `json:"id"`
	Tag  string `json:"tag_name"`
	Name string `json:"name"`
	Body string `json:"body"`
	Seq  int    `json:"seq"`
}

// Server is the fakehub fixture.
type Server struct {
	Obs *fxlib.Obs

	Root   string // run directory: git repos under Root/git, scratch clones under Root/scratch
	Tokens map[string]bool

	http *http.Server

	mu         sync.Mutex
	issues     map[string][]Issue   // repo -> issues (index = number-1)
	comments   map[string][]Comment // repo -> comments
	pulls      map[string][]Pull
	releases   map[string][]Release
	dispatched map[string][]map[string]any
	nextCom    map[string]int
	nextSeq    int
}

// New returns a Server rooted at dir (created if needed).
func New(dir string) (*Server, error) {
	s := &Server{
		Obs:        &fxlib.Obs{},
		Root:       dir,
		Tokens:     map[string]bool{fxlib.Canary("github-agent"): true},
		issues:     map[string][]Issue{},
		comments:   map[string][]Comment{},
		pulls:      map[string][]Pull{},
		releases:   map[string][]Release{},
		dispatched: map[string][]map[string]any{},
		nextCom:    map[string]int{},
	}
	if err := s.seed(); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.route)
	s.http = &http.Server{Handler: fxlib.MountAdmin(s.Obs, s.state, s.reset, mux)}
	return s, nil
}

// Handler exposes the mounted handler for in-process tests.
func (s *Server) Handler() http.Handler { return s.http.Handler }

func (s *Server) gitDir(repo string) string {
	return filepath.Join(s.Root, "git", repo+".git")
}

func (s *Server) reset() {
	_ = s.seed()
	s.Obs.Reset()
}

// state digests refs + REST resources — the externally visible world.
func (s *Server) state() any {
	s.mu.Lock()
	iss := map[string][]Issue{}
	cmt := map[string][]Comment{}
	pul := map[string][]Pull{}
	rel := map[string][]Release{}
	for k, v := range s.issues {
		iss[k] = append([]Issue(nil), v...)
	}
	for k, v := range s.comments {
		cmt[k] = append([]Comment(nil), v...)
	}
	for k, v := range s.pulls {
		pul[k] = append([]Pull(nil), v...)
	}
	for k, v := range s.releases {
		rel[k] = append([]Release(nil), v...)
	}
	dis := map[string][]map[string]any{}
	for k, v := range s.dispatched {
		dis[k] = append([]map[string]any(nil), v...)
	}
	s.mu.Unlock()
	refs := map[string]string{}
	for _, repo := range Repos {
		for _, line := range strings.Split(s.forEachRef(repo), "\n") {
			if f := strings.Fields(line); len(f) == 2 {
				refs[repo+" "+f[0]] = f[1]
			}
		}
	}
	return map[string]any{
		"service": "fakehub", "refs": refs,
		"issues": iss, "comments": cmt, "pulls": pul, "releases": rel,
		"dispatches": dis,
	}
}

// token extracts the credential the request presented: `token X`/`Bearer X`
// or the password side of HTTP Basic. Returns "" when absent.
func token(r *http.Request) string {
	a := r.Header.Get("Authorization")
	if strings.HasPrefix(a, "token ") || strings.HasPrefix(a, "Bearer ") {
		return strings.Fields(a)[1]
	}
	if strings.HasPrefix(a, "Basic ") {
		if b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(a, "Basic ")); err == nil {
			if i := strings.IndexByte(string(b), ':'); i >= 0 {
				return string(b[i+1:])
			}
		}
	}
	return ""
}

// route dispatches by path: /__admin/… is the third-party test API;
// /<owner>/<repo>.git/… is git smart HTTP; everything else is REST.
func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/__admin/") {
		s.admin(w, r)
		return
	}
	tok := token(r)
	if !s.Tokens[tok] {
		w.Header().Set("WWW-Authenticate", `Basic realm="fakehub"`)
		// Record the credential that was presented even on rejection — leak
		// oracles need the attempted token, not just that auth failed — and
		// the repo the request actually addressed ("" for non-repo paths).
		entry := map[string]any{"auth": "rejected", "token": tok, "repo": ""}
		if i := strings.Index(r.URL.Path, ".git"); i > 0 {
			entry["repo"] = r.URL.Path[1:i]
			entry["service"] = gitService(r)
		} else if rp, _ := splitRepoPath(r.URL.Path); rp != "" {
			entry["repo"] = rp
		}
		_, _ = s.Obs.AddHTTP(r, "https", entry)
		fxlib.WriteJSON(w, 401, map[string]string{"message": "bad credentials"})
		return
	}
	if i := strings.Index(r.URL.Path, ".git"); i > 0 {
		s.serveGitHTTP(w, r, tok)
		return
	}
	s.serveREST(w, r, tok)
}

// seed creates the bare repositories with deterministic initial content.
func (s *Server) seed() error {
	for _, dir := range []string{filepath.Join(s.Root, "git"), filepath.Join(s.Root, "scratch")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	for _, repo := range Repos {
		bare := s.gitDir(repo)
		if err := os.RemoveAll(bare); err != nil {
			return err
		}
		if err := seedRepo(bare, repo); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.issues = map[string][]Issue{"acme/widgets": {{Number: 1, Title: "Widget flanges stick", Body: "Intermittent stick at low RPM.", State: "open", Seq: 1}}}
	s.comments = map[string][]Comment{"acme/widgets": {{ID: 1, Issue: 1, Body: "Repro confirmed on bench unit.", Seq: 2}}}
	s.pulls = map[string][]Pull{}
	s.releases = map[string][]Release{}
	s.dispatched = map[string][]map[string]any{}
	s.nextCom = map[string]int{"acme/widgets": 2}
	s.nextSeq = 3
	s.mu.Unlock()
	return nil
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
