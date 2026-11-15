// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package fakehub

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/countersign/countersign/test/fixtures/fxlib"
)

// GitHub-shaped REST API under api.github.com. Every mutating endpoint takes
// the entity ETag in If-Match; mismatches are 412. Token and repo are
// recorded with each request (M0.3 row).

func (s *Server) serveREST(w http.ResponseWriter, r *http.Request, tok string) {
	repo, tail := splitRepoPath(r.URL.Path)
	_, _ = s.Obs.AddHTTP(r, "https", map[string]any{"token": tok, "repo": repo, "rest": tail})

	if r.URL.Path == "/debug/echo" {
		fxlib.WriteJSON(w, 200, map[string]any{
			"method": r.Method, "path": r.URL.RequestURI(), "headers": r.Header,
		})
		return
	}
	if repo == "" || !knownRepo(repo) {
		fxlib.WriteJSON(w, 404, map[string]string{"message": "not found"})
		return
	}
	switch {
	case tail == "/issues":
		s.issuesRoot(w, r, repo)
	case strings.HasPrefix(tail, "/issues/comments/"):
		s.commentByID(w, r, repo, strings.TrimPrefix(tail, "/issues/comments/"))
	case strings.HasPrefix(tail, "/issues/") && strings.HasSuffix(tail, "/comments"):
		s.commentsRoot(w, r, repo, tail)
	case strings.HasPrefix(tail, "/issues/"):
		s.issueByNum(w, r, repo, strings.TrimPrefix(tail, "/issues/"))
	case tail == "/pulls":
		s.pullsRoot(w, r, repo)
	case strings.HasPrefix(tail, "/pulls/"):
		s.pullByNum(w, r, repo, strings.TrimPrefix(tail, "/pulls/"))
	case tail == "/releases":
		s.releasesRoot(w, r, repo)
	case tail == "/dispatches":
		s.dispatches(w, r, repo)
	default:
		fxlib.WriteJSON(w, 404, map[string]string{"message": "not found"})
	}
}

// splitRepoPath extracts /repos/{owner}/{repo} and returns the remaining tail.
func splitRepoPath(p string) (repo, tail string) {
	if !strings.HasPrefix(p, "/repos/") {
		return "", ""
	}
	rest := strings.TrimPrefix(p, "/repos/")
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 {
		return "", ""
	}
	repo = parts[0] + "/" + parts[1]
	if len(parts) == 3 {
		tail = "/" + parts[2]
	}
	return repo, tail
}

func etagOf(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return `W/"` + hex.EncodeToString(h[:8]) + `"`
}

// matchETag enforces If-Match on mutations: header must carry the current ETag.
func matchETag(r *http.Request, etag string) bool {
	for _, f := range strings.Split(r.Header.Get("If-Match"), ",") {
		if strings.TrimSpace(f) == etag {
			return true
		}
	}
	return false
}

func readBodyJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return fmt.Errorf("empty body")
	}
	defer func() { _ = r.Body.Close() }()
	return json.NewDecoder(r.Body).Decode(v)
}

func parseNum(s string) int {
	n, _ := strconv.Atoi(strings.Trim(s, "/"))
	return n
}

// --- issues -----------------------------------------------------------------

func (s *Server) issuesRoot(w http.ResponseWriter, r *http.Request, repo string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("q")
		out := []Issue{}
		for _, is := range s.issues[repo] {
			if q == "" || strings.Contains(is.Title, q) || strings.Contains(is.Body, q) {
				out = append(out, is)
			}
		}
		fxlib.WriteJSON(w, 200, out)
	case http.MethodPost:
		var in Issue
		if err := readBodyJSON(r, &in); err != nil {
			fxlib.WriteJSON(w, 400, map[string]string{"message": "bad json"})
			return
		}
		is := Issue{
			Number: len(s.issues[repo]) + 1, Title: in.Title, Body: in.Body,
			State: "open", Seq: s.nextSeq,
		}
		s.nextSeq++
		s.issues[repo] = append(s.issues[repo], is)
		w.Header().Set("ETag", etagOf(is))
		fxlib.WriteJSON(w, 201, is)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) issueByNum(w http.ResponseWriter, r *http.Request, repo, numStr string) {
	n := parseNum(numStr)
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := n - 1
	if idx < 0 || idx >= len(s.issues[repo]) {
		fxlib.WriteJSON(w, 404, map[string]string{"message": "issue not found"})
		return
	}
	cur := s.issues[repo][idx]
	et := etagOf(cur)
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("ETag", et)
		fxlib.WriteJSON(w, 200, cur)
	case http.MethodPatch:
		if !matchETag(r, et) {
			fxlib.WriteJSON(w, 412, map[string]string{"message": "If-Match failed"})
			return
		}
		var in Issue
		if err := readBodyJSON(r, &in); err != nil {
			fxlib.WriteJSON(w, 400, map[string]string{"message": "bad json"})
			return
		}
		if in.Title != "" {
			cur.Title = in.Title
		}
		if in.Body != "" {
			cur.Body = in.Body
		}
		if in.State != "" {
			cur.State = in.State
		}
		s.issues[repo][idx] = cur
		w.Header().Set("ETag", etagOf(cur))
		fxlib.WriteJSON(w, 200, cur)
	case http.MethodDelete:
		if !matchETag(r, et) {
			fxlib.WriteJSON(w, 412, map[string]string{"message": "If-Match failed"})
			return
		}
		s.issues[repo] = append(s.issues[repo][:idx], s.issues[repo][idx+1:]...)
		for i := range s.issues[repo] {
			s.issues[repo][i].Number = i + 1
		}
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// --- comments ---------------------------------------------------------------

func (s *Server) commentsRoot(w http.ResponseWriter, r *http.Request, repo, tail string) {
	n := parseNum(strings.TrimSuffix(tail, "/comments"))
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		var out []Comment
		for _, c := range s.comments[repo] {
			if c.Issue == n {
				out = append(out, c)
			}
		}
		if out == nil {
			out = []Comment{}
		}
		fxlib.WriteJSON(w, 200, out)
	case http.MethodPost:
		var in Comment
		if err := readBodyJSON(r, &in); err != nil {
			fxlib.WriteJSON(w, 400, map[string]string{"message": "bad json"})
			return
		}
		c := Comment{ID: s.nextCom[repo], Issue: n, Body: in.Body, Injection: in.Injection, Seq: s.nextSeq}
		s.nextCom[repo]++
		s.nextSeq++
		s.comments[repo] = append(s.comments[repo], c)
		w.Header().Set("ETag", etagOf(c))
		fxlib.WriteJSON(w, 201, c)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) commentByID(w http.ResponseWriter, r *http.Request, repo, idStr string) {
	id := parseNum(idStr)
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, c := range s.comments[repo] {
		if c.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		fxlib.WriteJSON(w, 404, map[string]string{"message": "comment not found"})
		return
	}
	cur := s.comments[repo][idx]
	et := etagOf(cur)
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("ETag", et)
		fxlib.WriteJSON(w, 200, cur)
	case http.MethodPatch:
		if !matchETag(r, et) {
			fxlib.WriteJSON(w, 412, map[string]string{"message": "If-Match failed"})
			return
		}
		var in Comment
		if err := readBodyJSON(r, &in); err != nil {
			fxlib.WriteJSON(w, 400, map[string]string{"message": "bad json"})
			return
		}
		cur.Body = in.Body
		s.comments[repo][idx] = cur
		w.Header().Set("ETag", etagOf(cur))
		fxlib.WriteJSON(w, 200, cur)
	case http.MethodDelete:
		if !matchETag(r, et) {
			fxlib.WriteJSON(w, 412, map[string]string{"message": "If-Match failed"})
			return
		}
		s.comments[repo] = append(s.comments[repo][:idx], s.comments[repo][idx+1:]...)
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// --- pull requests ------------------------------------------------------------

func (s *Server) pullsRoot(w http.ResponseWriter, r *http.Request, repo string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		fxlib.WriteJSON(w, 200, s.pulls[repo])
	case http.MethodPost:
		var in Pull
		if err := readBodyJSON(r, &in); err != nil {
			fxlib.WriteJSON(w, 400, map[string]string{"message": "bad json"})
			return
		}
		// Creation fails unless the branch exists on the real remote.
		if !s.refExists(repo, in.Head) {
			fxlib.WriteJSON(w, 422, map[string]string{"message": "head branch does not exist: " + in.Head})
			return
		}
		p := Pull{Number: len(s.pulls[repo]) + 1, Title: in.Title, Head: in.Head, Base: in.Base, State: "open", Seq: s.nextSeq}
		s.nextSeq++
		s.pulls[repo] = append(s.pulls[repo], p)
		w.Header().Set("ETag", etagOf(p))
		fxlib.WriteJSON(w, 201, p)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) pullByNum(w http.ResponseWriter, r *http.Request, repo, numStr string) {
	n := parseNum(numStr)
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := n - 1
	if idx < 0 || idx >= len(s.pulls[repo]) {
		fxlib.WriteJSON(w, 404, map[string]string{"message": "pull request not found"})
		return
	}
	cur := s.pulls[repo][idx]
	w.Header().Set("ETag", etagOf(cur))
	fxlib.WriteJSON(w, 200, cur)
}

// --- dispatches ---------------------------------------------------------------

// dispatches records repository_dispatch events (mcpdemo's phone-home POSTs).
func (s *Server) dispatches(w http.ResponseWriter, r *http.Request, repo string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in map[string]any
	_ = readBodyJSON(r, &in)
	s.mu.Lock()
	s.dispatched[repo] = append(s.dispatched[repo], in)
	s.nextSeq++
	s.mu.Unlock()
	fxlib.WriteJSON(w, 204, nil)
}

// --- releases -----------------------------------------------------------------

func (s *Server) releasesRoot(w http.ResponseWriter, r *http.Request, repo string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		fxlib.WriteJSON(w, 200, s.releases[repo])
	case http.MethodPost:
		var in Release
		if err := readBodyJSON(r, &in); err != nil {
			fxlib.WriteJSON(w, 400, map[string]string{"message": "bad json"})
			return
		}
		rel := Release{ID: len(s.releases[repo]) + 1, Tag: in.Tag, Name: in.Name, Body: in.Body, Seq: s.nextSeq}
		s.nextSeq++
		s.releases[repo] = append(s.releases[repo], rel)
		w.Header().Set("ETag", etagOf(rel))
		fxlib.WriteJSON(w, 201, rel)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
