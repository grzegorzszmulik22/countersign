// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package fakehub

import (
	"net/http"

	"github.com/countersign/countersign/test/fixtures/fxlib"
)

// Third-party test API: the harness acts as someone else touching the same
// code host — seeding injection content, pushing refs around, installing the
// pre-receive hook. All under /__admin/ and intentionally unauthenticated.
func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	_, _ = s.Obs.AddHTTP(r, "https", map[string]any{"admin": r.URL.Path})
	var in map[string]any
	decode := func() bool {
		in = map[string]any{}
		if err := readBodyJSON(r, &in); err != nil {
			fxlib.WriteJSON(w, 400, map[string]string{"error": "bad json"})
			return false
		}
		return true
	}
	str := func(k string) string {
		v, _ := in[k].(string)
		return v
	}

	switch r.URL.Path {
	case "/__admin/seed_issue":
		if !decode() {
			return
		}
		repo := str("repo")
		s.mu.Lock()
		is := Issue{Number: len(s.issues[repo]) + 1, Title: str("title"), Body: str("body"), State: "open", Injection: str("injection"), Seq: s.nextSeq}
		s.nextSeq++
		s.issues[repo] = append(s.issues[repo], is)
		s.mu.Unlock()
		fxlib.WriteJSON(w, 201, is)

	case "/__admin/seed_comment":
		if !decode() {
			return
		}
		repo := str("repo")
		s.mu.Lock()
		c := Comment{ID: s.nextCom[repo], Issue: int(num(in["issue"])), Body: str("body"), Injection: str("injection"), Seq: s.nextSeq}
		s.nextCom[repo]++
		s.nextSeq++
		s.comments[repo] = append(s.comments[repo], c)
		s.mu.Unlock()
		fxlib.WriteJSON(w, 201, c)

	case "/__admin/commit":
		if !decode() {
			return
		}
		files := map[string]string{}
		if fm, ok := in["files"].(map[string]any); ok {
			for k, v := range fm {
				files[k], _ = v.(string)
			}
		}
		sha, err := s.adminCommit(str("repo"), str("branch"), str("message"), files)
		if err != nil {
			fxlib.WriteJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		fxlib.WriteJSON(w, 200, map[string]string{"sha": sha})

	case "/__admin/ref":
		if !decode() {
			return
		}
		if err := s.updateRef(str("repo"), str("ref"), str("sha")); err != nil {
			fxlib.WriteJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(204)

	case "/__admin/hook":
		if r.Method == http.MethodDelete {
			if !decode() {
				return
			}
			if err := s.installHook(str("repo"), str("name"), ""); err != nil {
				fxlib.WriteJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			w.WriteHeader(204)
			return
		}
		if !decode() {
			return
		}
		if err := s.installHook(str("repo"), str("name"), str("script")); err != nil {
			fxlib.WriteJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(204)

	default:
		fxlib.WriteJSON(w, 404, map[string]string{"error": "unknown admin endpoint"})
	}
}

func num(v any) float64 {
	f, _ := v.(float64)
	return f
}
