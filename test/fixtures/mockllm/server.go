// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

// Package mockllm plays model endpoints (M0.3): Anthropic messages, OpenAI
// responses, and OpenAI chat/completions. It serves scripted turns and
// validates that incoming requests carry the tool results the script expects;
// violations are answered and recorded, never silently accepted.
package mockllm

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/countersign/countersign/test/fixtures/fxlib"
)

// Options configures a Server.
type Options struct {
	Variant     Variant
	Conditional bool
	Flaky       *Flaky
}

// Server is the mockllm fixture.
type Server struct {
	Obs *fxlib.Obs

	http *http.Server

	mu     sync.Mutex
	base   *Transcript // pristine
	cursor int
	opts   Options
	files  []fileRec
}

type fileRec struct {
	Key      string `json:"key"`
	Filename string `json:"filename"`
	Purpose  string `json:"purpose"`
	Bytes    int    `json:"bytes"`
	SHA256   string `json:"sha256"`
	ID       string `json:"id"`
}

// New returns a Server serving t.
func New(t *Transcript, opts Options) *Server {
	s := &Server{Obs: &fxlib.Obs{}, base: t, opts: opts}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/messages", s.anthropic)
	mux.HandleFunc("/v1/responses", s.responses)
	mux.HandleFunc("/v1/chat/completions", s.chatCompletions)
	mux.HandleFunc("/v1/files", s.upload)
	s.http = &http.Server{Handler: fxlib.MountAdmin(s.Obs, s.state, s.reset, mux)}
	return s
}

// Handler exposes the mounted handler for in-process tests.
func (s *Server) Handler() http.Handler { return s.http.Handler }

func (s *Server) reset() {
	s.mu.Lock()
	s.cursor = 0
	s.files = nil
	s.mu.Unlock()
	s.Obs.Reset()
}

func (s *Server) state() any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]any{
		"service":     "mockllm",
		"model":       s.base.Model,
		"turns":       len(s.base.Turns),
		"cursor":      s.cursor,
		"files":       s.files,
		"variant":     s.opts.Variant.Kind,
		"conditional": s.opts.Conditional,
	}
}

// turn returns the transcript for this request: the base with any active
// variant applied (flaky decides per request). Returns a copy.
func (s *Server) turn(turnIdx int) Turn {
	t := *s.base
	if s.opts.Variant.Kind != "" && (s.opts.Flaky == nil || s.opts.Flaky.decide()) {
		cp := t
		cp.Turns = make([]Turn, len(t.Turns))
		for i, tn := range t.Turns {
			tn.Response.Calls = append([]Call{}, tn.Response.Calls...)
			cp.Turns[i] = tn
		}
		s.opts.Variant.apply(&cp)
		t = cp
	}
	if turnIdx < 0 || turnIdx >= len(t.Turns) {
		return Turn{Response: Resp{Stop: "end_turn", Text: "(transcript exhausted)"}}
	}
	return t.Turns[turnIdx]
}

// serve is the shared path: validate request, pick response, advance cursor.
// extract returns call-id -> result-content from the request body.
func (s *Server) serve(w http.ResponseWriter, r *http.Request, shape string,
	body []byte,
	extract func([]byte) (results map[string]string, userText string, stream bool, err error),
	render func(w http.ResponseWriter, m *Transcript, idx int, resp Resp, stream bool)) {

	s.mu.Lock()
	idx := s.cursor
	s.mu.Unlock()

	restoreBody(r, body)
	results, userText, stream, err := extract(body)
	entry := map[string]any{"shape": shape, "turn": idx, "stream": stream}

	tn := s.turn(idx)
	if err != nil {
		entry["valid"] = false
		entry["error"] = err.Error()
		_, _ = s.Obs.AddHTTP(r, "https", entry)
		writeErr(w, 400, fmt.Sprintf("mockllm: %v", err))
		return
	}
	valid := true
	var why []string
	if tn.ExpectUserContains != "" && !strings.Contains(userText, tn.ExpectUserContains) {
		valid = false
		why = append(why, "user message missing expected text")
	}
	for key, want := range tn.ExpectResults {
		// expected result may be carried under any of the per-shape ids
		got, ok := results["call_"+key]
		if !ok {
			got, ok = results["toolu_"+key]
		}
		if !ok {
			got, ok = results[key]
		}
		if !ok {
			valid = false
			why = append(why, "missing tool result for "+key)
			continue
		}
		if want != "" && !strings.Contains(got, want) {
			valid = false
			why = append(why, "tool result for "+key+" missing expected content")
		}
	}
	entry["valid"] = valid
	if len(why) > 0 {
		entry["error"] = strings.Join(why, "; ")
	}
	_, _ = s.Obs.AddHTTP(r, "https", entry)
	if !valid {
		writeErr(w, 400, "mockllm: "+strings.Join(why, "; "))
		return
	}

	resp := tn.Response
	if s.opts.Conditional && tn.ConditionalResponse != nil &&
		strings.Contains(string(body), tn.ConditionalResponse.Marker) {
		resp = tn.ConditionalResponse.Response
	}

	s.mu.Lock()
	if idx == s.cursor {
		s.cursor++
	}
	s.mu.Unlock()
	render(w, s.base, idx, resp, stream)
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fxlib.WriteJSON(w, 405, map[string]string{"error": "method"})
		return
	}
	ct := r.Header.Get("Content-Type")
	var filename, purpose string
	var data []byte
	if strings.Contains(ct, "multipart/form-data") {
		if err := r.ParseMultipartForm(64 << 20); err == nil {
			f, hdr, ferr := r.FormFile("file")
			if ferr == nil {
				data, _ = io.ReadAll(f)
				_ = f.Close()
				filename = hdr.Filename
			}
			purpose = r.FormValue("purpose")
		}
	} else {
		data, _ = io.ReadAll(r.Body)
		filename = r.URL.Query().Get("name")
		purpose = r.URL.Query().Get("purpose")
	}
	key := authKey(r)
	s.mu.Lock()
	rec := fileRec{
		Key: key, Filename: filename, Purpose: purpose,
		Bytes: len(data), SHA256: fxlib.DigestBytes(data),
		ID: fmt.Sprintf("file-%d", len(s.files)+1),
	}
	s.files = append(s.files, rec)
	s.mu.Unlock()
	_, _ = s.Obs.AddHTTP(r, "https", map[string]any{"upload": filename, "key_sha256": fxlib.DigestBytes([]byte(key)), "bytes": len(data)})
	fxlib.WriteJSON(w, 200, map[string]any{
		"id": rec.ID, "object": "file", "filename": filename,
		"bytes": len(data), "purpose": purpose, "created_at": 1700000000,
	})
}

func authKey(r *http.Request) string {
	if k := r.Header.Get("x-api-key"); k != "" {
		return k
	}
	a := r.Header.Get("Authorization")
	return strings.TrimPrefix(a, "Bearer ")
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	fxlib.WriteJSON(w, code, map[string]any{
		"error": map[string]string{"type": "invalid_request_error", "message": msg},
	})
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
