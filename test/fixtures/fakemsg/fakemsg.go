// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

// Package fakemsg plays a send-only messaging API (M0.3). POST /api/messages
// returns an ID; replies may reference a parent ID; the Idempotency-Key
// header deduplicates sends; every message is recorded.
package fakemsg

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/countersign/countersign/test/fixtures/fxlib"
)

// Message is one recorded message.
type Message struct {
	ID        string `json:"id"`
	To        string `json:"to,omitempty"`
	Text      string `json:"text,omitempty"`
	InReplyTo string `json:"in_reply_to,omitempty"`
	Key       string `json:"idempotency_key,omitempty"`
}

// Server is the fakemsg fixture.
type Server struct {
	Obs  *fxlib.Obs
	http *http.Server

	mu       sync.Mutex
	messages []Message
	byKey    map[string]Message
	nextID   int
}

// New returns a Server with routes wired.
func New() *Server {
	s := &Server{Obs: &fxlib.Obs{}}
	s.seed()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/messages", s.messages_)
	mux.HandleFunc("/api/messages/", s.messageByID)
	mux.HandleFunc("/", s.notFound)
	s.http = &http.Server{Handler: fxlib.MountAdmin(s.Obs, s.state, s.reset, mux)}
	return s
}

// Handler exposes the mounted handler for in-process tests.
func (s *Server) Handler() http.Handler { return s.http.Handler }

func (s *Server) seed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = nil
	s.byKey = map[string]Message{}
	s.nextID = 1
}

func (s *Server) reset() {
	s.seed()
	s.Obs.Reset()
}

func (s *Server) state() any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Message, len(s.messages))
	copy(out, s.messages)
	return map[string]any{"service": "fakemsg", "messages": out}
}

type postBody struct {
	To        string `json:"to"`
	Text      string `json:"text"`
	InReplyTo string `json:"in_reply_to"`
}

func (s *Server) messages_(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		out := make([]Message, len(s.messages))
		copy(out, s.messages)
		s.mu.Unlock()
		_, _ = s.Obs.AddHTTP(r, "https", nil)
		fxlib.WriteJSON(w, 200, map[string]any{"messages": out})
	case http.MethodPost:
		body, _ := s.Obs.AddHTTP(r, "https", nil)
		var pb postBody
		if err := json.Unmarshal(body, &pb); err != nil {
			fxlib.WriteJSON(w, 400, map[string]string{"error": "bad json"})
			return
		}
		key := r.Header.Get("Idempotency-Key")
		s.mu.Lock()
		if key != "" {
			if prev, ok := s.byKey[key]; ok {
				s.mu.Unlock()
				fxlib.WriteJSON(w, 200, map[string]any{"id": prev.ID, "deduplicated": true})
				return
			}
		}
		if pb.InReplyTo != "" && !s.hasIDLocked(pb.InReplyTo) {
			s.mu.Unlock()
			fxlib.WriteJSON(w, 404, map[string]string{"error": "in_reply_to not found"})
			return
		}
		m := Message{
			ID: fmt.Sprintf("msg_%04d", s.nextID), To: pb.To,
			Text: pb.Text, InReplyTo: pb.InReplyTo, Key: key,
		}
		s.nextID++
		s.messages = append(s.messages, m)
		if key != "" {
			s.byKey[key] = m
		}
		s.mu.Unlock()
		fxlib.WriteJSON(w, 201, map[string]any{"id": m.ID})
	default:
		_, _ = s.Obs.AddHTTP(r, "https", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) hasIDLocked(id string) bool {
	for _, m := range s.messages {
		if m.ID == id {
			return true
		}
	}
	return false
}

func (s *Server) messageByID(w http.ResponseWriter, r *http.Request) {
	_, _ = s.Obs.AddHTTP(r, "https", nil)
	id := strings.TrimPrefix(r.URL.Path, "/api/messages/")
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.messages {
		if m.ID == id {
			fxlib.WriteJSON(w, 200, m)
			return
		}
	}
	fxlib.WriteJSON(w, 404, map[string]string{"error": "not found"})
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	_, _ = s.Obs.AddHTTP(r, "https", nil)
	fxlib.WriteJSON(w, 404, map[string]string{"error": "unknown endpoint"})
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
