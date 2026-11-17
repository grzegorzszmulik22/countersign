// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

// Red-team helpers for the rt_* reproductions. Not product code.

package proxy

import (
	"io"
	"net/http"
	"sync"
)

// rtHit is one request an upstream saw, recorded independently of the
// broker's evidence so the two can be compared.
type rtHit struct {
	Method     string
	Host       string
	RequestURI string
	Body       string
	Headers    http.Header
}

// rtHits records upstream requests.
type rtHits struct {
	mu   sync.Mutex
	hits []rtHit
}

func (h *rtHits) add(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	hd := http.Header{}
	for k, v := range r.Header {
		cp := make([]string, len(v))
		copy(cp, v)
		hd[k] = cp
	}
	h.mu.Lock()
	h.hits = append(h.hits, rtHit{Method: r.Method, Host: r.Host, RequestURI: r.RequestURI, Body: string(body), Headers: hd})
	h.mu.Unlock()
}

func (h *rtHits) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.add(r)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("upstream-ok"))
}

func (h *rtHits) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.hits)
}

func (h *rtHits) snapshot() []rtHit {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]rtHit, len(h.hits))
	copy(out, h.hits)
	return out
}
