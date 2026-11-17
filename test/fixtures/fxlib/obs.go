// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package fxlib

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
)

// maxBodyStored caps the verbatim body bytes kept per observation (and echoed
// in __observed). The digest and length always cover the full body.
const maxBodyStored = 1 << 20

// Observation is one entry in a fixture's received-everything log, served
// verbatim by GET /__observed. For TCP/UDP/DNS/ICMP listeners Method is empty
// and Proto names the listener (e.g. "tcp", "udp", "dns-udp", "icmp").
type Observation struct {
	Seq      int               `json:"seq"`
	Proto    string            `json:"proto"`
	Listener string            `json:"listener,omitempty"`
	Method   string            `json:"method,omitempty"`
	Host     string            `json:"host,omitempty"`
	Path     string            `json:"path,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Source   string            `json:"source"`
	BodyLen  int               `json:"body_len"`
	BodySHA  string            `json:"body_sha256"`
	BodyB64  string            `json:"body_b64,omitempty"`
	Extra    map[string]any    `json:"extra,omitempty"`
}

// Obs is the fixture-local request log. It is deliberately not part of the
// state digest: observing is instrumentation, not externally visible state.
type Obs struct {
	mu   sync.Mutex
	list []Observation
	seq  int
}

// Add records an observation and returns its sequence number.
func (o *Obs) Add(ob Observation) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seq++
	ob.Seq = o.seq
	o.list = append(o.list, ob)
	return ob.Seq
}

// AddHTTP records an HTTP(S) request. The body is read fully and then
// restored on r.Body so handlers can consume it again.
func (o *Obs) AddHTTP(r *http.Request, listener string, extra map[string]any) (body []byte, err error) {
	if r.Body != nil {
		body, err = io.ReadAll(io.LimitReader(r.Body, maxBodyStored+1))
		if err != nil {
			return nil, err
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	h := map[string]string{}
	for k, v := range r.Header {
		h[k] = strings.Join(v, ",")
	}
	ob := Observation{
		Proto:    "https",
		Listener: listener,
		Method:   r.Method,
		Host:     r.Host,
		Path:     r.URL.RequestURI(),
		Headers:  h,
		Source:   r.RemoteAddr,
		BodyLen:  len(body),
		BodySHA:  DigestBytes(body),
		BodyB64:  base64.StdEncoding.EncodeToString(truncBody(body)),
		Extra:    extra,
	}
	if r.TLS == nil {
		ob.Proto = "http"
	}
	o.Add(ob)
	return body, nil
}

// AddBytes records an exact byte capture for a non-HTTP listener.
func (o *Obs) AddBytes(listener, proto, source string, data []byte, extra map[string]any) {
	o.Add(Observation{
		Proto:    proto,
		Listener: listener,
		Source:   source,
		BodyLen:  len(data),
		BodySHA:  DigestBytes(data),
		BodyB64:  base64.StdEncoding.EncodeToString(truncBody(data)),
		Extra:    extra,
	})
}

func truncBody(b []byte) []byte {
	if len(b) > maxBodyStored {
		return b[:maxBodyStored]
	}
	return b
}

// List returns a copy of all observations.
func (o *Obs) List() []Observation {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]Observation, len(o.list))
	copy(out, o.list)
	return out
}

// Len returns the number of observations.
func (o *Obs) Len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.list)
}

// Reset clears the log (called on POST /__reset).
func (o *Obs) Reset() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.list = nil
}

// DigestBytes returns the lowercase hex SHA-256 of b.
func DigestBytes(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// AdminHandler serves GET /__observed (JSON list of everything received),
// GET /__state (deterministic digest of externally visible state) and
// POST /__reset on every fixture. state must return the fixture's externally
// visible state snapshot; reset must restore seed state.
func AdminHandler(obs *Obs, state func() any, reset func()) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/__observed", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"observations": obs.List()})
	})
	mux.HandleFunc("/__state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"state": StateDigest(state())})
	})
	mux.HandleFunc("/__reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		reset()
		w.WriteHeader(204)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// WriteJSON is the exported form for fixture handlers.
func WriteJSON(w http.ResponseWriter, code int, v any) { writeJSON(w, code, v) }
