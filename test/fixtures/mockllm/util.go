// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package mockllm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func readBody(r *http.Request) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	return b, err
}

// restoreBody puts an already-consumed body back so AddHTTP records it fully.
func restoreBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
}

// sseWriter writes deterministic SSE frames and flushes each.
type sseWriter struct {
	w  io.Writer
	fl http.Flusher
}

// sse sets streaming headers and returns the frame writer.
func sse(w http.ResponseWriter) *sseWriter {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	fl, _ := w.(http.Flusher)
	return &sseWriter{w: w, fl: fl}
}

// ev writes one "event: <name>\ndata: <json>\n\n" block and flushes.
func (s *sseWriter) ev(name string, data any) {
	b, _ := json.Marshal(data)
	_, _ = fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", name, b)
	if s.fl != nil {
		s.fl.Flush()
	}
}

// usage is a deterministic token count derived from the response content.
func usage(resp Resp) int {
	n := len(resp.Text)
	for _, c := range resp.Calls {
		n += len(c.Input)
	}
	return 1 + n/8
}

// chunks splits s into deterministic <=24-byte fragments for delta events.
func chunks(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for len(s) > 24 {
		out = append(out, s[:24])
		s = s[24:]
	}
	return append(out, s)
}
