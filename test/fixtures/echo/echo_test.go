// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package echo

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/countersign/countersign/test/fixtures/fxlib"
	"github.com/countersign/countersign/test/fixtures/fxtest"
)

// startEcho runs the fixture as a local TLS server and returns its base URL.
func startEcho(t *testing.T, env *fxtest.Env) string {
	t.Helper()
	addr, err := New().Serve(env.Ctx, "127.0.0.1:0",
		env.Issue("echo.example.com", "httpbin.org", "127.0.0.1"))
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	env.Register("echo", addr.String())
	return "https://" + addr.String()
}

func TestC031Echo(t *testing.T) {
	env := fxtest.NewEnv(t)
	base := startEcho(t, env)

	// Echo of method/path/headers/body digest over HTTP/1.1.
	h11 := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: env.CA.Pool(), NextProtos: []string{"http/1.1"}},
		ForceAttemptHTTP2: false,
	}}
	req, _ := http.NewRequestWithContext(env.Ctx, http.MethodPost, base+"/some/path?q=1",
		strings.NewReader("hello-body"))
	req.Header.Set("X-Test-Marker", "marker-1")
	res, err := h11.Do(req)
	if err != nil {
		t.Fatalf("echo request: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	var echo map[string]any
	decodeJSON(t, res, &echo)
	if echo["method"] != "POST" || echo["path"] != "/some/path?q=1" {
		t.Fatalf("bad echo: %v", echo)
	}
	if echo["body_sha256"] != fxlib.DigestBytes([]byte("hello-body")) {
		t.Fatalf("bad body digest: %v", echo["body_sha256"])
	}
	if hdrs, ok := echo["headers"].(map[string]any); !ok || fmt.Sprint(hdrs["X-Test-Marker"]) != "[marker-1]" {
		t.Fatalf("headers not echoed: %v", hdrs)
	}
	if echo["proto"] != "HTTP/1.1" {
		t.Fatalf("expected HTTP/1.1 echo, got %v", echo["proto"])
	}

	// HTTP/2: the environment's default direct transport offers h2.
	res2, err := env.Direct().Get(base + "/h2check")
	if err != nil {
		t.Fatalf("h2 request: %v", err)
	}
	var echo2 map[string]any
	decodeJSON(t, res2, &echo2)
	_ = res2.Body.Close()
	if echo2["proto"] != "HTTP/2.0" {
		t.Fatalf("expected HTTP/2.0 echo, got %v", echo2["proto"])
	}

	// /status/<code>
	for _, code := range []int{200, 418, 503} {
		r, err := env.Direct().Get(fmt.Sprintf("%s/status/%d", base, code))
		if err != nil {
			t.Fatalf("status %d: %v", code, err)
		}
		_ = r.Body.Close()
		if r.StatusCode != code {
			t.Fatalf("/status/%d returned %d", code, r.StatusCode)
		}
	}

	// /bytes?n=
	r, err := env.Direct().Get(base + "/bytes?n=4097")
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	got, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil || len(got) != 4097 {
		t.Fatalf("/bytes: len=%d err=%v", len(got), err)
	}
	for i := 0; i < len(got); i += 1024 {
		if got[i] != byte(i%8192) {
			t.Fatalf("/bytes: unexpected byte at %d", i)
		}
	}

	// /sse?n=&interval_ms=
	r, err = env.Direct().Get(base + "/sse?n=3&interval_ms=1")
	if err != nil {
		t.Fatalf("sse: %v", err)
	}
	sseBody, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if c := bytes.Count(sseBody, []byte("data: ")); c != 3 {
		t.Fatalf("/sse: got %d events, want 3", c)
	}

	// /ws echo.
	wsRoundTrip(t, env, base)

	// __observed contains the requests.
	obs := env.Observed(base)
	var sawEcho, sawStatus bool
	for _, o := range obs {
		if strings.HasPrefix(o.Path, "/some/path") {
			sawEcho = true
		}
		if strings.HasPrefix(o.Path, "/status/418") {
			sawStatus = true
		}
	}
	if !sawEcho || !sawStatus {
		t.Fatalf("__observed missing entries (sawEcho=%v sawStatus=%v)", sawEcho, sawStatus)
	}
}

func TestC035StateEcho(t *testing.T) {
	env := fxtest.NewEnv(t)
	base := startEcho(t, env)

	before := env.RequireStateStable(base)
	// Read-only requests must not change the digest.
	for _, p := range []string{"/", "/bytes?n=1", "/status/200", "/sse?n=1"} {
		r, err := env.Direct().Get(base + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}
	if got := env.State(base); got != before {
		t.Fatalf("__state changed after read-only requests")
	}
	// Every supported write kind changes it: POST.
	req, _ := http.NewRequestWithContext(env.Ctx, http.MethodPost, base+"/w", strings.NewReader("x"))
	res, err := env.Direct().Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = res.Body.Close()
	env.RequireStateChanged(base, before, "POST /w")
	// __reset restores the seed digest.
	env.Reset(base)
	if got := env.State(base); got != before {
		t.Fatalf("__reset did not restore state")
	}
}

// --- helpers -----------------------------------------------------------------

func decodeJSON(t *testing.T, res *http.Response, v any) {
	t.Helper()
	if err := json.NewDecoder(res.Body).Decode(v); err != nil {
		t.Fatalf("decode %s: %v", res.Request.URL, err)
	}
}

// wsRoundTrip hand-shakes and echoes one text frame.
func wsRoundTrip(t *testing.T, env *fxtest.Env, base string) {
	t.Helper()
	addr := strings.TrimPrefix(base, "https://")
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: env.CA.Pool(), NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	_, _ = fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", addr, key)
	rw := bufio.NewReader(conn)
	status, err := rw.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("ws handshake: %q err=%v", status, err)
	}
	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			t.Fatalf("ws headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	// Send a masked text frame "hi".
	payload := []byte("hi")
	mask := [4]byte{0xAA, 0xBB, 0xCC, 0xDD}
	frame := []byte{0x81, 0x80 | byte(len(payload))}
	frame = append(frame, mask[:]...)
	for i, b := range payload {
		frame = append(frame, b^mask[i%4])
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("ws write: %v", err)
	}
	// Read echoed frame.
	var hdr [2]byte
	if _, err := io.ReadFull(rw, hdr[:]); err != nil {
		t.Fatalf("ws read hdr: %v", err)
	}
	if hdr[0]&0x0F != 0x1 {
		t.Fatalf("ws echo opcode %x, want text", hdr[0])
	}
	l := int(hdr[1] & 0x7F)
	got := make([]byte, l)
	if _, err := io.ReadFull(rw, got); err != nil {
		t.Fatalf("ws read payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("ws echo %q, want %q", got, payload)
	}
	// Close politely.
	_, _ = conn.Write([]byte{0x88, 0x80, mask[0], mask[1], mask[2], mask[3]})
	var ch [2]byte
	_, _ = io.ReadFull(rw, ch[:])
	if ch[0]&0x0F != 0x8 {
		t.Fatalf("ws close opcode %x", ch[0])
	}
}
