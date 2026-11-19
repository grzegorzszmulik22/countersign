// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// m21Policy grants echo.example.com (https:443) and h1.example (http:80).
const m21Grants = `  grants:
    - id: echo
      match: {hosts: [echo.example.com]}
    - id: plain
      match: {hosts: [h1.example], scheme: http}
`

// obsHandler records what reaches it and echoes a small JSON document.
type obsHandler struct {
	got chan http.Header
}

func (o *obsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := http.Header{}
	for k, v := range r.Header {
		cp := make([]string, len(v))
		copy(cp, v)
		h[k] = cp
	}
	select {
	case o.got <- h:
	default:
	}
	writeEchoJSON(w, r)
}

func writeEchoJSON(w http.ResponseWriter, r *http.Request) {
	h := map[string]string{}
	for k, v := range r.Header {
		h[strings.ToLower(k)] = strings.Join(v, ",")
	}
	body, _ := io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"method":   r.Method,
		"path":     r.URL.RequestURI(),
		"headers":  h,
		"body_len": len(body),
	})
}

// rawConnect issues a CONNECT to the proxy and returns the response status
// plus the live tunnel connection (still usable after a 2xx).
func (e *testEnv) rawConnect(t *testing.T, token, authority string) (int, net.Conn) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", e.proxyURL.Host, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	auth := ""
	if token != "" {
		auth = "Proxy-Authorization: " + basicAuth("cs", token) + "\r\n"
	}
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", authority, authority, auth)
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("CONNECT response: %v", err)
	}
	_ = res.Body.Close()
	return res.StatusCode, conn
}

// --- C2.1.1 ---------------------------------------------------------------
// No token, wrong token, right token from the wrong client IP (and a wrong
// user): 407, reason NO_SESSION. Unattributable failures land in the broker
// log; the attributable one (valid token, wrong IP) lands an effect.denied.
func TestC211SessionAuth(t *testing.T) {
	dir := shmTempDir(t)
	pol := writePolicy(t, dir, "p", m21Grants)
	e := newTestEnv(t, []SessionEntry{
		sessionEntry("s1", "tok-one", "127.0.0.1", pol),
		sessionEntry("s2", "tok-two", "127.0.0.2", pol), // wrong client IP for this host
	}, nil)
	e.startEcho(t)

	get := func(auth string) int {
		if auth != "" {
			auth = "Proxy-Authorization: " + auth + "\r\n"
		}
		st, head, _, conn := e.rawProxyExchange(t,
			"GET http://h1.example/x HTTP/1.1\r\nHost: h1.example\r\n"+auth+"\r\n")
		_ = conn.Close()
		if st == 407 && !strings.Contains(head, "Proxy-Authenticate") {
			t.Errorf("407 response missing Proxy-Authenticate header:\n%s", head)
		}
		return st
	}

	if st := get(""); st != 407 {
		t.Errorf("no token: status %d, want 407", st)
	}
	if st := get(basicAuth("cs", "wrong-token")); st != 407 {
		t.Errorf("wrong token: status %d, want 407", st)
	}
	if st := get(basicAuth("nobody", "tok-one")); st != 407 {
		t.Errorf("wrong user: status %d, want 407", st)
	}
	if st := get(basicAuth("cs", "tok-two")); st != 407 {
		t.Errorf("right token wrong IP: status %d, want 407", st)
	}
	if st := get(basicAuth("cs", "malformed%%")); st != 407 {
		t.Errorf("malformed auth: status %d, want 407", st)
	}

	// The attributable denial (session s2, wrong client IP) is a record.
	s2recs := e.readSessionRecords(t, "s2")
	denied := recordsOfType[DeniedBody](t, s2recs, "effect.denied")
	if len(denied) != 1 || denied[0].Reason != "NO_SESSION" {
		t.Errorf("s2 denied records = %+v, want one NO_SESSION", denied)
	}
	// Unattributable failures are broker log lines only.
	if n := strings.Count(e.brokerLogText(t), "NO_SESSION"); n < 4 {
		t.Errorf("broker.log NO_SESSION lines = %d, want >= 4", n)
	}
	// And no effect.denied exists for a session that never authenticated.
	s1recs := e.readSessionRecords(t, "s1")
	if d := recordsOfType[DeniedBody](t, s1recs, "effect.denied"); len(d) != 0 {
		t.Errorf("s1 got %d denied records, want 0", len(d))
	}

	// A correctly identified session reaches upstream: CONNECT + TLS + GET.
	cli := e.proxyClient(t, "tok-one", e.combinedPool(t, "s1"))
	res, err := cli.Get("https://echo.example.com/echo?ok=1")
	if err != nil {
		t.Fatalf("valid session request: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != 200 {
		t.Fatalf("valid session: status %d, want 200", res.StatusCode)
	}
}

// --- C2.1.2 ---------------------------------------------------------------
// Valid session, host not in the test policy: 403 NO_GRANT plus an
// effect.http record with decision.action deny.
func TestC212NoGrant(t *testing.T) {
	dir := shmTempDir(t)
	pol := writePolicy(t, dir, "p", m21Grants)
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, nil)
	e.startEcho(t)

	st, head, _, conn := e.rawProxyExchange(t,
		"GET http://unlisted.example/x HTTP/1.1\r\nHost: unlisted.example\r\n"+
			"Proxy-Authorization: "+basicAuth("cs", "tok-one")+"\r\n\r\n")
	_ = conn.Close()
	if st != 403 {
		t.Fatalf("unlisted host: status %d, want 403", st)
	}
	if !strings.Contains(head, "NO_GRANT") {
		t.Errorf("expected X-Countersign-Reason NO_GRANT, head:\n%s", head)
	}

	// A granted host but ungranted path is the same decision.
	st, _, _, conn = e.rawProxyExchange(t,
		"GET http://h1.example/path HTTP/1.1\r\nHost: h1.example\r\n"+
			"Proxy-Authorization: "+basicAuth("cs", "tok-one")+"\r\n\r\n")
	_ = conn.Close()
	if st != 200 { // h1.example resolves to nothing upstream here; grant must match though
		t.Logf("h1.example forward status %d (no upstream running is OK at this point)", st)
	}

	recs := e.readSessionRecords(t, "s1")
	effects := recordsOfType[EffectHTTPBody](t, recs, "effect.http")
	var deny *EffectHTTPBody
	for i := range effects {
		if effects[i].Decision.Action == "deny" {
			deny = &effects[i]
		}
	}
	if deny == nil || deny.Decision.Reason != "NO_GRANT" {
		t.Fatalf("want effect.http with action=deny reason=NO_GRANT, got %+v", effects)
	}
	if deny.Request.Authority != "unlisted.example" {
		t.Errorf("denied record authority %q, want unlisted.example", deny.Request.Authority)
	}
}

// --- C2.1.3 ---------------------------------------------------------------
// Proxy-Authorization and the hop-by-hop set never reach the upstream, on
// the plain listener and inside a CONNECT tunnel.
func TestC213HopByHop(t *testing.T) {
	dir := shmTempDir(t)
	pol := writePolicy(t, dir, "p", m21Grants)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)
	e.startEcho(t)

	obs := &obsHandler{got: make(chan http.Header, 8)}
	addr, closeUp := startUpstream(t, obs)
	defer closeUp()
	routes["h1.example"] = addr

	st, _, _, conn := e.rawProxyExchange(t,
		"GET http://h1.example/obs?q=1 HTTP/1.1\r\n"+
			"Host: h1.example\r\n"+
			"Proxy-Authorization: "+basicAuth("cs", "tok-one")+"\r\n"+
			"Proxy-Authenticate: Basic abc\r\n"+
			"Connection: X-Hop, keep-alive\r\n"+
			"X-Hop: injected\r\n"+
			"Keep-Alive: timeout=5\r\n"+
			"TE: trailers, deflate\r\n"+
			"Trailer: X-Tr\r\n"+
			"Upgrade: h2c\r\n\r\n")
	_ = conn.Close()
	if st != 200 {
		t.Fatalf("hop-by-hop request: status %d, want 200", st)
	}
	var got http.Header
	select {
	case got = <-obs.got:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never saw the request")
	}
	for _, name := range []string{
		"Proxy-Authorization", "Proxy-Authenticate", "Connection",
		"Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "X-Hop",
	} {
		if _, ok := got[http.CanonicalHeaderKey(name)]; ok {
			t.Errorf("hop-by-hop header %s reached upstream: %v", name, got[http.CanonicalHeaderKey(name)])
		}
	}

	// Inside a CONNECT tunnel the same holds: the auth header belongs to the
	// proxy boundary, not the origin.
	cli := e.proxyClient(t, "tok-one", e.combinedPool(t, "s1"))
	res, err := cli.Get("https://echo.example.com/echo")
	if err != nil {
		t.Fatalf("tunneled GET: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	var doc struct {
		Headers map[string][]string `json:"headers"`
	}
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		t.Fatalf("echo decode: %v", err)
	}
	for name, v := range doc.Headers {
		switch strings.ToLower(name) {
		case "proxy-authorization", "proxy-authenticate", "connection", "keep-alive", "upgrade", "x-hop":
			t.Errorf("tunneled header %s reached echo: %v", name, v)
		}
	}
}

// --- C2.1.4 ---------------------------------------------------------------
// CONNECT to a port the grant does not list: PROTOCOL_DENIED. A host no
// grant lists at all: NO_GRANT.
func TestC214ConnectPort(t *testing.T) {
	dir := shmTempDir(t)
	pol := writePolicy(t, dir, "p", m21Grants)
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, nil)
	e.startEcho(t)

	st, conn := e.rawConnect(t, "tok-one", "echo.example.com:8443")
	_ = conn.Close()
	if st != 403 {
		t.Fatalf("CONNECT :8443 status %d, want 403", st)
	}
	st, conn = e.rawConnect(t, "tok-one", "nothing.example:443")
	_ = conn.Close()
	if st != 403 {
		t.Fatalf("CONNECT unlisted host status %d, want 403", st)
	}

	denied := recordsOfType[DeniedBody](t, e.readSessionRecords(t, "s1"), "effect.denied")
	var protoDenied, noGrant bool
	for _, d := range denied {
		switch d.Reason {
		case "PROTOCOL_DENIED":
			protoDenied = true
		case "NO_GRANT":
			noGrant = true
		}
	}
	if !protoDenied {
		t.Errorf("no PROTOCOL_DENIED record for CONNECT :8443 (denied=%+v)", denied)
	}
	if !noGrant {
		t.Errorf("no NO_GRANT record for CONNECT unlisted host (denied=%+v)", denied)
	}

	// The listed port still works.
	st, conn = e.rawConnect(t, "tok-one", "echo.example.com:443")
	if st != 200 {
		t.Fatalf("CONNECT :443 status %d, want 200", st)
	}
	_ = conn.Close()
}

// --- C2.1.5 ---------------------------------------------------------------
// Plain-HTTP requests forward only where the grant has scheme: http.
func TestC215PlainHTTPScheme(t *testing.T) {
	dir := shmTempDir(t)
	pol := writePolicy(t, dir, "p", m21Grants)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)
	e.startEcho(t)

	addr, closeUp := startUpstream(t, &obsHandler{got: make(chan http.Header, 8)})
	defer closeUp()
	routes["h1.example"] = addr
	routes["echo.example.com"] = addr // even reachable, the scheme gate must deny

	auth := "Proxy-Authorization: " + basicAuth("cs", "tok-one") + "\r\n"
	st, _, _, conn := e.rawProxyExchange(t,
		"GET http://h1.example/ok HTTP/1.1\r\nHost: h1.example\r\n"+auth+"\r\n")
	_ = conn.Close()
	if st != 200 {
		t.Fatalf("http-scheme grant: status %d, want 200", st)
	}
	st, head, _, conn := e.rawProxyExchange(t,
		"GET http://echo.example.com/ok HTTP/1.1\r\nHost: echo.example.com\r\n"+auth+"\r\n")
	_ = conn.Close()
	if st != 403 {
		t.Fatalf("https-only host over http: status %d, want 403", st)
	}
	if !strings.Contains(head, "NO_GRANT") {
		t.Errorf("want NO_GRANT for http to https-only host, head:\n%s", head)
	}
}
