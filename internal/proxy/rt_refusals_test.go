// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

// Red-team refusal battery. These cases are expected to be refused by the
// current broker; they are kept as executable evidence for TRIED.md and as
// regression tests for the controls that already hold.

package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestRTRefusalTunnelEdges: CONNECT authority edge cases and inner Host
// deviations must never reach the sink.
func TestRTRefusalTunnelEdges(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", `  grants:
    - id: allowed
      match: {hosts: [allowed.example.com]}
`)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)
	allowed := &rtHits{}
	aAddr, closeA := startTLSUpstream(t, e.ca, []string{"allowed.example.com"}, nil, allowed)
	defer closeA()
	routes["allowed.example.com"] = aAddr
	sink := &rtHits{}
	sAddr, closeS := startTLSUpstream(t, e.ca, []string{"sink.example.com", "allowed.example.com", "127.0.0.1"}, nil, sink)
	defer closeS()
	routes["sink.example.com"] = sAddr
	routes["*"] = sAddr // any name the broker is tricked into dialing lands on the sink

	pool := e.combinedPool(t, "s1")
	sinkBefore := sink.count()

	// CONNECT authorities that are not the granted name (or its exact
	// case/trailing-dot variants).
	for _, authority := range []string{
		"sink.example.com:443",
		"evil.allowed.example.com:443",
		"allowed.example.com.evil.net:443",
		"allowed.example.comm:443",
		"127.0.0.1:443",
		"0x7f000001:443",
		"2130706433:443",
		"127.1:443",
		"[::ffff:127.0.0.1]:443",
		"allowed.example.com:8443",
		"allowed.example.com:80",
		"allowed.example.com:0",
		"allowed.example.com:65535",
	} {
		st, conn := e.rawConnect(t, "tok-one", authority)
		_ = conn.Close()
		if st != http.StatusForbidden {
			t.Errorf("CONNECT %s: status %d, want 403", authority, st)
		}
	}
	if got := sink.count(); got != sinkBefore {
		t.Fatalf("sink was reached by CONNECT edge cases: %d new hits", got-sinkBefore)
	}

	// Inner Host/SNI deviations on an honest tunnel never reach the sink.
	cases := []string{
		"GET /x HTTP/1.1\r\nHost: sink.example.com\r\n\r\n",
		"GET /x HTTP/1.1\r\nHost: allowed.example.com:8443\r\n\r\n",
		"GET /x HTTP/1.1\r\nHost: evil.allowed.example.com\r\n\r\n",
		"GET https://sink.example.com/x HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n",
		"GET https://called.example/x HTTP/1.1\r\nHost: sink.example.com\r\n\r\n",
	}
	for _, req := range cases {
		tc, st := e.tunnelTLS(t, "tok-one", "allowed.example.com:443", &tls.Config{RootCAs: pool})
		if st != 200 {
			t.Fatalf("tunnel: %d", st)
		}
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
		code, head := innerRequest(t, tc, req)
		_ = tc.Close()
		if code != http.StatusForbidden || !strings.Contains(head, "SMUGGLING_SUSPECT") {
			t.Errorf("inner %q: status %d head %q, want 403 SMUGGLING_SUSPECT", strings.SplitN(req, "\r\n", 2)[0], code, head)
		}
	}
	if got := sink.count(); got != sinkBefore {
		t.Fatalf("sink was reached by inner Host deviations: %d new hits", got-sinkBefore)
	}

	// SNI != CONNECT authority aborts the handshake and reaches nothing.
	tc, st := e.tunnelTLS(t, "tok-one", "allowed.example.com:443", &tls.Config{InsecureSkipVerify: true, ServerName: "sink.example.com"})
	if st != 200 {
		t.Fatalf("tunnel: %d", st)
	}
	if err := tc.Handshake(); err == nil {
		_ = tc.Close()
		t.Fatalf("SNI sink.example.com was accepted on a CONNECT to allowed.example.com")
	}
	_ = tc.Close()
	if got := sink.count(); got != sinkBefore {
		t.Fatalf("sink was reached after an SNI mismatch: %d new hits", got-sinkBefore)
	}
}

// TestRTRefusalSessionCross checks token/source-address binding and that a
// Proxy-Authorization header inside a tunnel cannot switch sessions.
func TestRTRefusalSessionCross(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", `  grants:
    - id: allowed
      match: {hosts: [allowed.example.com]}
`)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{
		sessionEntry("s1", "tok-one", "127.0.0.1", pol),
		sessionEntry("s2", "tok-two", "127.0.0.2", pol),
	}, routes)
	up := &rtHits{}
	addr, closeUp := startTLSUpstream(t, e.ca, []string{"allowed.example.com"}, nil, up)
	defer closeUp()
	routes["allowed.example.com"] = addr
	pool := e.combinedPool(t, "s1")

	// s2's token from s1's address: 407, recorded as s2 NO_SESSION.
	before := up.count()
	st, conn := e.rawConnect(t, "tok-two", "allowed.example.com:443")
	_ = conn.Close()
	if st != http.StatusProxyAuthRequired {
		t.Errorf("s2 token from 127.0.0.1: status %d, want 407", st)
	}
	if got := up.count(); got != before {
		t.Errorf("s2 token from the wrong address reached upstream")
	}
	recs2 := e.readSessionRecords(t, "s2")
	found := false
	for _, d := range recordsOfType[DeniedBody](t, recs2, "effect.denied") {
		if d.Reason == "NO_SESSION" {
			found = true
		}
	}
	if !found {
		t.Errorf("no NO_SESSION effect.denied in s2 for token/source mismatch")
	}

	// s1's token from a socket bound to 127.0.0.2 (when the OS permits).
	pu := *e.proxyURL
	d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	c2, err := d.Dial("tcp", pu.Host)
	if err == nil {
		_, _ = fmt.Fprintf(c2, "GET http://allowed.example.com/x HTTP/1.1\r\nHost: allowed.example.com\r\nProxy-Authorization: %s\r\n\r\n",
			basicAuth("cs", "tok-one"))
		res, rerr := http.ReadResponse(bufio.NewReader(c2), nil)
		if rerr == nil {
			_ = res.Body.Close()
			if res.StatusCode != http.StatusProxyAuthRequired {
				t.Errorf("s1 token from 127.0.0.2: status %d, want 407", res.StatusCode)
			}
		}
		_ = c2.Close()
	} else {
		t.Logf("could not bind 127.0.0.2, skipping the reverse-address case: %v", err)
	}

	// A Proxy-Authorization header inside an s1 tunnel does not switch to s2.
	tc, st := e.tunnelTLS(t, "tok-one", "allowed.example.com:443", &tls.Config{RootCAs: pool})
	if st != 200 {
		t.Fatalf("tunnel: %d", st)
	}
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	code, _ := innerRequest(t, tc, "GET /x HTTP/1.1\r\nHost: allowed.example.com\r\nProxy-Authorization: "+basicAuth("cs", "tok-two")+"\r\n\r\n")
	_ = tc.Close()
	if code != 200 {
		t.Fatalf("inner request with a foreign proxy token: %d, want 200 (token is hop-by-hop, session is fixed)", code)
	}
	hits := up.snapshot()
	if len(hits) == 0 {
		t.Fatal("upstream never saw the inner request")
	}
	if v := hits[len(hits)-1].Headers.Get("Proxy-Authorization"); v != "" {
		t.Errorf("Proxy-Authorization reached the upstream: %q", v)
	}
	if d := recordsOfType[DeniedBody](t, e.readSessionRecords(t, "s2"), "effect.denied"); len(d) != 1 {
		t.Errorf("s2 records changed after an s1 tunnel request: %d denials", len(d))
	}
}

// TestRTRefusalPaths: path tricks and encoded traversal never reach the
// sink; allowed paths are forwarded to the granted host only.
func TestRTRefusalPaths(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", `  grants:
    - id: allowed
      match: {hosts: [allowed.example.com]}
`)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)
	allowed := &rtHits{}
	aAddr, closeA := startTLSUpstream(t, e.ca, []string{"allowed.example.com"}, nil, allowed)
	defer closeA()
	routes["allowed.example.com"] = aAddr
	sink := &rtHits{}
	sAddr, closeS := startTLSUpstream(t, e.ca, []string{"sink.example.com", "allowed.example.com"}, nil, sink)
	defer closeS()
	routes["sink.example.com"] = sAddr
	routes["*"] = sAddr
	pool := e.combinedPool(t, "s1")
	sinkBefore := sink.count()

	for _, target := range []string{
		"/..%2fsink.example.com/x",
		"/%2e%2e/sink.example.com/x",
		"/a/../sink.example.com/x",
		"/a/%2e%2e/sink.example.com/x",
		"/%2fsink.example.com/x",
		"/%5csink.example.com/x",
		"/%00sink.example.com/x",
	} {
		tc, st := e.tunnelTLS(t, "tok-one", "allowed.example.com:443", &tls.Config{RootCAs: pool})
		if st != 200 {
			t.Fatalf("%s: tunnel %d", target, st)
		}
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
		code, _ := innerRequest(t, tc, "GET "+target+" HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n")
		_ = tc.Close()
		if code != http.StatusForbidden {
			t.Errorf("path %q: status %d, want 403 SMUGGLING_SUSPECT", target, code)
		}
	}
	if got := sink.count(); got != sinkBefore {
		t.Fatalf("sink was reached by a path trick: %d new hits", got-sinkBefore)
	}
}

// TestRTRefusalRedirectAndUpgrade: a redirect to the sink is not followed by
// the broker, and an Upgrade request is stripped before the upstream.
func TestRTRefusalRedirectAndUpgrade(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", `  grants:
    - id: allowed
      match: {hosts: [allowed.example.com]}
`)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)
	ups := &rtHits{}
	var upgradeSeen atomic.Bool
	aAddr, closeA := startTLSUpstream(t, e.ca, []string{"allowed.example.com"}, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ups.add(r)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "https://sink.example.com/landed", http.StatusFound)
			return
		}
		if r.Header.Get("Upgrade") != "" {
			upgradeSeen.Store(true)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer closeA()
	routes["allowed.example.com"] = aAddr
	sink := &rtHits{}
	sAddr, closeS := startTLSUpstream(t, e.ca, []string{"sink.example.com"}, nil, sink)
	defer closeS()
	routes["sink.example.com"] = sAddr
	pool := e.combinedPool(t, "s1")

	cli := e.proxyClient(t, "tok-one", pool, "http/1.1")
	res, err := cli.Get("https://allowed.example.com/redirect")
	if err == nil {
		_ = res.Body.Close()
		t.Errorf("redirect client followed to the sink: status %d", res.StatusCode)
	}
	if sink.count() != 0 {
		t.Errorf("sink reached via redirect: %d hits", sink.count())
	}

	req, _ := http.NewRequest("GET", "https://allowed.example.com/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "AAAAAAAAAAAAAAAAAAAAAA==")
	res, err = cli.Do(req)
	if err != nil {
		t.Fatalf("upgrade request: %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if res.Header.Get("Upgrade") != "" {
		t.Errorf("client received Upgrade %q with no upgrade grant", res.Header.Get("Upgrade"))
	}
	if upgradeSeen.Load() {
		t.Errorf("Upgrade header reached the upstream without an upgrade grant")
	}
}
