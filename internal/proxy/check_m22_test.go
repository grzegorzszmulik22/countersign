// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// m22Grants grants https on every host (M2.2's checks pick their own
// upstreams; the grant gates only the CONNECT).
const m22Grants = `  grants:
    - id: any
      match: {hosts: ["*"]}
`

// countHandler counts upstream hits (nothing must reach it on TLS failure).
type countHandler struct{ n atomic.Int64 }

func (h *countHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.n.Add(1)
	writeEchoJSON(w, r)
}

// tunnelTLS opens CONNECT authority on the proxy under token and TLSes
// over the tunnel with the given client config (ServerName set to the
// authority's host when empty). Returns the established tls.Conn.
func (e *testEnv) tunnelTLS(t *testing.T, token, authority string, ccfg *tls.Config) (*tls.Conn, int) {
	t.Helper()
	st, conn := e.rawConnect(t, token, authority)
	if st != 200 {
		_ = conn.Close()
		return nil, st
	}
	host, _, _ := net.SplitHostPort(authority)
	if ccfg == nil {
		ccfg = &tls.Config{}
	}
	if ccfg.ServerName == "" {
		ccfg.ServerName = host
	}
	return tls.Client(conn, ccfg), st
}

// innerRequest sends one HTTP/1.1 request inside an established tunnel and
// returns the raw status and head.
func innerRequest(t *testing.T, tc *tls.Conn, req string) (int, string) {
	t.Helper()
	if _, err := tc.Write([]byte(req)); err != nil {
		t.Fatalf("inner write: %v", err)
	}
	br := bufio.NewReader(tc)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("inner response: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	var head strings.Builder
	head.WriteString(res.Status + "\n")
	for k, v := range res.Header {
		head.WriteString(k + ": " + strings.Join(v, ",") + "\n")
	}
	return res.StatusCode, head.String()
}

// --- C2.2.1 ---------------------------------------------------------------
// A client trusting ONLY the session CA completes requests over HTTP/1.1
// and HTTP/2.
func TestC221SessionCATrust(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", m22Grants)
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, nil)
	e.startEcho(t)

	pool := e.sessionCAPool(t, "s1")
	for _, proto := range []string{"http/1.1", "h2"} {
		cli := e.proxyClient(t, "tok-one", pool, proto)
		res, err := cli.Get("https://echo.example.com/echo?p=" + proto)
		if err != nil {
			t.Fatalf("%s request: %v", proto, err)
		}
		var doc map[string]any
		if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
			t.Fatalf("%s decode: %v", proto, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("%s: status %d", proto, res.StatusCode)
		}
		wantProto := "HTTP/1.1"
		if proto == "h2" {
			wantProto = "HTTP/2.0"
		}
		if res.Proto != wantProto {
			t.Errorf("client proto %s, want %s", res.Proto, wantProto)
		}
	}
}

// --- C2.2.2 ---------------------------------------------------------------
// Session A's CA does not validate a leaf minted under session B's CA —
// CAs are per-session.
func TestC222PerSessionCA(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", m22Grants)
	e := newTestEnv(t, []SessionEntry{
		sessionEntry("sa", "tok-a", "127.0.0.1", pol),
		sessionEntry("sb", "tok-b", "127.0.0.1", pol),
	}, nil)
	e.startEcho(t)

	if e.broker.Session("sa").CACert().Equal(e.broker.Session("sb").CACert()) {
		t.Fatal("sessions share one CA cert — leaves are not per-session")
	}

	// Client trusts only A's CA but tunnels under B's token: B's leaf must
	// fail verification.
	cli := e.proxyClient(t, "tok-b", e.sessionCAPool(t, "sa"))
	_, err := cli.Get("https://echo.example.com/echo")
	if err == nil {
		t.Fatal("session-B leaf accepted under session-A trust")
	}
	if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "tls:") {
		t.Fatalf("expected TLS verify error, got %v", err)
	}

	// Same tunnel under B's own CA works.
	cli = e.proxyClient(t, "tok-b", e.sessionCAPool(t, "sb"))
	res, err := cli.Get("https://echo.example.com/echo")
	if err != nil {
		t.Fatalf("session-B request: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
}

// --- C2.2.3 ---------------------------------------------------------------
// Invalid, expired or wrong-name upstream certificate: 502 UPSTREAM_TLS
// and nothing reaches the upstream.
func TestC223UpstreamVerify(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", m22Grants)

	// trusted-miniCA: the broker's pool trusts it, so expired/wrong-name
	// leaves fail on their own fault, not the chain.
	trusted := newMiniCA(t, "trusted-test-root")
	routes := map[string]string{}
	e := newTestEnvRoots(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes, trusted)

	now := time.Now()
	hit := &countHandler{}
	cases := []struct {
		name string
		cert tls.Certificate
	}{
		{"untrusted", mintUntrustedLeaf(t, []string{"bad.example"})},
		{"expired", trusted.Issue(t, []string{"expired.example"}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))},
		{"wrongname", trusted.Issue(t, []string{"other.example"}, now.Add(-time.Hour), now.Add(time.Hour))},
	}
	hosts := []string{"bad.example", "expired.example", "wrongname.example"}
	for i, c := range cases {
		addr, closeUp := startTLSUpstreamCert(t, c.cert, nil, hit)
		defer closeUp()
		routes[hosts[i]] = addr
	}

	cli := e.proxyClient(t, "tok-one", e.combinedPool(t, "s1"))
	for _, h := range hosts {
		res, err := cli.Get("https://" + h + "/x")
		if err != nil {
			t.Fatalf("%s: %v", h, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != 502 {
			t.Errorf("%s: status %d, want 502", h, res.StatusCode)
		}
		if res.Header.Get("X-Countersign-Reason") != "UPSTREAM_TLS" {
			t.Errorf("%s: reason %q, want UPSTREAM_TLS", h, res.Header.Get("X-Countersign-Reason"))
		}
	}
	if hit.n.Load() != 0 {
		t.Errorf("upstream was hit %d times despite TLS failure", hit.n.Load())
	}
	results := recordsOfType[ResultBody](t, e.readSessionRecords(t, "s1"), "effect.http.result")
	var tlsErr int
	for _, r := range results {
		if r.Error == "UPSTREAM_TLS" {
			tlsErr++
		}
	}
	if tlsErr != len(hosts) {
		t.Errorf("UPSTREAM_TLS results = %d, want %d", tlsErr, len(hosts))
	}
}

// --- C2.2.4 ---------------------------------------------------------------
// SNI ≠ CONNECT authority, or Host ≠ authority → SMUGGLING_SUSPECT.
func TestC224SNICrossCheck(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", m22Grants)
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, nil)
	e.startEcho(t)
	pool := e.combinedPool(t, "s1")

	// SNI ≠ CONNECT authority: the handshake is refused and recorded.
	tc, _ := e.tunnelTLS(t, "tok-one", "echo.example.com:443",
		&tls.Config{RootCAs: pool, ServerName: "different.example"})
	err := tc.Handshake()
	_ = tc.Close()
	if err == nil {
		t.Fatal("handshake with mismatched SNI succeeded")
	}

	// Host ≠ authority inside an honest tunnel.
	tc, _ = e.tunnelTLS(t, "tok-one", "echo.example.com:443", &tls.Config{RootCAs: pool})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tunnel handshake: %v", err)
	}
	st, head := innerRequest(t, tc, "GET /x HTTP/1.1\r\nHost: other.example\r\n\r\n")
	_ = tc.Close()
	if st != 403 {
		t.Fatalf("Host-mismatch status %d, want 403", st)
	}
	if !strings.Contains(head, "SMUGGLING_SUSPECT") {
		t.Errorf("want SMUGGLING_SUSPECT, head:\n%s", head)
	}

	denied := recordsOfType[DeniedBody](t, e.readSessionRecords(t, "s1"), "effect.denied")
	var sniDenied bool
	for _, d := range denied {
		if d.Reason == "SMUGGLING_SUSPECT" {
			sniDenied = true
		}
	}
	if !sniDenied {
		t.Errorf("no SMUGGLING_SUSPECT effect.denied for SNI mismatch: %+v", denied)
	}
	effects := recordsOfType[EffectHTTPBody](t, e.readSessionRecords(t, "s1"), "effect.http")
	var hostDenied bool
	for _, ef := range effects {
		if ef.Decision.Action == "deny" && ef.Decision.Reason == "SMUGGLING_SUSPECT" {
			hostDenied = true
		}
	}
	if !hostDenied {
		t.Errorf("no SMUGGLING_SUSPECT effect.http for Host mismatch")
	}
}

// --- C2.2.5 ---------------------------------------------------------------
// The CA private key reaches neither the client, the records dir, nor the
// logs. Its only serialization call site is the session-key store.
func TestC225KeyContainment(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", m22Grants)
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, nil)
	e.startEcho(t)

	cli := e.proxyClient(t, "tok-one", e.combinedPool(t, "s1"))
	res, err := cli.Get("https://echo.example.com/echo")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()

	// Everything the client saw: headers, body and the presented certs.
	var clientBytes []byte
	for k, v := range res.Header {
		clientBytes = append(clientBytes, []byte(k+strings.Join(v, ","))...)
	}
	clientBytes = append(clientBytes, body...)
	if res.TLS != nil {
		for _, c := range res.TLS.PeerCertificates {
			clientBytes = append(clientBytes, c.Raw...)
		}
	}
	// Everything the broker wrote: the records dir (session logs, broker.log).
	var ledgerBytes []byte
	err = filepath.Walk(e.records, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		ledgerBytes = append(ledgerBytes, b...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	keyDER := sessionKeyDER(t, e.broker, "s1")
	pemDER := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for _, what := range []struct {
		name  string
		bytes []byte
	}{
		{"key DER", keyDER},
		{"key PEM", pemDER},
		{"key hex", []byte(hex.EncodeToString(keyDER))},
		{"key b64", []byte(base64.StdEncoding.EncodeToString(keyDER))},
		{"PEM marker", []byte("PRIVATE KEY")},
	} {
		if bytes.Contains(clientBytes, what.bytes) {
			t.Errorf("client-side data contains %s", what.name)
		}
		if bytes.Contains(ledgerBytes, what.bytes) {
			t.Errorf("records dir contains %s", what.name)
		}
	}
}

// sessionKeyDER returns the session CA key's DER via the key store — the
// only sanctioned serialization path.
func sessionKeyDER(t *testing.T, srv *Server, sessionID string) []byte {
	t.Helper()
	if ks, ok := srv.keys.(*MemoryKeyStore); ok {
		if key, found := ks.Get(sessionID); found {
			der, err := marshalSessionKey(key)
			if err != nil {
				t.Fatal(err)
			}
			return der
		}
	}
	t.Fatal("session key not in store")
	return nil
}

// --- C2.2.6 ---------------------------------------------------------------
// Client HTTP/2 with upstream HTTP/1.1, and the reverse.
func TestC226ALPNIndependent(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", m22Grants)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)

	h1addr, closeH1 := startTLSUpstream(t, e.ca, []string{"h1up.example"}, []string{"http/1.1"}, http.HandlerFunc(writeEchoJSON))
	defer closeH1()
	routes["h1up.example"] = h1addr
	h2addr, closeH2 := startTLSUpstream(t, e.ca, []string{"h2up.example"}, []string{"h2"}, http.HandlerFunc(writeEchoJSON))
	defer closeH2()
	routes["h2up.example"] = h2addr

	pool := e.combinedPool(t, "s1")

	// h2 client -> h1 upstream
	cli := e.proxyClient(t, "tok-one", pool, "h2")
	res, err := cli.Get("https://h1up.example/x")
	if err != nil {
		t.Fatalf("h2->h1: %v", err)
	}
	_ = res.Body.Close()
	if res.Proto != "HTTP/2.0" {
		t.Errorf("client side %s, want HTTP/2.0", res.Proto)
	}
	// h1 client -> h2 upstream
	cli = e.proxyClient(t, "tok-one", pool, "http/1.1")
	res, err = cli.Get("https://h2up.example/x")
	if err != nil {
		t.Fatalf("h1->h2: %v", err)
	}
	_ = res.Body.Close()
	if res.Proto != "HTTP/1.1" {
		t.Errorf("client side %s, want HTTP/1.1", res.Proto)
	}

	// Result records are appended server-side after the handler returns;
	// wait for both before asserting.
	var sawH1, sawH2 bool
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sawH1, sawH2 = false, false
		for _, r := range recordsOfType[ResultBody](t, e.readSessionRecords(t, "s1"), "effect.http.result") {
			if r.Upstream != nil {
				switch r.Upstream.ALPN {
				case "http/1.1":
					sawH1 = true
				case "h2":
					sawH2 = true
				}
			}
		}
		if sawH1 && sawH2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !sawH1 || !sawH2 {
		t.Errorf("upstream ALPNs seen h1=%v h2=%v", sawH1, sawH2)
	}
}

// --- C2.2.7 ---------------------------------------------------------------
// 1,000 distinct host names in one session all mint leaves; the per-session
// cache stays bounded at 4,096.
func TestC227LeafMinting(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", m22Grants)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)
	addr := e.startEcho(t)
	routes["*"] = addr.String() // wildcard route for the thousand names

	pool := e.sessionCAPool(t, "s1")
	const N = 1000
	for i := 0; i < N; i++ {
		host := fmt.Sprintf("h%04d.example", i)
		tc, st := e.tunnelTLS(t, "tok-one", host+":443", &tls.Config{RootCAs: pool})
		if st != 200 || tc == nil {
			t.Fatalf("CONNECT %s: status %d", host, st)
		}
		if err := tc.Handshake(); err != nil {
			t.Fatalf("handshake %s: %v", host, err)
		}
		state := tc.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			t.Fatalf("%s: no peer cert", host)
		}
		leaf := state.PeerCertificates[0]
		if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != host {
			t.Errorf("%s: SAN %v", host, leaf.DNSNames)
		}
		if d := leaf.NotAfter.Sub(leaf.NotBefore); d < 23*time.Hour || d > 25*time.Hour {
			t.Errorf("%s: validity %v, want ~24h", host, d)
		}
		_ = tc.Close()
	}
	sess := e.broker.Session("s1")
	if got := sess.LeafCacheLen(); got != N {
		t.Errorf("leaf cache %d, want %d", got, N)
	}

	// Bounded LRU: pushing past 4,096 evicts the oldest.
	for i := N; i < leafCacheMax+10; i++ {
		if _, err := sess.mintLeaf(fmt.Sprintf("lru%04d.example", i)); err != nil {
			t.Fatalf("mintLeaf %d: %v", i, err)
		}
	}
	if got := sess.LeafCacheLen(); got != leafCacheMax {
		t.Errorf("leaf cache %d, want bounded %d", got, leafCacheMax)
	}
}
