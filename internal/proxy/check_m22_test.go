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
	dir := shmTempDir(t)
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
	dir := shmTempDir(t)
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
	dir := shmTempDir(t)
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
// SNI, Host and :authority must EQUAL the CONNECT authority (04 §2 step
// 1): identical after lowercasing, with one trailing root dot folding in.
// Every other deviation — a suffix, a prefix, a superstring, another
// name, a wrong port, a name sent for an IP-literal authority, or an
// absent SNI — is SMUGGLING_SUSPECT, is recorded, and never reaches the
// upstream.
const m224Grants = `  grants:
    - id: any
      match: {hosts: ["*"]}
    - id: ip-literal
      match: {hosts: ["127.0.0.1"]}
`

func TestC224SNICrossCheck(t *testing.T) {
	dir := shmTempDir(t)
	pol := writePolicy(t, dir, "p", m224Grants)
	hit := &countHandler{}
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)
	addr, closeUp := startTLSUpstream(t, e.ca, []string{"echo.example.com"}, nil, hit)
	defer closeUp()
	routes["echo.example.com"] = addr
	pool := e.combinedPool(t, "s1")
	const authority = "echo.example.com:443"
	accepts := 0 // requests that legitimately reach upstream

	// ---- SNI vs CONNECT authority -------------------------------------
	sniCases := []struct {
		name      string
		sni       string
		authority string
		accept    bool
	}{
		{"exact", "echo.example.com", authority, true},
		{"case-folded", "ECHO.EXAMPLE.COM", authority, true},
		{"trailing-dot", "echo.example.com.", authority, true},
		{"case-and-dot", "Echo.Example.Com.", authority, true},
		{"authority-as-suffix", "evil.echo.example.com", authority, false},
		{"authority-as-prefix", "echo.example.com.evil.net", authority, false},
		{"superstring", "echo.example.comm", authority, false},
		{"wildcard-name", "*.example.com", authority, false},
		{"other-name", "other.example", authority, false},
		{"parent-domain", "example.com", authority, false},
		{"sni-with-port", "echo.example.com:443", authority, false},
		{"empty-sni", "", authority, false},
		{"ip-authority-with-name", "evil.example", "127.0.0.1:443", false},
		{"ip-authority-empty-sni", "", "127.0.0.1:443", false},
	}
	wantSNIDenials := 0
	for _, c := range sniCases {
		ccfg := &tls.Config{ServerName: c.sni}
		if c.accept {
			ccfg.RootCAs = pool
		} else {
			// The broker's refusal is under test; keep the client from
			// rejecting the leaf itself first.
			ccfg.InsecureSkipVerify = true
		}
		st, conn := e.rawConnect(t, "tok-one", c.authority)
		if st != 200 {
			t.Fatalf("CONNECT %s: status %d", c.authority, st)
		}
		tc := tls.Client(conn, ccfg)
		err := tc.Handshake()
		if !c.accept {
			wantSNIDenials++
			_ = tc.Close()
			if err == nil {
				t.Errorf("%s: SNI %q for CONNECT %s accepted, want refused", c.name, c.sni, c.authority)
			}
			continue
		}
		if err != nil {
			_ = tc.Close()
			t.Errorf("%s: SNI %q for CONNECT %s refused an equal name: %v", c.name, c.sni, c.authority, err)
			continue
		}
		st, head := innerRequest(t, tc, "GET /x HTTP/1.1\r\nHost: echo.example.com\r\n\r\n")
		_ = tc.Close()
		if st != 200 {
			t.Errorf("%s: inner request status %d, want 200 (head: %s)", c.name, st, head)
			continue
		}
		accepts++
	}

	// ---- Host and :authority vs CONNECT authority ---------------------
	hostCases := []struct {
		name   string
		host   string // Host header / :authority value; "" = header omitted
		accept bool
	}{
		{"exact", "echo.example.com", true},
		{"explicit-port", "echo.example.com:443", true},
		{"case-folded", "ECHO.EXAMPLE.COM", true},
		{"trailing-dot", "echo.example.com.", true},
		{"dot-and-port", "echo.example.com.:443", true},
		{"authority-as-suffix", "evil.echo.example.com", false},
		{"authority-as-prefix", "echo.example.com.evil.net", false},
		{"superstring", "echo.example.comm", false},
		{"other-name", "other.example", false},
		{"wrong-port", "echo.example.com:444", false},
		{"empty", "", false},
	}
	h1Denies, h2Denies := 0, 0
	for _, c := range hostCases {
		tc, st := e.tunnelTLS(t, "tok-one", authority, &tls.Config{RootCAs: pool})
		if st != 200 || tc == nil {
			t.Fatalf("CONNECT %s: status %d", authority, st)
		}
		if err := tc.Handshake(); err != nil {
			_ = tc.Close()
			t.Fatalf("honest tunnel handshake: %v", err)
		}
		req := "GET /x HTTP/1.1\r\n\r\n" // Host header omitted entirely
		if c.host != "" {
			req = "GET /x HTTP/1.1\r\nHost: " + c.host + "\r\n\r\n"
		}
		st, head := innerRequest(t, tc, req)
		_ = tc.Close()
		if c.accept {
			if st != 200 {
				t.Errorf("h1 Host %q: status %d, want 200 (head: %s)", c.host, st, head)
			} else {
				accepts++
			}
			continue
		}
		if c.host == "" {
			// An absent Host is rejected by net/http before the broker's
			// own check (400); either way it must never be forwarded.
			if st == 200 {
				t.Errorf("h1 empty Host: request forwarded (status 200)")
			}
			continue
		}
		h1Denies++
		if st != 403 || !strings.Contains(head, "SMUGGLING_SUSPECT") {
			t.Errorf("h1 Host %q: status %d, want 403 SMUGGLING_SUSPECT (head: %s)", c.host, st, head)
		}
	}

	h2cli := e.proxyClient(t, "tok-one", pool, "h2")
	for _, c := range hostCases {
		if c.host == "" {
			continue // a conforming h2 client cannot send an empty :authority
		}
		req, err := http.NewRequest("GET", "https://echo.example.com/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = c.host // becomes :authority on h2, Host on h1
		res, err := h2cli.Do(req)
		if err != nil {
			t.Fatalf(":authority %q: %v", c.host, err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		if c.accept {
			if res.StatusCode != 200 {
				t.Errorf("h2 :authority %q: status %d, want 200", c.host, res.StatusCode)
			} else {
				accepts++
			}
			continue
		}
		h2Denies++
		if res.StatusCode != 403 || res.Header.Get("X-Countersign-Reason") != "SMUGGLING_SUSPECT" {
			t.Errorf("h2 :authority %q: status %d reason %q, want 403 SMUGGLING_SUSPECT",
				c.host, res.StatusCode, res.Header.Get("X-Countersign-Reason"))
		}
	}

	// Upstream saw exactly the accepted requests — every inequality was
	// stopped before forwarding.
	if got := int(hit.n.Load()); got != accepts {
		t.Errorf("upstream hit %d times, want %d (accepted requests only)", got, accepts)
	}

	// Denials are recorded: SNI refusals as effect.denied, Host refusals
	// as effect.http{deny, SMUGGLING_SUSPECT}. Host denials are durable
	// before the response; handshake refusals append as the tunnel dies,
	// so poll for the full count.
	wantDenyEffects := h1Denies + h2Denies
	deadline := time.Now().Add(30 * time.Second)
	for {
		recs := e.readSessionRecords(t, "s1")
		sniDenied := 0
		for _, d := range recordsOfType[DeniedBody](t, recs, "effect.denied") {
			if d.Reason == "SMUGGLING_SUSPECT" {
				sniDenied++
			}
		}
		hostDenied := 0
		for _, ef := range recordsOfType[EffectHTTPBody](t, recs, "effect.http") {
			if ef.Decision.Action == "deny" && ef.Decision.Reason == "SMUGGLING_SUSPECT" {
				hostDenied++
			}
		}
		if sniDenied >= wantSNIDenials && hostDenied >= wantDenyEffects {
			if sniDenied != wantSNIDenials || hostDenied != wantDenyEffects {
				t.Fatalf("denial records: effect.denied=%d (want %d), effect.http deny=%d (want %d)",
					sniDenied, wantSNIDenials, hostDenied, wantDenyEffects)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("denial records: effect.denied=%d (want %d), effect.http deny=%d (want %d)",
				sniDenied, wantSNIDenials, hostDenied, wantDenyEffects)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// A denial whose record append fails must surface as a broker error:
	// a denial that is not recorded breaks the evidence record.
	dir2 := shmTempDir(t)
	inner, err := NewFileRecordSink(filepath.Join(dir2, "records"), "broker/test")
	if err != nil {
		t.Fatal(err)
	}
	fs := &failableSink{inner: inner, rejected: make(chan string, 16)}
	e2 := newTestEnvFull(t, dir2,
		[]SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, map[string]string{}, nil, fs)
	fs.fail.Store(true)
	st2, conn2 := e2.rawConnect(t, "tok-one", authority)
	if st2 != 200 {
		t.Fatalf("CONNECT %s: status %d", authority, st2)
	}
	tc2 := tls.Client(conn2, &tls.Config{ServerName: "evil.example", InsecureSkipVerify: true})
	_ = tc2.Handshake()
	_ = tc2.Close()
	// The client handshake returns when the alert leaves the broker, which
	// is before the denial append is attempted. Hold fail until the sink
	// has rejected the effect.denied append itself — otherwise a slow
	// intercept goroutine could append after fail clears and the denial
	// would record, leaving nothing to surface.
	deadline = time.Now().Add(10 * time.Second)
	for {
		select {
		case rt := <-fs.rejected:
			if rt == "effect.denied" {
				goto denied
			}
		case <-time.After(time.Until(deadline)):
			t.Fatal("denial append never reached the record sink")
		}
	}
denied:
	fs.fail.Store(false)
	for !time.Now().After(deadline) {
		if strings.Contains(e2.brokerLogText(t), "record append failed") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("failed denial record append left no broker error")
}

// --- C2.2.5 ---------------------------------------------------------------
// The CA private key reaches neither the client, the records dir, nor the
// logs. Its only serialization call site is the session-key store.
func TestC225KeyContainment(t *testing.T) {
	dir := shmTempDir(t)
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
	dir := shmTempDir(t)
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
	dir := shmTempDir(t)
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
