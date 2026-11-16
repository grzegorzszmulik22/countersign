// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/countersign/countersign/test/fixtures/echo"
	"github.com/countersign/countersign/test/fixtures/fxlib"
	"github.com/countersign/countersign/test/fixtures/fxres"
)

// testEnv is the shared M2 test environment: a temp dir holding the test
// root CA, a session table and a running broker.
type testEnv struct {
	t        *testing.T
	dir      string
	ca       *fxlib.CA
	records  string
	sessions string
	broker   *Server
	proxyURL *url.URL
	cancel   context.CancelFunc
}

var testSeq struct {
	mu sync.Mutex
	n  int
}

// newTestEnv builds a broker with the given session table entries and a
// dialer that resolves names via routes (name -> host:port, or "*" as a
// wildcard) before falling back to fxres.
func newTestEnv(t *testing.T, entries []SessionEntry, routes map[string]string) *testEnv {
	t.Helper()
	return newTestEnvRoots(t, entries, routes, nil)
}

// newTestEnvRoots additionally trusts extraCA's root for upstream
// verification (C2.2.3 needs expired/wrong-name leaves under a CA the
// broker otherwise trusts).
func newTestEnvRoots(t *testing.T, entries []SessionEntry, routes map[string]string, extraCA *miniCA) *testEnv {
	t.Helper()
	testSeq.mu.Lock()
	testSeq.n++
	testSeq.mu.Unlock()

	dir := t.TempDir()
	ca, err := fxlib.EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	fxres.RegisterCA(ca)
	roots := ca.Pool()
	if extraCA != nil {
		roots.AddCert(extraCA.cert)
	}
	records := filepath.Join(dir, "records")
	sessFile := filepath.Join(dir, "sessions.yaml")
	var b strings.Builder
	b.WriteString("sessions:\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "  - id: %s\n    token: %s\n    client_ip: %s\n    policy: %s\n",
			e.ID, e.Token, e.ClientIP, e.Policy)
	}
	if err := os.WriteFile(sessFile, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	srv, err := NewServer(Config{
		SessionsFile: sessFile,
		RecordsDir:   records,
		RootCAs:      roots,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host := addr
			if h, _, err := net.SplitHostPort(addr); err == nil {
				host = h
			}
			real, ok := routes[strings.ToLower(host)]
			if !ok {
				real, ok = routes["*"]
			}
			if ok {
				var d net.Dialer
				return d.DialContext(ctx, network, real)
			}
			return fxres.DialContext(ctx, network, addr)
		},
		Logf: func(format string, args ...any) { t.Logf("broker: "+format, args...) },
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	addr, err := srv.Serve(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	pu, _ := url.Parse("http://" + addr.String())
	e := &testEnv{t: t, dir: dir, ca: ca, records: records, sessions: sessFile,
		broker: srv, proxyURL: pu, cancel: cancel}
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
	})
	return e
}

// writePolicy writes a SessionPolicy YAML file into the env dir and returns
// its path (for the session table). Call before newTestEnv.
func writePolicy(t *testing.T, dir, name, grantsYAML string) string {
	t.Helper()
	doc := "apiVersion: countersign.dev/v1alpha1\n" +
		"kind: SessionPolicy\n" +
		"metadata: {name: " + name + "}\n" +
		"spec:\n" + grantsYAML
	p := filepath.Join(dir, name+".yaml")
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// sessionEntry makes a session-table row.
func sessionEntry(id, token, clientIP, policyPath string) SessionEntry {
	return SessionEntry{ID: id, Token: token, ClientIP: clientIP, Policy: policyPath}
}

// proxyClient returns an http.Client that tunnels through the broker. The
// session token rides in the proxy URL's userinfo exactly as the spec's
// clients send it (02 §3: Proxy-Authorization: Basic cs:<token>).
func (e *testEnv) proxyClient(t *testing.T, token string, pool *x509.CertPool, protos ...string) *http.Client {
	t.Helper()
	if pool == nil {
		pool = e.ca.Pool()
	}
	pu := *e.proxyURL
	if token != "" {
		pu.User = url.UserPassword("cs", token)
	}
	// ForceAttemptHTTP2 must follow the caller's ALPN intent: with it true
	// the transport offers "h2" alongside any custom NextProtos, which
	// would make an http/1.1-only client negotiate h2 anyway.
	h2ok := len(protos) == 0
	for _, p := range protos {
		if p == "h2" {
			h2ok = true
		}
	}
	tr := &http.Transport{
		Proxy:             http.ProxyURL(&pu),
		ForceAttemptHTTP2: h2ok,
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			NextProtos: protos,
		},
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

func basicAuth(user, pass string) string {
	return "Basic " + b64(user+":"+pass)
}

func b64(s string) string {
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := strings.Builder{}
	for i := 0; i < len(s); i += 3 {
		var b [3]byte
		n := copy(b[:], s[i:])
		v := uint(b[0])<<16 | uint(b[1])<<8 | uint(b[2])
		out.WriteByte(table[(v>>18)&63])
		out.WriteByte(table[(v>>12)&63])
		if n > 1 {
			out.WriteByte(table[(v>>6)&63])
		} else {
			out.WriteByte('=')
		}
		if n > 2 {
			out.WriteByte(table[v&63])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}

// sessionCAPool returns a pool trusting only the given session's CA.
func (e *testEnv) sessionCAPool(t *testing.T, sessionID string) *x509.CertPool {
	t.Helper()
	s := e.broker.Session(sessionID)
	if s == nil {
		t.Fatalf("no session %q", sessionID)
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.CACert())
	return pool
}

// combinedPool trusts the test root and the session CA.
func (e *testEnv) combinedPool(t *testing.T, sessionID string) *x509.CertPool {
	t.Helper()
	pool := e.ca.Pool()
	s := e.broker.Session(sessionID)
	if s == nil {
		t.Fatalf("no session %q", sessionID)
	}
	pool.AddCert(s.CACert())
	return pool
}

// startEcho runs the echo fixture under the test CA and registers its names.
func (e *testEnv) startEcho(t *testing.T) net.Addr {
	t.Helper()
	cert, err := e.ca.Issue([]string{"echo.example.com", "httpbin.org", "127.0.0.1"})
	if err != nil {
		t.Fatalf("issue echo cert: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := echo.New()
	addr, err := srv.Serve(ctx, "127.0.0.1:0", cert)
	if err != nil {
		cancel()
		t.Fatalf("echo serve: %v", err)
	}
	fxres.RegisterLocal("echo", addr.String())
	e.t.Cleanup(func() { cancel() })
	return addr
}

// startUpstream runs handler on a plain HTTP listener; returns its addr.
func startUpstream(t *testing.T, h http.Handler) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), func() { _ = srv.Close() }
}

// startTLSUpstream runs handler on a TLS listener whose leaf (under ca)
// covers the given SANs and whose ALPN is limited to protos (empty = both).
func startTLSUpstream(t *testing.T, ca *fxlib.CA, hosts []string, protos []string, h http.Handler) (addr string, closeFn func()) {
	t.Helper()
	cert, err := ca.Issue(hosts)
	if err != nil {
		t.Fatalf("issue upstream cert: %v", err)
	}
	if len(protos) == 0 {
		protos = []string{"h2", "http/1.1"}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   protos,
	})
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(tl) }()
	return ln.Addr().String(), func() { _ = srv.Close() }
}

// miniCA is a throwaway CA the harness uses when a test must control
// issuance (expired, wrong-name) — fxlib.CA deliberately hides its key.
type miniCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// newMiniCA creates a root CA.
func newMiniCA(t *testing.T, cn string) *miniCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &miniCA{cert: cert, key: key}
}

// Pool returns a pool trusting only this CA.
func (c *miniCA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// Issue mints a leaf under this CA with explicit validity — including
// expired or wrong-name variants (C2.2.3).
func (c *miniCA) Issue(t *testing.T, hosts []string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lt := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: hosts[0]},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			lt.IPAddresses = append(lt.IPAddresses, ip)
		} else {
			lt.DNSNames = append(lt.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, lt, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// mintUntrustedLeaf makes a leaf signed by its own throwaway CA (invalid).
func mintUntrustedLeaf(t *testing.T, hosts []string) tls.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caT := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "untrusted"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(der)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lt := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: hosts[0]},
		DNSNames: hosts, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	lder, err := x509.CreateCertificate(rand.Reader, lt, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{lder}, PrivateKey: key}
}

// startTLSUpstreamCert serves h on TLS with an explicit certificate.
func startTLSUpstreamCert(t *testing.T, cert tls.Certificate, protos []string, h http.Handler) (addr string, closeFn func()) {
	t.Helper()
	if len(protos) == 0 {
		protos = []string{"h2", "http/1.1"}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   protos,
	})
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(tl) }()
	return ln.Addr().String(), func() { _ = srv.Close() }
}

// rawProxyExchange sends raw request bytes to the proxy and returns the
// raw response head + body bytes.
func (e *testEnv) rawProxyExchange(t *testing.T, reqBytes string) (status int, head string, body string, conn net.Conn) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", e.proxyURL.Host, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(reqBytes)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}
	var headB strings.Builder
	headB.WriteString(res.Status + "\n")
	for k, v := range res.Header {
		headB.WriteString(k + ": " + strings.Join(v, ",") + "\n")
	}
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, headB.String(), string(b), conn
}

// readSessionRecords parses the session's JSONL record file.
func (e *testEnv) readSessionRecords(t *testing.T, sessionID string) []Record {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(e.records, sessionID+".jsonl"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []Record
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("record line decode: %v", err)
		}
		out = append(out, r)
	}
	return out
}

// recordsOfType returns records of one type with the body decoded.
func recordsOfType[T any](t *testing.T, recs []Record, rtype string) []T {
	t.Helper()
	var out []T
	for _, r := range recs {
		if r.Type != rtype {
			continue
		}
		var b T
		if err := json.Unmarshal(r.Body, &b); err != nil {
			t.Fatalf("record body decode %s: %v", rtype, err)
		}
		out = append(out, b)
	}
	return out
}

// brokerLogText returns broker.log's contents.
func (e *testEnv) brokerLogText(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(e.records, "broker.log"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
