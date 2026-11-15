// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

// Package fxtest provides the shared fixture-test environment (M0.3): a run
// directory, the test root CA, an fxres CONNECT proxy for real clients
// (git/pip/npm/curl run as subprocesses against realistic host names), and
// helpers for the __state/__observed/__reset admin endpoints.
package fxtest

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/countersign/countersign/test/fixtures/fxlib"
	"github.com/countersign/countersign/test/fixtures/fxres"
)

// Env is one fixture-test environment.
type Env struct {
	T    *testing.T
	Dir  string
	CA   *fxlib.CA
	Ctx  context.Context
	stop context.CancelFunc

	proxyLn net.Listener
	proxy   *http.Server

	direct *http.Client // CA-trusting, no proxy — for loopback/admin URLs
	named  *http.Client // CA-trusting, via CONNECT proxy — for real host names
}

// NewEnv creates the run directory, CA and CONNECT proxy, and registers the
// CA with fxres.
func NewEnv(t *testing.T) *Env {
	t.Helper()
	dir := t.TempDir()
	ca, err := fxlib.EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Env{T: t, Dir: dir, CA: ca, Ctx: ctx, stop: cancel}
	fxres.RegisterCA(ca)

	e.proxyLn, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	e.proxy = &http.Server{Handler: fxres.ConnectProxy()}
	go func() { _ = e.proxy.Serve(e.proxyLn) }()
	t.Cleanup(func() {
		_ = e.proxy.Close()
		_ = e.proxyLn.Close()
		cancel()
	})

	pool := ca.Pool()
	e.direct = &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool},
		ForceAttemptHTTP2: true,
	}}
	pu, _ := url.Parse("http://" + e.proxyLn.Addr().String())
	e.named = &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(pu),
		TLSClientConfig:   &tls.Config{RootCAs: pool},
		ForceAttemptHTTP2: true,
	}}
	return e
}

// Issue mints a leaf for hosts (DNS names and/or IP literals).
func (e *Env) Issue(hosts ...string) tls.Certificate {
	e.T.Helper()
	cert, err := e.CA.Issue(hosts)
	if err != nil {
		e.T.Fatalf("Issue: %v", err)
	}
	return cert
}

// Register binds fixture key to the bound listener address so host names in
// fxres.HostTable resolve to it through the proxy (and fxres.DialContext).
func (e *Env) Register(key, addr string) {
	fxres.RegisterLocal(key, addr)
}

// ProxyAddr is the CONNECT proxy address for subprocess env vars.
func (e *Env) ProxyAddr() string { return e.proxyLn.Addr().String() }

// CAFile is the path of the CA certificate PEM for subprocess env vars.
func (e *Env) CAFile() string { return filepath.Join(e.Dir, "ca.crt") }

// Direct is an HTTP client for loopback URLs (admin endpoints, 127.0.0.1).
func (e *Env) Direct() *http.Client { return e.direct }

// Named is an HTTP client that reaches real host names through the proxy.
func (e *Env) Named() *http.Client { return e.named }

// toolsBin returns <repo>/.tools/bin, located relative to this source file
// so it resolves identically no matter where the test binary runs.
func toolsBin() string {
	_, src, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(src), "..", "..", "..", ".tools", "bin")
}

// SubEnv returns subprocess environment that routes HTTPS through the proxy
// and trusts the test CA (git/pip/npm/curl all honour these variables).
// .tools/bin leads PATH so python3/npm/node resolve to the pinned toolchain
// (06 §11) no matter what the ambient PATH holds.
func (e *Env) SubEnv() []string {
	proxy := "http://" + e.ProxyAddr()
	return []string{
		"HOME=" + e.Dir,
		"PATH=" + toolsBin() + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HTTPS_PROXY=" + proxy, "https_proxy=" + proxy,
		"HTTP_PROXY=" + proxy, "http_proxy=" + proxy,
		"GIT_SSL_CAINFO=" + e.CAFile(),
		"GIT_CONFIG_NOSYSTEM=1",
		"SSL_CERT_FILE=" + e.CAFile(),
		"PIP_CERT=" + e.CAFile(),
		"NODE_EXTRA_CA_CERTS=" + e.CAFile(),
		"NO_PROXY=", "no_proxy=",
	}
}

// Admin performs an admin request against a fixture's loopback base URL.
func (e *Env) Admin(base, method, path string, body io.Reader) *http.Response {
	e.T.Helper()
	req, err := http.NewRequestWithContext(e.Ctx, method, base+path, body)
	if err != nil {
		e.T.Fatalf("admin %s %s: %v", method, path, err)
	}
	res, err := e.direct.Do(req)
	if err != nil {
		e.T.Fatalf("admin %s %s: %v", method, path, err)
	}
	return res
}

// State returns the fixture's __state digest.
func (e *Env) State(base string) string {
	e.T.Helper()
	res := e.Admin(base, http.MethodGet, "/__state", nil)
	defer func() { _ = res.Body.Close() }()
	var v struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		e.T.Fatalf("__state decode: %v", err)
	}
	return v.State
}

// Observed returns the fixture's __observed entries.
func (e *Env) Observed(base string) []fxlib.Observation {
	e.T.Helper()
	res := e.Admin(base, http.MethodGet, "/__observed", nil)
	defer func() { _ = res.Body.Close() }()
	var v struct {
		Observations []fxlib.Observation `json:"observations"`
	}
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		e.T.Fatalf("__observed decode: %v", err)
	}
	return v.Observations
}

// Reset POSTs __reset.
func (e *Env) Reset(base string) {
	e.T.Helper()
	res := e.Admin(base, http.MethodPost, "/__reset", nil)
	_ = res.Body.Close()
	if res.StatusCode != 204 {
		e.T.Fatalf("__reset: status %d", res.StatusCode)
	}
}

// RequireStateStable asserts two __state reads are identical.
func (e *Env) RequireStateStable(base string) string {
	e.T.Helper()
	a := e.State(base)
	if b := e.State(base); a != b {
		e.T.Fatalf("__state changed across reads: %s then %s", a, b)
	}
	return a
}

// RequireStateChanged asserts the digest differs after a write.
func (e *Env) RequireStateChanged(base, before, what string) {
	e.T.Helper()
	if after := e.State(base); after == before {
		e.T.Fatalf("__state unchanged after %s", what)
	}
}
