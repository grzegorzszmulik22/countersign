// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

// Package fxres is the resolver-override code of 02-architecture.md §8:
// fixture services are reached under realistic host names. In local mode a
// static table maps each name to a fixture key and RegisterLocal binds the key
// to a loopback address; Transport and ConnectProxy give clients (including
// real git/pip/npm through the CONNECT proxy) the same view.
package fxres

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/countersign/countersign/test/fixtures/fxlib"
)

// HostTable maps realistic host names to fixture keys (02 §8).
var HostTable = map[string]string{
	"github.com":             "fakehub",
	"api.github.com":         "fakehub",
	"pypi.org":               "fakereg",
	"files.pythonhosted.org": "fakereg",
	"registry.npmjs.org":     "fakereg",
	"api.slack.com":          "fakemsg",
	"api.anthropic.com":      "mockllm",
	"api.openai.com":         "mockllm",
	"mcp.example.com":        "mcpdemo",
	"httpbin.org":            "echo",
	"echo.example.com":       "echo",
	"evil.example.com":       "sink",
	"sink.attacker.test":     "sink",
}

// Ports is the well-known port each fixture serves under its real names in
// local mode. The broker-side override in cluster mode resolves to Service
// IPs instead (packaged on oci-free-a1, out of scope on agent-vpc).
var Ports = map[string]int{
	"fakehub": 443, "fakereg": 443, "fakemsg": 443,
	"mockllm": 443, "mcpdemo": 443, "echo": 443, "sink": 443,
}

var (
	mu      sync.RWMutex
	local   = map[string]string{} // fixture key -> host:port
	caStore *fxlib.CA
)

// RegisterLocal binds a fixture key to a loopback address (e.g. the address
// of a net.Listener the test opened). It must be called before clients
// resolve the fixture's host names.
func RegisterLocal(key, addr string) {
	mu.Lock()
	defer mu.Unlock()
	local[key] = addr
}

// RegisterCA records the test root CA so Transport can trust fixture leaves.
func RegisterCA(c *fxlib.CA) {
	mu.Lock()
	defer mu.Unlock()
	caStore = c
}

// resolve maps host[:port] to the registered local address for the host's
// fixture key. ok=false when the name is not in HostTable.
func resolve(hostport string) (string, bool) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
		port = "443"
	}
	key, ok := HostTable[strings.ToLower(host)]
	if !ok {
		return "", false
	}
	mu.RLock()
	addr := local[key]
	mu.RUnlock()
	if addr == "" {
		return "", false
	}
	// The port of the request is advisory; the fixture's registered address is
	// authoritative in local mode (all fixture names ride one listener).
	_ = port
	return addr, true
}

// DialContext dials the local address of the fixture that owns the requested
// host name. Unknown names are an error: fixtures never reach the real
// network (M0.3 denied list).
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if real, ok := resolve(addr); ok {
		var d net.Dialer
		return d.DialContext(ctx, network, real)
	}
	return nil, fmt.Errorf("fxres: %s is not a fixture host name", addr)
}

// DialKey dials the registered local address for a fixture key directly —
// the broker's fixtures-build dialer reaches it after resolve-once has
// already turned the host name into a synthetic IP.
func DialKey(ctx context.Context, network, key string) (net.Conn, error) {
	mu.RLock()
	addr := local[key]
	mu.RUnlock()
	if addr == "" {
		return nil, fmt.Errorf("fxres: no local address for fixture key %q", key)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// Transport returns an http.Transport that resolves fixture host names
// locally and trusts the test root CA. Unmapped names fail.
func Transport() *http.Transport {
	mu.RLock()
	pool := caStore.Pool()
	mu.RUnlock()
	return &http.Transport{
		DialContext:           DialContext,
		TLSClientConfig:       &tls.Config{RootCAs: pool},
		ForceAttemptHTTP2:     true,
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: 30 * time.Second,
	}
}

// Client returns an http.Client over Transport.
func Client() *http.Client { return &http.Client{Transport: Transport()} }

// ConnectProxy is an HTTP CONNECT forward proxy for real clients (git, pip,
// npm, curl): they ask it for host:443; it dials the owning fixture's local
// address and relays bytes. Plain (non-CONNECT) requests are refused — fixture
// traffic is TLS-only except for sink's HTTP listener, which tests reach
// directly.
func ConnectProxy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		target, ok := resolve(r.Host)
		if !ok {
			http.Error(w, "fxres: not a fixture host", http.StatusForbidden)
			return
		}
		up, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			_ = up.Close()
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		cli, buf, err := hj.Hijack()
		if err != nil {
			_ = up.Close()
			return
		}
		_, _ = fmt.Fprintf(buf, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buf.Flush()
		go func() {
			_, _ = io.Copy(up, cli)
			_ = up.Close()
		}()
		go func() {
			_, _ = io.Copy(cli, up)
			_ = cli.Close()
		}()
	})
}
