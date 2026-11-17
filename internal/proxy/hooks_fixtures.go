// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package proxy

import (
	"context"
	"crypto/x509"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/countersign/countersign/test/fixtures/fxres"
)

// Fixtures builds wire the broker-side resolver override and test root CA
// of 02 §8 into the default upstream path. Two environment variables steer
// the wiring so out-of-process broker binaries work the same way:
//
//	CS_FIXTURE_RESOLVE="echo.example.com=127.0.0.1:4433,name=addr,..."
//	CS_FIXTURE_CA=/path/to/ca.crt   (PEM appended to the system pool)
//
// With no CS_FIXTURE_RESOLVE set, fixture host names resolve through fxres
// (its RegisterLocal table), which is how in-process tests reach fixtures.
var (
	fixtureMu      sync.Once
	fixtureResolve map[string]string
	fixtureCAFile  string
)

func fixtureEnv() {
	fixtureResolve = map[string]string{}
	for _, kv := range strings.Split(os.Getenv("CS_FIXTURE_RESOLVE"), ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		name, addr, ok := strings.Cut(kv, "=")
		if ok {
			fixtureResolve[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(addr)
		}
	}
	fixtureCAFile = os.Getenv("CS_FIXTURE_CA")
}

func init() {
	defaultDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		fixtureMu.Do(fixtureEnv)
		host := addr
		if h, _, err := net.SplitHostPort(addr); err == nil {
			host = h
		}
		if resolved, ok := fixtureResolve[strings.ToLower(host)]; ok {
			var d net.Dialer
			return d.DialContext(ctx, network, resolved)
		}
		return fxres.DialContext(ctx, network, addr)
	}

	baseRoots := defaultRootCAs
	defaultRootCAs = func() *x509.CertPool {
		pool := baseRoots()
		fixtureMu.Do(fixtureEnv)
		if fixtureCAFile != "" {
			if pemBytes, err := os.ReadFile(fixtureCAFile); err == nil {
				pool.AppendCertsFromPEM(pemBytes)
			}
		}
		return pool
	}
}
