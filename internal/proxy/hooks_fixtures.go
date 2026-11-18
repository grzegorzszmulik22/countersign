// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package proxy

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
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
// Resolve-once (B2-04) means the resolver's answer IS the dialled address
// — fixture names cannot resolve to their real loopback sockets or the
// link-local/loopback range check would deny every fixture request. So the
// fixture resolver hands each name a stable synthetic IP in TEST-NET-2
// (198.51.100.0/24, publicly routable-looking) and the dialer maps the
// synthetic IP back to the registered loopback address. upstream.ip in
// records is the synthetic IP — the address actually checked and dialled.
var (
	fixtureMu      sync.Once
	fixtureResolve map[string]string // name -> literal dial addr (env)
	fixtureCAFile  string

	fixtureTabMu  sync.Mutex
	fixtureName   map[string]netip.Addr // name -> synthetic IP
	fixtureIPAddr map[string]string     // synthetic IP -> env dial addr
	fixtureKey    map[string]string     // synthetic IP -> fxres key
	fixtureNext   = netip.MustParseAddr("198.51.100.10")
)

func fixtureEnv() {
	fixtureResolve = map[string]string{}
	fixtureName = map[string]netip.Addr{}
	fixtureIPAddr = map[string]string{}
	fixtureKey = map[string]string{}
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

// syntheticIP allocates (or returns the existing) TEST-NET-2 stand-in for
// a resolved name.
func syntheticIP(tag string) netip.Addr {
	fixtureTabMu.Lock()
	defer fixtureTabMu.Unlock()
	if ip, ok := fixtureName[tag]; ok {
		return ip
	}
	ip := fixtureNext
	b := ip.As4()
	b[3]++
	fixtureNext = netip.AddrFrom4(b)
	fixtureName[tag] = ip
	return ip
}

func init() {
	resolveHost = func(ctx context.Context, host string) ([]netip.Addr, error) {
		fixtureMu.Do(fixtureEnv)
		h := strings.ToLower(strings.TrimSuffix(host, "."))
		if addr, ok := fixtureResolve[h]; ok {
			ip := syntheticIP("env:" + h)
			fixtureTabMu.Lock()
			fixtureIPAddr[ip.String()] = addr
			fixtureTabMu.Unlock()
			return []netip.Addr{ip}, nil
		}
		if key, ok := fxres.HostTable[h]; ok {
			ip := syntheticIP("fx:" + key)
			fixtureTabMu.Lock()
			fixtureKey[ip.String()] = key
			fixtureTabMu.Unlock()
			return []netip.Addr{ip}, nil
		}
		return nil, fmt.Errorf("fxres: %s is not a fixture host name", host)
	}
	defaultDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		fixtureMu.Do(fixtureEnv)
		host := addr
		if h, _, err := net.SplitHostPort(addr); err == nil {
			host = h
		}
		fixtureTabMu.Lock()
		envAddr, okEnv := fixtureIPAddr[host]
		key, okKey := fixtureKey[host]
		fixtureTabMu.Unlock()
		if okEnv {
			var d net.Dialer
			return d.DialContext(ctx, network, envAddr)
		}
		if okKey {
			return fxres.DialKey(ctx, network, key)
		}
		return nil, fmt.Errorf("fxres: %s is not a fixture address", addr)
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
