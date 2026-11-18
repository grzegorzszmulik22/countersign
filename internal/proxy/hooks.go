// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/x509"
	"net"
	"net/netip"
)

// defaultDialContext is the upstream dialer when Config.DialContext is nil:
// the plain network dialer in release builds; the fixture resolver (fxres)
// under the fixtures build tag (02 §8, M0.3).
var defaultDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// resolveHost is the name resolver when Config.Resolve is nil: system DNS
// in release builds; the fixture table (with its synthetic public IPs,
// 02 §8) under the fixtures build tag.
var resolveHost = func(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a); ok {
			out = append(out, ip)
		}
	}
	return out, nil
}

// defaultRootCAs is the upstream trust store when Config.RootCAs is nil:
// the system pool; under the fixtures tag the test root is appended.
var defaultRootCAs = func() *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	return pool
}

// injectHook, when non-nil, is invoked at the moment a credential is
// injected into an outbound request — after the write-ahead record is
// durable, before the first upstream byte (02 §6). Fixture tests wrap it
// to assert that ordering and the 04 §2 injection invariant; it is nil in
// production.
var injectHook func(sessionID, grantID, credRef string)
