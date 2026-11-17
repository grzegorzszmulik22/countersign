// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/x509"
	"net"
)

// defaultDialContext is the upstream dialer when Config.DialContext is nil:
// the plain network dialer in release builds; the fixture resolver (fxres)
// under the fixtures build tag (02 §8, M0.3).
var defaultDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
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
