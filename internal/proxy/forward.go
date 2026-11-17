// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/countersign/countersign/internal/names"
	"github.com/countersign/countersign/internal/policy"
)

// forwardEnv carries the per-request context the pipeline needs: the
// authenticated session, the proxy connection's identity and (for tunneled
// requests) the CONNECT authority and negotiated SNI.
type forwardEnv struct {
	sess      *Session
	connID    string
	client    ClientAddr
	connect   string // CONNECT authority host ("" on the plain listener)
	sni       string
	tlsClient bool // inner requests arrive over the intercepted TLS conn
}

// outConn is the wrapped upstream connection: it surfaces the TLS state the
// transport negotiated so the result record can name ip/port/tls_version/
// cert_sha256 (03 §4.2).
type outConn struct {
	*tls.Conn
	info UpstreamRecord
}

func (c *outConn) ConnectionState() tls.ConnectionState { return c.Conn.ConnectionState() }

type rawConn struct {
	net.Conn
	info UpstreamRecord
}

// upstreamTransport builds the broker's upstream RoundTripper. HTTPS dials
// go through DialTLSContext so the broker performs the upstream handshake
// itself: system roots (+ test root in fixtures builds), TLS >= 1.2, and an
// ALPN offer independent of the client's (M2.2).
func (s *Server) upstreamTransport() *http.Transport {
	dial := s.cfg.DialContext
	if dial == nil {
		dial = defaultDialContext
	}
	tr := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			host, port := splitHostPort(addr)
			return &rawConn{Conn: c, info: UpstreamRecord{IP: host, Port: port}}, nil
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			host, port := splitHostPort(addr)
			serverName := host
			if ip := net.ParseIP(host); ip != nil {
				serverName = host
			}
			cfg := &tls.Config{
				RootCAs:    s.upstreamRoots(),
				MinVersion: tls.VersionTLS12,
				ServerName: serverName,
				NextProtos: []string{"h2", "http/1.1"},
			}
			tc := tls.Client(raw, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				// Best effort: the handshake already failed; the close
				// error cannot make upstream verification any safer.
				_ = raw.Close()
				return nil, &upstreamTLSError{err: err}
			}
			st := tc.ConnectionState()
			info := UpstreamRecord{IP: host, Port: port, TLSVersion: tlsVersionName(st.Version), ALPN: st.NegotiatedProtocol}
			if len(st.PeerCertificates) > 0 {
				sum := sha256.Sum256(st.PeerCertificates[0].Raw)
				info.CertSHA256 = hex.EncodeToString(sum[:])
			}
			return &outConn{Conn: tc, info: info}, nil
		},
	}
	return tr
}

// upstreamTLSError marks TLS handshake failures so the pipeline maps them
// to 502 UPSTREAM_TLS (C2.2.3).
type upstreamTLSError struct{ err error }

func (e *upstreamTLSError) Error() string { return e.err.Error() }
func (e *upstreamTLSError) Unwrap() error { return e.err }

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// upstreamRoots returns the CA pool for upstream verification.
func (s *Server) upstreamRoots() *x509.CertPool {
	if s.cfg.RootCAs != nil {
		return s.cfg.RootCAs
	}
	return defaultRootCAs()
}

// classify computes the reversibility class a request gets in local mode:
// the subset of 05 §1 rules that exist before M5 lands (boundary endpoint
// and control hosts; safe reads; everything else irreversible).
func classify(authority, method string) string {
	if strings.EqualFold(authority, names.BoundaryHost) {
		return "control"
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return "safe"
	default:
		return "irreversible"
	}
}

// grantByID returns the grant with the given id, nil when absent.
func grantByID(p *policy.SessionPolicy, id string) *policy.Grant {
	for i := range p.Spec.Grants {
		if p.Spec.Grants[i].ID == id {
			return &p.Spec.Grants[i]
		}
	}
	return nil
}
