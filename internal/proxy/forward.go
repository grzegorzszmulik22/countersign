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

// publishDialInfo hands the completed upstream record (dialled address
// plus, for HTTPS, the negotiated TLS state) to the result accumulator
// the request's dial carrier installed (B2-06).
func publishDialInfo(ctx context.Context, info UpstreamRecord) {
	if d, _ := ctx.Value(ctxDialKey{}).(*ctxDial); d != nil && d.info != nil {
		*d.info = info
	}
}

// dialChecked resolves the authority once, checks the range policy, and
// dials the checked address; for https it performs the upstream TLS
// handshake inline (ServerName is the name the client asked for — the
// resolved IP rides only in the socket and the record). The completed
// record is published to the dial carrier (B2-06); the negotiated ALPN
// comes back in the returned record. Used by the transport's dial hooks
// (ClientConn path) and by the synchronous h1 upstream path.
func (s *Server) dialChecked(ctx context.Context, network, addr, scheme string) (net.Conn, UpstreamRecord, error) {
	raw, info, err := s.dialResolved(ctx, network, addr)
	if err != nil {
		return nil, info, err
	}
	if scheme != "https" {
		publishDialInfo(ctx, info)
		return raw, info, nil
	}
	// ServerName is the name the client asked for — the resolved IP
	// rides only in the socket and the record.
	host, _ := splitHostPort(addr)
	tc := tls.Client(raw, &tls.Config{
		RootCAs:    s.upstreamRoots(),
		MinVersion: tls.VersionTLS12,
		ServerName: host,
		NextProtos: []string{"h2", "http/1.1"},
		// X25519 only: the standard mandatory TLS 1.3 group — skips the
		// hybrid ML-KEM key exchange whose cost dominates handshakes on
		// this host (every upstream attempt pays a fresh handshake).
		CurvePreferences: []tls.CurveID{tls.X25519},
		// Every request still gets its own conn and handshake (B2-01);
		// resumption only abbreviates the handshake — fresh keys, fresh
		// socket, fresh recorded attempt.
		ClientSessionCache: s.upstreamSessionCache,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		// Best effort: the handshake already failed; the close error
		// cannot make upstream verification any safer.
		_ = raw.Close()
		return nil, info, &upstreamTLSError{err: err}
	}
	st := tc.ConnectionState()
	info.TLSVersion = tlsVersionName(st.Version)
	info.ALPN = st.NegotiatedProtocol
	if len(st.PeerCertificates) > 0 {
		sum := sha256.Sum256(st.PeerCertificates[0].Raw)
		info.CertSHA256 = hex.EncodeToString(sum[:])
	}
	publishDialInfo(ctx, info)
	return tc, info, nil
}

// upstreamTransport builds the broker's upstream RoundTripper. HTTPS dials
// go through DialTLSContext so the broker performs the upstream handshake
// itself: system roots (+ test root in fixtures builds), TLS >= 1.2, and an
// ALPN offer independent of the client's (M2.2). Both dial hooks resolve
// the host once, check the range policy and dial the checked address
// (B2-04/B2-06); the name stays in TLS ServerName while the socket and the
// record carry the IP.
func (s *Server) upstreamTransport() *http.Transport {
	tr := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		// Never let the transport unzip: credentialed responses must be
		// decoded inside the scrubber (04 §4.5), and plain ones cross
		// byte-exact (M2.3).
		DisableCompression: true,
		// B2-01: upstream requests run through Transport.NewClientConn —
		// a pooled-exempt conn whose RoundTrip makes exactly one attempt
		// (h1 persistConn and h2 ClientConn alike). The pool is never
		// consulted, so neither the reused-conn idempotent retry nor the
		// h2 REFUSED/GOAWAY stream retry can ever produce an upstream
		// attempt the effect records did not cover.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, _, err := s.dialChecked(ctx, network, addr, "http")
			return c, err
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, _, err := s.dialChecked(ctx, network, addr, "https")
			return c, err
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
