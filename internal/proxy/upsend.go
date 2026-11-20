// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// upsend.go — synchronous HTTP/1.1 upstream attempts.
//
// For h1 upstreams there is no reason to pay for persistConn's readLoop/
// writeLoop machinery: the broker never reuses upstream conns (B2-01),
// so each attempt dials one policy-checked conn, writes the request, and
// reads the response inline. There is no pool and no retry path of any
// kind in this file — one conn, one attempt, then close. Upstreams that
// negotiate h2 keep the http.Transport.NewClientConn path (the only
// stdlib h2 entry); upstreamProto remembers which path each authority
// takes so https requests skip straight to it.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// spliceRW lets the 101 upgrade path treat the conn (plus the bytes the
// response reader may already have buffered) as a bidirectional stream.
// Its Close unregisters the ctx watcher and RSTs the conn (linger 0) so
// per-request conns never pile up in TIME_WAIT.
type spliceRW struct {
	*bufio.Reader
	conn net.Conn
	stop func() bool
	once sync.Once
}

func (s *spliceRW) Write(b []byte) (int, error) { return s.conn.Write(b) }

func (s *spliceRW) Close() error {
	s.once.Do(func() {
		s.stop()
		raw := s.conn
		if tc, ok := raw.(*tls.Conn); ok {
			raw = tc.NetConn()
		}
		if tcp, ok := raw.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
	})
	return s.conn.Close()
}

// upstreamRoundTrip performs exactly one upstream attempt on a freshly
// dialled conn and returns the response plus the close func that tears
// the conn down once the body is consumed. HTTP/1.1 targets (plain http,
// or https after ALPN learned h1) take the synchronous path; h2 targets
// — including first contact while ALPN is still unknown — take
// Transport.NewClientConn, whose pooled-exempt conn likewise has no
// retry path (B2-01).
func (s *Server) upstreamRoundTrip(dctx, reqCtx context.Context, tgt forwardTarget, dialAuthority string, upReq *http.Request, upInfo *UpstreamRecord, firstByte chan<- struct{}) (*http.Response, func(), error) {
	proto := "http/1.1"
	if tgt.scheme == "https" {
		proto = ""
		if p, ok := s.upstreamProto.Load(dialAuthority); ok {
			proto, _ = p.(string)
		}
	}
	if proto == "http/1.1" {
		conn, info, err := s.dialChecked(dctx, "tcp", dialAuthority, tgt.scheme)
		if err != nil {
			return nil, func() {}, err
		}
		if info.ALPN == "h2" {
			// The authority was recorded as h1 but just negotiated h2 —
			// a proto flip. Fail the request closed (the attempt is
			// recorded), learn h2 for next time; never send a second
			// upstream conn.
			s.upstreamProto.Store(dialAuthority, "h2")
			_ = conn.Close()
			return nil, func() {}, fmt.Errorf("upstream: ALPN flipped to h2")
		}
		res, splice, err := h1Attempt(reqCtx, conn, upReq, 60*time.Second)
		if err != nil {
			return nil, func() {}, err
		}
		if res.StatusCode == http.StatusSwitchingProtocols {
			res.Body = splice
		}
		if firstByte != nil {
			close(firstByte)
		}
		return res, func() { _ = splice.Close() }, nil
	}
	cc, err := s.transport.NewClientConn(dctx, tgt.scheme, dialAuthority)
	if err != nil {
		return nil, func() {}, err
	}
	res, err := cc.RoundTrip(upReq.WithContext(reqCtx))
	if err != nil {
		_ = cc.Close()
		return nil, func() {}, err
	}
	if upInfo != nil && upInfo.ALPN != "" {
		s.upstreamProto.Store(dialAuthority, upInfo.ALPN)
	}
	return res, func() { _ = cc.Close() }, nil
}

// h1Attempt writes req on conn and reads the response inline — one
// conn, one attempt, no persistConn goroutines at all. Interim 1xx are
// skipped; 101 is terminal. A request-write failure (including the
// LIMIT_BODY abort) fails the attempt immediately rather than waiting
// on a response the upstream is still expecting a body for.
func h1Attempt(ctx context.Context, conn net.Conn, req *http.Request, hdrTimeout time.Duration) (*http.Response, *spliceRW, error) {
	// AfterFunc needs no dedicated watcher goroutine: the close runs on
	// the ctx canceller. stop() unregisters when the conn retires.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	splice := &spliceRW{Reader: bufio.NewReader(conn), conn: conn, stop: stop}
	if hdrTimeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(hdrTimeout))
	}
	if err := req.Write(conn); err != nil {
		_ = splice.Close()
		return nil, nil, err
	}
	_ = conn.SetWriteDeadline(time.Time{})
	var res *http.Response
	for {
		if hdrTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(hdrTimeout))
		}
		r, err := http.ReadResponse(splice.Reader, req)
		if err != nil {
			_ = splice.Close()
			return nil, nil, err
		}
		res = r
		if res.StatusCode < 100 || res.StatusCode >= 200 || res.StatusCode == http.StatusSwitchingProtocols {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	return res, splice, nil
}
