// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// The WebSocket and opaque-tunnel relay of M2.5: an upgraded request is a
// granted effect.tunnel{kind:websocket}, a passthrough CONNECT is
// effect.tunnel{kind:passthrough}; both splice bytes through one counted,
// idle-bounded relay and end in effect.tunnel.result.

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/countersign/countersign/internal/policy"
)

// isWSUpgrade reports whether the request asks for a WebSocket upgrade:
// Connection carries the upgrade token and Upgrade names websocket.
func isWSUpgrade(r *http.Request) bool {
	return headerHasToken(r.Header, "Connection", "upgrade") &&
		headerHasToken(r.Header, "Upgrade", "websocket")
}

func headerHasToken(h http.Header, name, want string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), want) {
				return true
			}
		}
	}
	return false
}

// grantUpgrade reports whether the grant names u in its upgrade list.
func grantUpgrade(g *policy.Grant, u string) bool {
	for _, x := range g.Upgrade {
		if x == u {
			return true
		}
	}
	return false
}

// withDial installs the resolve-once carrier the transport's dial hooks
// need: the session's dial budget and the grant's network opt-in. info,
// when non-nil, receives the dialled upstream address for the result
// record (B2-06).
func withDial(ctx context.Context, sess *Session, grant *policy.Grant, info *UpstreamRecord) context.Context {
	return context.WithValue(ctx, ctxDialKey{}, &ctxDial{sess: sess, grant: grant, info: info})
}

// wsForward carries a granted WebSocket upgrade: write-ahead
// effect.tunnel{kind:websocket}, the upgrade round trip, then the counted
// byte relay and effect.tunnel.result. An upstream that declines the
// upgrade relays as a normal HTTP response and records "upgrade-declined".
func (s *Server) wsForward(w http.ResponseWriter, r *http.Request, env *forwardEnv, tgt forwardTarget, grant *policy.Grant, mres policy.Result) {
	sess := env.sess
	effectID := newULID()
	start := time.Now()

	result := &TunnelResultBody{EffectID: effectID}
	fin := func() {
		result.DurationMS = float64(time.Since(start).Microseconds()) / 1000.0
		if err := s.appendRecord(sess, "effect.tunnel.result", result); err != nil {
			s.Logf("tunnel result append failed for %s: %v", tgt.authority, err)
		}
	}

	// Write-ahead: the tunnel evidence is durable before the upgrade
	// round trip begins.
	err := s.appendRecordBound(sess, "effect.tunnel", TunnelBody{
		EffectID:  effectID,
		Authority: tgt.authority,
		SNI:       env.sni,
		Kind:      "websocket",
		Decision: DecisionRecord{
			Action: "allow", Reason: "OK", Requires: "allow", Grant: mres.Grant, Creds: []string{},
		},
	})
	if err != nil {
		s.Logf("record append failed for websocket %s: %v", tgt.authority, err)
		w.Header().Set("X-Countersign-Reason", "LEDGER_UNAVAILABLE")
		http.Error(w, "evidence store unavailable", http.StatusBadGateway)
		return
	}
	defer fin()

	outHdr := stripHopByHop(r.Header)
	// The upgrade pair is hop-by-hop but this hop honors it: put it back.
	outHdr["Connection"] = []string{"Upgrade"}
	outHdr["Upgrade"] = []string{"websocket"}
	dialAuthority := net.JoinHostPort(normName(tgt.host), strconv.Itoa(tgt.port))
	upReq := &http.Request{
		Method: r.Method,
		URL: &url.URL{
			Scheme:     tgt.scheme,
			Host:       dialAuthority,
			Opaque:     tgt.path,
			RawQuery:   tgt.rawQuery,
			ForceQuery: tgt.forceQ,
		},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       tgt.authority,
		Header:     outHdr,
		Body:       http.NoBody,
	}
	// B2-01: the upgrade attempt runs on one dedicated conn — the
	// synchronous h1 path or a pooled-exempt ClientConn for h2 — never
	// pooled; no transport retry path can produce an attempt the
	// effect.tunnel record did not cover. The conn stays open for the
	// tunnel's whole relay.
	res, closeUpstream, err := s.upstreamRoundTrip(withDial(r.Context(), sess, grant, nil),
		r.Context(), tgt, dialAuthority, upReq, nil, nil)
	if err != nil {
		result.Error = upstreamErrorReason(err)
		w.Header().Set("X-Countersign-Reason", result.Error)
		http.Error(w, "upstream failed", http.StatusBadGateway)
		return
	}
	defer closeUpstream()
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusSwitchingProtocols {
		// Upstream declined the upgrade: relay the plain response and
		// close the tunnel effect as declined.
		result.Error = "upgrade-declined"
		outRes := stripHopByHop(res.Header)
		for k, vals := range outRes {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(res.StatusCode)
		n, _ := io.Copy(w, res.Body)
		result.BytesDown = n
		return
	}

	// 101: splice the client's conn to the transport's read/write body
	// (a 101 response body is the live upstream conn under the hood).
	rwc, ok := res.Body.(interface {
		io.Reader
		io.Writer
	})
	if !ok {
		result.Error = "upgrade-unsupported"
		http.Error(w, "upstream conn not writable", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		result.Error = "hijack-unsupported"
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	cli, buf, err := hj.Hijack()
	if err != nil {
		result.Error = "hijack"
		return
	}
	// The 101 head crosses verbatim, then the tunnel is opaque bytes.
	if _, err := fmt.Fprintf(buf, "HTTP/1.1 %s\r\n", res.Status); err != nil {
		_ = cli.Close()
		result.Error = "response-write"
		return
	}
	if err := res.Header.Write(buf); err != nil {
		_ = cli.Close()
		result.Error = "response-write"
		return
	}
	if _, err := buf.WriteString("\r\n"); err != nil {
		_ = cli.Close()
		result.Error = "response-write"
		return
	}
	if err := buf.Flush(); err != nil {
		_ = cli.Close()
		result.Error = "response-write"
		return
	}
	if ic, ok := cli.(*inspectedConn); ok {
		ic.markOpaque()
	}
	if !s.trackTunnel(cli) {
		_ = cli.Close()
		result.Error = "broker-closed"
		return
	}
	defer s.untrackTunnel(cli)
	up64, down64, rerr := relayRW(&bufConn{Conn: cli, r: buf.Reader}, rwc, idleTunnelMax)
	result.BytesUp = up64
	result.BytesDown = down64
	if rerr != nil {
		result.Error = rerr.Error()
	}
}

// relayTunnel splices an accepted CONNECT conn to its upstream conn under
// the idle bound, counting bytes each way.
func relayTunnel(cli net.Conn, up net.Conn, idle time.Duration) (up64, down64 int64, err error) {
	return relayRW(cli, up, idle)
}

// relayRW copies bytes both ways between client and upstream until one
// side ends, applying the idle bound. up64 counts client->upstream bytes,
// down64 upstream->client. An idle kill reports error "idle-timeout".
func relayRW(cli io.ReadWriter, up io.ReadWriter, idle time.Duration) (up64, down64 int64, rerr error) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	var idled atomic.Bool
	stop := make(chan struct{})
	closer := func() {
		if c, ok := cli.(io.Closer); ok {
			_ = c.Close()
		}
		if c, ok := up.(io.Closer); ok {
			_ = c.Close()
		}
	}
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if time.Since(time.Unix(0, last.Load())) > idle {
					idled.Store(true)
					closer()
					return
				}
			}
		}
	}()
	var wg sync.WaitGroup
	var once sync.Once
	setErr := func(e error) {
		if e == nil || errors.Is(e, io.EOF) || isClosedErr(e) {
			return
		}
		once.Do(func() { rerr = e })
	}
	bump := func() { last.Store(time.Now().UnixNano()) }
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, err := relayCount(up, cli, bump)
		up64 = n
		setErr(err)
		closer()
	}()
	go func() {
		defer wg.Done()
		n, err := relayCount(cli, up, bump)
		down64 = n
		setErr(err)
		closer()
	}()
	wg.Wait()
	close(stop)
	if idled.Load() && rerr == nil {
		rerr = errors.New("idle-timeout")
	}
	return up64, down64, rerr
}

// relayCount copies src to dst counting bytes, bumping liveness on data.
func relayCount(dst io.Writer, src io.Reader, bump func()) (int64, error) {
	buf := make([]byte, 32*1024)
	var tot int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			bump()
			wn, werr := dst.Write(buf[:n])
			tot += int64(wn)
			if werr != nil {
				return tot, werr
			}
			if wn < n {
				return tot, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return tot, nil
			}
			return tot, rerr
		}
	}
}

func isClosedErr(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}
