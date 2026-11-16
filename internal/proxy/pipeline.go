// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"

	"github.com/countersign/countersign/internal/policy"
)

// handlePlain serves forward-proxy requests on the plain listener:
// absolute-form (and, tolerantly, origin-form) http requests (M2.1).
func (s *Server) handlePlain(w http.ResponseWriter, r *http.Request) {
	env := &forwardEnv{connID: connID(r), client: clientAddr(r)}
	sess, attributed := s.identifySession(r)
	if sess == nil || attributed {
		s.denyNoSession(w, r, sess, attributed, plainAuthority(r))
		return
	}
	env.sess = sess

	authority := plainAuthority(r)
	host, port := splitHostPort(authority)
	if port == 0 {
		port = 80
	}
	path, rawQuery := plainPathQuery(r)
	res := sess.Policy.Match(policyRequest(r, "http", host, port, path, rawQuery, "", ""))
	if res.Reason != "" {
		s.denyRequest(w, r, env, res.Reason, "http", authority, path, rawQuery, res.Grant)
		return
	}
	s.forward(w, r, env, forwardTarget{
		scheme:    "http",
		authority: authority,
		host:      host,
		port:      port,
		path:      path,
		rawQuery:  rawQuery,
	}, res)
}

// plainAuthority returns the authority a plain-listener request names:
// absolute-form URL host, else the Host header (origin-form tolerance).
func plainAuthority(r *http.Request) string {
	if r.URL != nil && r.URL.IsAbs() && r.URL.Host != "" {
		return r.URL.Host
	}
	return r.Host
}

// plainPathQuery returns the raw path and query exactly as received.
func plainPathQuery(r *http.Request) (path, rawQuery string) {
	if r.URL != nil {
		path = r.URL.EscapedPath()
		if path == "" {
			path = "/"
		}
		return path, r.URL.RawQuery
	}
	return "/", ""
}

// policyRequest adapts an inbound request to a policy.Request (04 §2).
func policyRequest(r *http.Request, scheme, host string, port int, path, query, sni, connect string) *policy.Request {
	return &policy.Request{
		Method:  r.Method,
		Scheme:  scheme,
		Host:    host,
		Port:    port,
		Path:    path,
		Query:   query,
		SNI:     sni,
		Connect: connect,
	}
}

// denyRequest records an attributable denial for a fully-parsed request:
// an effect.http with decision.action deny (C2.1.2).
func (s *Server) denyRequest(w http.ResponseWriter, r *http.Request, env *forwardEnv, reason, scheme, authority, path, rawQuery, grantID string) {
	status := http.StatusForbidden
	if reason == "LEDGER_UNAVAILABLE" {
		status = http.StatusBadGateway
	}
	s.recordDenyEffect(env, r, scheme, authority, path, rawQuery, grantID, reason)
	w.Header().Set("X-Countersign-Reason", reason)
	http.Error(w, "request denied: "+reason, status)
}

// recordDenyEffect writes effect.http{decision.action: deny}.
func (s *Server) recordDenyEffect(env *forwardEnv, r *http.Request, scheme, authority, path, rawQuery, grantID, reason string) {
	body := EffectHTTPBody{
		EffectID: newULID(),
		Actor:    "sandbox",
		ConnID:   env.connID,
		Client:   env.client,
		Request: RequestRecord{
			Method:      r.Method,
			Scheme:      scheme,
			Authority:   authority,
			Path:        path,
			QuerySHA256: querySHA(rawQuery),
			QueryLen:    len(rawQuery),
			HeaderNames: headerNames(stripHopByHop(r.Header)),
		},
		Class: classify(hostOnly(authority), r.Method),
		Decision: DecisionRecord{
			Action:   "deny",
			Reason:   reason,
			Requires: "allow",
			Grant:    grantID,
			Creds:    []string{},
		},
		Attribution: Attribution{Level: "none", Intents: []string{}},
		Taint:       []string{},
		Budget:      BudgetRecord{},
		Inspect:     "none",
	}
	if err := s.appendRecord(env.sess, "effect.http", body); err != nil {
		s.Logf("record write failed for deny: %v", err)
	}
}

// forwardTarget is the normalized upstream destination of a request.
type forwardTarget struct {
	scheme    string // http | https
	authority string // host[:port] exactly as the client named it
	host      string
	port      int
	path      string // raw path as received
	rawQuery  string
}

// forward runs the pipeline: write-ahead record -> upstream round trip ->
// streamed relay -> result record. It returns nothing; failures map to an
// HTTP response and a result record where the request reached the wire.
func (s *Server) forward(w http.ResponseWriter, r *http.Request, env *forwardEnv, tgt forwardTarget, mres policy.Result) {
	start := time.Now()
	effectID := newULID()
	sess := env.sess
	grant := grantByID(sess.Policy, mres.Grant)
	limit := bufferLimit(sess.Policy, grant)

	// Buffer-or-defer the request body (03 §4.5 deferred bodies): up to the
	// grant's bufferLimit the digest rides in the write-ahead record.
	var (
		bodySHA    [32]byte
		bodyLen    int64
		bodyDefer  bool
		bodyReader io.Reader
	)
	reqBody := &hashCounter{h: sha256.New()}
	if r.Body != nil && r.Body != http.NoBody {
		buf := &bytes.Buffer{}
		n, err := io.CopyN(buf, r.Body, limit+1)
		if err != nil && err != io.EOF {
			s.denyRequest(w, r, env, "LIMIT_BODY", tgt.scheme, tgt.authority, tgt.path, tgt.rawQuery, mres.Grant)
			return
		}
		_, _ = reqBody.Write(buf.Bytes())
		if n <= limit {
			bodySHA = sha256.Sum256(buf.Bytes())
			bodyLen = n
			bodyReader = bytes.NewReader(buf.Bytes())
		} else {
			bodyDefer = true
			bodyLen = -1
			bodyReader = io.MultiReader(bytes.NewReader(buf.Bytes()), io.TeeReader(r.Body, reqBody))
		}
	} else {
		bodySHA = sha256.Sum256(nil)
		bodyLen = 0
		bodyReader = nil
	}

	outHdr := stripHopByHop(r.Header)
	reqRec := RequestRecord{
		Method:       r.Method,
		Scheme:       tgt.scheme,
		Authority:    tgt.authority,
		Path:         tgt.path,
		QuerySHA256:  querySHA(tgt.rawQuery),
		QueryLen:     len(tgt.rawQuery),
		HeaderNames:  headerNames(outHdr),
		BodyLen:      bodyLen,
		BodyDeferred: bodyDefer,
	}
	var reqDigest string
	if !bodyDefer {
		reqRec.BodySHA256 = hex_SHA(bodySHA[:])
		reqDigest = requestDigest(r.Method, tgt.scheme, digestAuthority(tgt.host, tgt.port, tgt.scheme), tgt.path, tgt.rawQuery, bodySHA, outHdr)
	}

	effect := EffectHTTPBody{
		EffectID:      effectID,
		Actor:         "sandbox",
		ConnID:        env.connID,
		Client:        env.client,
		Request:       reqRec,
		RequestDigest: reqDigest,
		Class:         classify(tgt.host, r.Method),
		Decision: DecisionRecord{
			Action:   "allow",
			Reason:   "OK",
			Requires: "allow",
			Grant:    mres.Grant,
			Creds:    []string{},
		},
		Attribution: Attribution{Level: "none", Intents: []string{}},
		Taint:       []string{},
		Budget:      BudgetRecord{},
		Inspect:     "none",
	}
	// Write-ahead: the effect.http record is durable before the first byte
	// goes upstream. Sink failure fails closed (02 §6).
	if err := s.appendRecord(sess, "effect.http", effect); err != nil {
		s.Logf("record append failed: %v", err)
		w.Header().Set("X-Countersign-Reason", "LEDGER_UNAVAILABLE")
		http.Error(w, "evidence store unavailable", http.StatusBadGateway)
		return
	}

	result := &ResultBody{
		EffectID:  effectID,
		ServedBy:  "upstream",
		Scrubbed:  0,
		ReqDigest: reqDigest,
	}
	defer func() {
		result.Timing.TotalMS = float64(time.Since(start).Microseconds()) / 1000.0
		if err := s.appendRecord(sess, "effect.http.result", result); err != nil {
			s.Logf("result record append failed: %v", err)
		}
	}()

	// Build the upstream request.
	upURL := &url.URL{Scheme: tgt.scheme, Host: tgt.authority, Path: tgt.path, RawPath: tgt.path, RawQuery: tgt.rawQuery}
	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, upURL.String(), bodyReader)
	if err != nil {
		result.Error = "request-build"
		w.Header().Set("X-Countersign-Reason", "UPSTREAM_BLOCKED")
		http.Error(w, "bad request", http.StatusBadGateway)
		return
	}
	upReq.Header = outHdr
	if bodyLen >= 0 {
		upReq.ContentLength = bodyLen
	}
	upInfo := &UpstreamRecord{}
	gotFirstByte := make(chan struct{})
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if uc, ok := info.Conn.(*outConn); ok {
				*upInfo = uc.info
			} else if rc, ok := info.Conn.(*rawConn); ok {
				*upInfo = rc.info
			}
		},
		GotFirstResponseByte: func() { close(gotFirstByte) },
	}
	upReq = upReq.WithContext(httptrace.WithClientTrace(upReq.Context(), trace))

	res, err := s.transport.RoundTrip(upReq)
	if err != nil {
		result.Error = upstreamErrorReason(err)
		result.Upstream = nonNil(upInfo)
		s.Logf("upstream %s %s: %v", r.Method, tgt.authority, err)
		w.Header().Set("X-Countersign-Reason", result.Error)
		http.Error(w, "upstream failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = res.Body.Close() }()
	select {
	case <-gotFirstByte:
		result.Timing.TTFBMS = float64(time.Since(start).Microseconds()) / 1000.0
	default:
	}
	result.Status = res.StatusCode
	result.Upstream = nonNil(upInfo)

	outRes := stripHopByHop(res.Header)
	// Preserve trailers: declare upstream-announced keys before WriteHeader
	// (h1 framing needs it); values land via TrailerPrefix after the body.
	for k := range res.Trailer {
		w.Header().Add("Trailer", k)
	}
	for k, vals := range outRes {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	result.Response.HeaderNames = headerNames(outRes)
	w.WriteHeader(res.StatusCode)

	respBody := &hashCounter{h: sha256.New()}
	err = relayStream(w, res.Body, respBody)
	result.Response.BodySHA256 = hex_SHA(respBody.h.Sum(nil))
	result.Response.BodyLen = respBody.n
	result.RequestBody = BodyDigest{SHA256: hex_SHA(reqBody.h.Sum(nil)), Len: reqBody.n}
	if bodyDefer {
		var ds [32]byte
		copy(ds[:], reqBody.h.Sum(nil))
		result.ReqDigest = requestDigest(r.Method, tgt.scheme, digestAuthority(tgt.host, tgt.port, tgt.scheme), tgt.path, tgt.rawQuery, ds, outHdr)
	}
	// Forward upstream trailers to the client.
	for k, vals := range res.Trailer {
		for _, v := range vals {
			w.Header().Set(http.TrailerPrefix+k, v)
		}
	}
	if err != nil {
		var we *writeErr
		if errors.As(err, &we) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || clientGone(r) {
			result.Error = "client-abort"
		} else {
			result.Error = "upstream-body"
		}
		s.Logf("relay %s %s: %v", r.Method, tgt.authority, err)
		return
	}
	if bodyLen >= 0 && result.RequestBody.Len != bodyLen {
		result.Error = "request-body-truncated"
	}
}

// hashCounter feeds a hash while counting bytes (streamed body digests).
type hashCounter struct {
	h hash.Hash
	n int64
}

func (c *hashCounter) Write(b []byte) (int, error) {
	m, err := c.h.Write(b)
	c.n += int64(m)
	return m, err
}

// writeErr marks a client-side write failure so the result record can
// name the abort (C2.3.4) instead of blaming upstream.
type writeErr struct{ err error }

func (e *writeErr) Error() string { return e.err.Error() }
func (e *writeErr) Unwrap() error { return e.err }

// relayStream copies src to w in bounded chunks, flushing after every
// write so streamed responses (SSE, chunked, h2 frames) are never
// coalesced or held back (M2.3). It counts and hashes the bytes.
func relayStream(w http.ResponseWriter, src io.Reader, dst *hashCounter) error {
	buf := make([]byte, 32*1024)
	fl, _ := w.(http.Flusher)
	for {
		m, rerr := src.Read(buf)
		if m > 0 {
			wm, werr := w.Write(buf[:m])
			_, _ = dst.Write(buf[:wm])
			if fl != nil {
				fl.Flush()
			}
			if werr != nil {
				return &writeErr{werr}
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return nil
			}
			return rerr
		}
	}
}

// clientGone reports whether the client connection's context is done.
func clientGone(r *http.Request) bool {
	select {
	case <-r.Context().Done():
		return true
	default:
		return false
	}
}

func querySHA(q string) string {
	sum := sha256.Sum256([]byte(q))
	return hex_SHA(sum[:])
}

func hex_SHA(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0xf]
	}
	return string(out)
}

func hostOnly(authority string) string {
	host, _, err := net.SplitHostPort(authority)
	if err != nil {
		return authority
	}
	return host
}

func nonNil(u *UpstreamRecord) *UpstreamRecord {
	if u.IP == "" && u.Port == 0 && u.CertSHA256 == "" {
		return nil
	}
	return u
}

func upstreamErrorReason(err error) string {
	var ute *upstreamTLSError
	if errors.As(err, &ute) {
		return "UPSTREAM_TLS"
	}
	return "UPSTREAM"
}
