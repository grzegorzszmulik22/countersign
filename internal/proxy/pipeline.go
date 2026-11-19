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
	"strconv"
	"strings"
	"time"

	"github.com/countersign/countersign/internal/creds"
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

	// Pipelined requests skip conn-level head inspection; re-apply the
	// parsed-layer smuggling rules before the grant is consulted.
	if deny := parsedHeadDeny(r); deny != nil {
		p, q, _ := wirePathQuery(r)
		s.denyRequest(w, r, env, deny.reason, "http", plainAuthority(r), p, q, "")
		return
	}

	authority := plainAuthority(r)
	host, port := splitHostPort(authority)
	if port == 0 {
		port = 80
	}
	path, rawQuery, forceQ := wirePathQuery(r)
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
		forceQ:    forceQ,
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

// wirePathQuery returns the request target's path and query exactly as
// the wire carried them (B2-03): r.RequestURI is the unmodified target.
// For absolute-form requests the scheme+authority prefix is stripped.
// forceQ marks a trailing "?" with an empty query, preserved verbatim.
func wirePathQuery(r *http.Request) (path, rawQuery string, forceQ bool) {
	target := r.RequestURI
	if r.URL != nil && r.URL.IsAbs() && strings.HasPrefix(target, r.URL.Scheme+"://") {
		rest := target[len(r.URL.Scheme)+3:]
		i := strings.IndexAny(rest, "/?")
		if i < 0 {
			return "/", "", false
		}
		target = rest[i:]
	}
	p, q, hasQ := strings.Cut(target, "?")
	if p == "" {
		p = "/"
	}
	return p, q, hasQ
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
	if reason == "LEDGER_UNAVAILABLE" || reason == "CREDENTIAL_UNAVAILABLE" {
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
	if err := s.appendRecordBound(env.sess, "effect.http", body); err != nil {
		s.Logf("record write failed for deny: %v", err)
	}
}

// forwardTarget is the normalized upstream destination of a request.
type forwardTarget struct {
	scheme    string // http | https
	authority string // host[:port] exactly as the client named it
	host      string
	port      int
	path      string // request-target path, wire-exact (B2-03)
	rawQuery  string // query bytes, wire-exact
	forceQ    bool   // the wire target ended in a bare "?"
}

// forward runs the pipeline: 04 §2 step 4 limits -> body buffer/defer ->
// step 5 credential rules -> write-ahead record -> injection -> upstream
// round trip -> scrubbed relay -> result record. It returns nothing;
// failures map to an HTTP response and a result record where the request
// reached the wire.
func (s *Server) forward(w http.ResponseWriter, r *http.Request, env *forwardEnv, tgt forwardTarget, mres policy.Result) {
	start := time.Now()
	effectID := newULID()
	sess := env.sess
	grant := grantByID(sess.Policy, mres.Grant)
	limit := bufferLimit(sess.Policy, grant)

	// 04 §2 step 4 (M3.5): limits — URL size, declared body size, then the
	// per-(session, grant) rate bucket.
	if reason := checkLimits(grant, r, tgt); reason != "" {
		s.denyRequest(w, r, env, reason, tgt.scheme, tgt.authority, tgt.path, tgt.rawQuery, mres.Grant)
		return
	}
	if grant != nil && grant.Limits != nil && grant.Limits.RequestsPerMinute != nil &&
		!sess.rate.take(mres.Grant, *grant.Limits.RequestsPerMinute) {
		s.denyRequest(w, r, env, "LIMIT_RATE", tgt.scheme, tgt.authority, tgt.path, tgt.rawQuery, mres.Grant)
		return
	}

	// WebSocket upgrade (04 §2 step 5, M2.5): the matched grant must name
	// "websocket" in its upgrade list — otherwise the request can never
	// become a tunnel (the response crosses as a plain HTTP relay).
	if isWSUpgrade(r) {
		if grant == nil || !grantUpgrade(grant, "websocket") {
			s.denyRequest(w, r, env, "PROTOCOL_DENIED", tgt.scheme, tgt.authority, tgt.path, tgt.rawQuery, mres.Grant)
			return
		}
		s.wsForward(w, r, env, tgt, grant, mres)
		return
	}

	// Buffer-or-defer the request body (03 §4.5 deferred bodies): up to the
	// grant's bufferLimit the digest rides in the write-ahead record.
	var (
		bodySHA    [32]byte
		bodyLen    int64
		bodyDefer  bool
		bodyReader io.Reader
		buf        []byte
	)
	reqBody := &hashCounter{h: sha256.New()}
	if r.Body != nil && r.Body != http.NoBody {
		b := &bytes.Buffer{}
		n, err := io.CopyN(b, r.Body, limit+1)
		if err != nil && err != io.EOF {
			s.denyRequest(w, r, env, "LIMIT_BODY", tgt.scheme, tgt.authority, tgt.path, tgt.rawQuery, mres.Grant)
			return
		}
		buf = b.Bytes()
		if _, err := reqBody.Write(buf); err != nil {
			s.Logf("request body hashing failed: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if n <= limit {
			bodySHA = sha256.Sum256(buf)
			bodyLen = n
			bodyReader = bytes.NewReader(buf)
		} else {
			bodyDefer = true
			bodyLen = -1
			bodyReader = io.MultiReader(bytes.NewReader(buf), io.TeeReader(r.Body, reqBody))
		}
	} else {
		bodySHA = sha256.Sum256(nil)
		bodyLen = 0
		bodyReader = nil
	}

	outHdr := stripHopByHop(r.Header)

	// 04 §2 step 5 (M3.3): credential rules on the pre-injection request —
	// the buffered prefix is all a scan may see (04 §4.3).
	plan, reason := evalCreds(sess, grant, r, outHdr, tgt, buf)
	if reason != "" {
		if reason == "CREDENTIAL_UNAVAILABLE" {
			s.Logf("credential store unavailable for grant %s", mres.Grant)
		}
		s.denyRequest(w, r, env, reason, tgt.scheme, tgt.authority, tgt.path, tgt.rawQuery, mres.Grant)
		return
	}

	// M3.5 streaming body cap: the buffered prefix already over the grant's
	// body limit denies before upstream; a deferred body is capped on the
	// wire — the connection dies mid-write and the result carries
	// error: limit-body (C3.5.3).
	var capped *capBody
	if mb := maxBody(grant); mb > 0 {
		if int64(len(buf)) > mb {
			s.denyRequest(w, r, env, "LIMIT_BODY", tgt.scheme, tgt.authority, tgt.path, tgt.rawQuery, mres.Grant)
			return
		}
		if bodyReader != nil {
			capped = &capBody{r: bodyReader, max: mb}
			bodyReader = capped
		}
	}
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
	if plan.spec != nil {
		effect.Decision.Creds = []string{plan.refID}
	}
	// Write-ahead: the effect.http record is durable before the first byte
	// goes upstream — and before the credential materializes (02 §6:
	// evidence first, then secrets touch the wire). Sink failure fails
	// closed, and the append itself is bounded (M2.4's write-ahead window).
	if err := s.appendRecordBound(sess, "effect.http", effect); err != nil {
		s.Logf("record append failed: %v", err)
		w.Header().Set("X-Countersign-Reason", "LEDGER_UNAVAILABLE")
		http.Error(w, "evidence store unavailable", http.StatusBadGateway)
		return
	}
	if plan.spec != nil {
		plan.spec.Apply(outHdr)
		plan.injected = true
		if injectHook != nil {
			injectHook(sess.ID, mres.Grant, plan.refID)
		}
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

	// Build the upstream request. Dial the identity the checks verified,
	// folded the same way (case, trailing root dot) so an authority
	// accepted as equal cannot fail resolution on the cosmetic
	// difference; the client's Host header still crosses verbatim.
	// Opaque carries the request-target's raw path bytes so the wire gets
	// them exactly — no re-escaping, no decoding (B2-03).
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
	}
	if bodyReader != nil {
		upReq.Body = io.NopCloser(bodyReader)
	}
	if bodyLen >= 0 {
		upReq.ContentLength = bodyLen
	} else {
		upReq.ContentLength = -1
	}
	if plan.injected {
		// 04 §4.5: credentialed requests offer exactly gzip or identity so
		// every response arrives in an encoding the broker can scan.
		upReq.Header.Set("Accept-Encoding", "gzip, identity")
	}
	upInfo := &UpstreamRecord{}
	gotFirstByte := make(chan struct{})
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() { close(gotFirstByte) },
	}
	// B2-01: the upstream attempt runs on one dedicated conn — the
	// synchronous h1 path or a pooled-exempt ClientConn for h2 — so no
	// transport retry path (h1 reused-conn or h2 REFUSED/GOAWAY) can
	// fire: a second attempt could never be recorded, so none may
	// happen. Resolve-once needs the session (dial budget) and the grant
	// (network opt-in) inside the dial carrier; upInfo comes back
	// through the same carrier.
	ctx := httptrace.WithClientTrace(r.Context(), trace)
	res, closeUpstream, err := s.upstreamRoundTrip(withDial(r.Context(), sess, grant, upInfo),
		ctx, tgt, dialAuthority, upReq, upInfo, gotFirstByte)
	if err != nil {
		// The synchronous h1 path wraps a body-read failure in net/http's
		// requestBodyReadError (no Unwrap); the capBody flag records the
		// sentinel independently of the wrapping (C3.5.3).
		if errors.Is(err, errBodyLimit) || (capped != nil && capped.over) {
			result.Error = "limit-body"
			w.Header().Set("X-Countersign-Reason", "LIMIT_BODY")
			http.Error(w, "request denied: LIMIT_BODY", http.StatusForbidden)
			return
		}
		result.Error = upstreamErrorReason(err)
		result.Upstream = nonNil(upInfo)
		s.Logf("upstream %s %s: %v", r.Method, tgt.authority, err)
		w.Header().Set("X-Countersign-Reason", result.Error)
		http.Error(w, "upstream failed", http.StatusBadGateway)
		return
	}
	defer closeUpstream()
	// Best effort: the upstream body is drained or abandoned; a close
	// error only repeats an already-recorded failure mode.
	defer func() { _ = res.Body.Close() }()
	select {
	case <-gotFirstByte:
		result.Timing.TTFBMS = float64(time.Since(start).Microseconds()) / 1000.0
	default:
	}
	result.Status = res.StatusCode
	result.Upstream = nonNil(upInfo)

	outRes := stripHopByHop(res.Header)
	src := io.Reader(res.Body)
	var scr *creds.Scrubber
	if plan.injected {
		scr = newScrubber(plan)
		scrubHeaders(scr, outRes)
		src, err = scrubBody(res)
		if err != nil {
			// 04 §4.5: the broker offered only gzip and identity; anything
			// else is unverifiable and cannot cross.
			result.Error = "upstream-encoding"
			w.Header().Set("X-Countersign-Reason", "UPSTREAM_ENCODING")
			http.Error(w, "upstream encoding", http.StatusBadGateway)
			return
		}
	}
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
	err = relayResponse(w, src, scr, respBody)
	if scr != nil {
		result.Scrubbed = scr.Count
	}
	result.Response.BodySHA256 = hex_SHA(respBody.h.Sum(nil))
	result.Response.BodyLen = respBody.n
	result.RequestBody = BodyDigest{SHA256: hex_SHA(reqBody.h.Sum(nil)), Len: reqBody.n}
	if bodyDefer {
		var ds [32]byte
		copy(ds[:], reqBody.h.Sum(nil))
		result.ReqDigest = requestDigest(r.Method, tgt.scheme, digestAuthority(tgt.host, tgt.port, tgt.scheme), tgt.path, tgt.rawQuery, ds, outHdr)
	}
	// Forward upstream trailers to the client — scrubbed when a
	// credential is in play (04 §4.5: headers and trailers get the same
	// search-and-replace).
	for k, vals := range res.Trailer {
		for _, v := range vals {
			if scr != nil {
				v = scr.Scrub(v)
			}
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

// relayResponse copies src to w in bounded chunks, flushing after every
// chunk so streamed responses (SSE, chunked, h2 frames) are never
// coalesced or held back (M2.3). When scr is non-nil each chunk passes
// the scrubber first (M3.4); its carry window holds back at most
// maxPattern-1 bytes at a time, so streaming semantics are preserved.
// It counts and hashes the bytes the client received.
func relayResponse(w http.ResponseWriter, src io.Reader, scr *creds.Scrubber, dst *hashCounter) error {
	buf := make([]byte, 32*1024)
	fl, _ := w.(http.Flusher)
	var werr error
	wrote := false
	emit := func(b []byte) {
		if werr != nil || len(b) == 0 {
			return
		}
		wm, err := w.Write(b)
		if _, derr := dst.Write(b[:wm]); derr != nil {
			werr = derr
			return
		}
		wrote = true
		if err != nil {
			werr = &writeErr{err}
		}
	}
	for {
		m, rerr := src.Read(buf)
		wrote = false
		if scr != nil {
			scr.Write(buf[:m], emit)
			if rerr == io.EOF {
				scr.Flush(emit)
			}
		} else {
			emit(buf[:m])
		}
		if wrote && fl != nil {
			fl.Flush()
		}
		if werr != nil {
			return werr
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
	var ub *errUpstreamBlocked
	if errors.As(err, &ub) {
		return "UPSTREAM_BLOCKED"
	}
	return "UPSTREAM"
}
