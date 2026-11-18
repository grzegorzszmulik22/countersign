// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/countersign/countersign/test/fixtures/fxlib"
)

// M3.5 checks: request limits of 04 §1 — maxRequestBodyBytes,
// maxUrlBytes (path + query) and requestsPerMinute as a per-(session,
// grant) token bucket with burst = one tenth.

// m35Grants: one limited grant family, a credentialed redirect source,
// and non-credentialed space.
const m35Grants = `  grants:
    - id: lim-stream
      match: {hosts: [api.anthropic.com], paths: [/lim/stream]}
      bufferLimit: 1Ki
      limits: {maxRequestBodyBytes: 4096}
    - id: lim
      match: {hosts: [api.anthropic.com], paths: [/lim/**]}
      limits: {maxRequestBodyBytes: 100, maxUrlBytes: 96, requestsPerMinute: 60}
    - id: lim-h2
      match: {hosts: [h2.anthropic.example], paths: [/lim/**]}
      bufferLimit: 1Ki
      limits: {maxRequestBodyBytes: 4096}
    - id: lim2
      match: {hosts: [api.anthropic.com], paths: [/lim2/**]}
      limits: {requestsPerMinute: 60}
    - id: redir
      match: {hosts: [api.anthropic.com], paths: [/redir]}
      credential:
        ref: {secret: anthropic, key: api-key}
        inject: {header: x-api-key, format: "{secret}"}
        placeholderEnv: ANTHROPIC_API_KEY
    - id: open
      match: {hosts: [api.anthropic.com]}
    - id: pypi
      match: {hosts: [pypi.org, files.pythonhosted.org]}
`

// --- C3.5.1 -------------------------------------------------------------
// At the limit the request passes; one byte over carries the right
// LIMIT_* reason. URL limit counts path + query; body limit counts
// bytes (here via Content-Length; the streaming form is C3.5.3).
func TestC351LimitBoundaries(t *testing.T) {
	ce := startCredEnv(t, m35Grants, nil)
	e := ce.env

	// URL: limit 96 over path+query.
	//   allowed: "/lim/" + 87 a's (92) + "abcd" (4) = 96
	//   denied:  same path + "abcde" (5)         = 97
	before := ce.anthro.count()
	pad := strings.Repeat("a", 87)
	res, _ := doCred(t, e, "tok-one", "GET", "https://api.anthropic.com/lim/"+pad+"?abcd", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("at-limit URL denied: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
	if ce.anthro.count() != before+1 {
		t.Fatal("at-limit URL request never reached upstream")
	}
	res, body := doCred(t, e, "tok-one", "GET", "https://api.anthropic.com/lim/"+pad+"?abcde", nil, nil)
	if res.StatusCode != http.StatusForbidden || denyReason(res) != "LIMIT_URL" {
		t.Fatalf("over-limit URL: status=%d reason=%q body=%s", res.StatusCode, denyReason(res), body)
	}
	if ce.anthro.count() != before+1 {
		t.Fatal("over-limit URL reached upstream")
	}
	// The URL rule sees the QUERY too (sabotage target): a path alone
	// under the limit is denied once the query pushes it over.
	res, _ = doCred(t, e, "tok-one", "GET",
		"https://api.anthropic.com/lim/u?"+strings.Repeat("q", 91), nil, nil)
	if res.StatusCode != http.StatusForbidden || denyReason(res) != "LIMIT_URL" {
		t.Fatalf("query-pushed URL: status=%d reason=%q", res.StatusCode, denyReason(res))
	}

	// Body: limit 100 via declared length. At-limit must pass AND arrive
	// complete — "allowed but truncated" is a boundary failure too.
	bb := ce.anthro.bodyBytes()
	res, _ = doCred(t, e, "tok-one", "POST", "https://api.anthropic.com/lim/b",
		nil, bytes.Repeat([]byte{'x'}, 100))
	if res.StatusCode != 200 {
		t.Fatalf("at-limit body denied: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
	if got := ce.anthro.bodyBytes() - bb; got != 100 {
		t.Fatalf("at-limit body arrived incomplete: upstream got %d of 100", got)
	}
	bb = ce.anthro.bodyBytes()
	res, _ = doCred(t, e, "tok-one", "POST", "https://api.anthropic.com/lim/b",
		nil, bytes.Repeat([]byte{'x'}, 101))
	if res.StatusCode != http.StatusForbidden || denyReason(res) != "LIMIT_BODY" {
		t.Fatalf("over-limit body: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
	if got := ce.anthro.bodyBytes() - bb; got != 0 {
		t.Fatalf("denied body still reached upstream: %d bytes", got)
	}

	// Declared-length body over bufferLimit but exactly at the body cap
	// (lim-stream: buffer 1 KiB, cap 4 KiB): the deferred path must
	// deliver it complete; one byte over is denied pre-wire.
	bb = ce.anthro.bodyBytes()
	res, _ = doCred(t, e, "tok-one", "POST", "https://api.anthropic.com/lim/stream",
		nil, bytes.Repeat([]byte{'x'}, 4096))
	if res.StatusCode != 200 {
		t.Fatalf("at-limit deferred body denied: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
	if got := ce.anthro.bodyBytes() - bb; got != 4096 {
		t.Fatalf("at-limit deferred body incomplete: upstream got %d of 4096", got)
	}
	bb = ce.anthro.bodyBytes()
	res, _ = doCred(t, e, "tok-one", "POST", "https://api.anthropic.com/lim/stream",
		nil, bytes.Repeat([]byte{'x'}, 4097))
	if res.StatusCode != http.StatusForbidden || denyReason(res) != "LIMIT_BODY" {
		t.Fatalf("over-limit deferred body: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
	if got := ce.anthro.bodyBytes() - bb; got != 0 {
		t.Fatalf("denied deferred body still reached upstream: %d bytes", got)
	}
}

// --- C3.5.2 -------------------------------------------------------------
// The rate bucket is per (session, grant): rpm 60 -> burst 6, refill
// 1/s. Six requests to lim pass, the 7th (fired well inside a second) is
// LIMIT_RATE — while session s2 on the same grant and session s1 on
// another grant are unaffected.
func TestC352RateScope(t *testing.T) {
	ce := startCredEnv(t, m35Grants, nil)
	e := ce.env
	const lim = "https://api.anthropic.com/lim/r"

	var denyAt = -1
	for i := 0; i < 8; i++ {
		res, _ := doCred(t, e, "tok-one", "GET", lim, nil, nil)
		if res.StatusCode != 200 {
			if denyReason(res) != "LIMIT_RATE" {
				t.Fatalf("request %d denied %q, want LIMIT_RATE or pass", i, denyReason(res))
			}
			if denyAt < 0 {
				denyAt = i
			}
		}
	}
	if denyAt != 6 {
		t.Fatalf("first LIMIT_RATE at request %d, want index 6 (burst 6)", denyAt)
	}

	// Same session, another limited grant (lim2): its bucket must still
	// hold a FULL burst — a bucket shared across grants inside the
	// session would be dry already.
	const lim2 = "https://api.anthropic.com/lim2/r"
	for i := 0; i < 6; i++ {
		res, _ := doCred(t, e, "tok-one", "GET", lim2, nil, nil)
		if res.StatusCode != 200 {
			t.Fatalf("lim2 request %d denied by lim's drained bucket: %q", i, denyReason(res))
		}
	}
	res, _ := doCred(t, e, "tok-one", "GET", lim2, nil, nil)
	if res.StatusCode != http.StatusForbidden || denyReason(res) != "LIMIT_RATE" {
		t.Fatalf("lim2's own burst did not exhaust at 6: status=%d reason=%q",
			res.StatusCode, denyReason(res))
	}

	// Same grant, another session: a full burst of its own — a bucket
	// shared across sessions would be dry already.
	for i := 0; i < 6; i++ {
		res, _ := doCred(t, e, "tok-two", "GET", lim, nil, nil)
		if res.StatusCode != 200 {
			t.Fatalf("session B request %d denied by session A's bucket: %q", i, denyReason(res))
		}
	}
	res, _ = doCred(t, e, "tok-two", "GET", lim, nil, nil)
	if res.StatusCode != http.StatusForbidden || denyReason(res) != "LIMIT_RATE" {
		t.Fatalf("session B's own burst did not exhaust at 6: status=%d reason=%q",
			res.StatusCode, denyReason(res))
	}
}

// --- C3.5.3 -------------------------------------------------------------
// The streamed body cap holds under every framing and timing (04 §1): a
// deferred body of exactly maxRequestBodyBytes arrives complete; one byte
// over is denied mid-write with at most the cap delivered upstream and
// result.error "limit-body". Upstream bytes are attributed per request —
// a denied request's accounting lands only when the aborted connection
// unblocks the upstream's ReadAll, so a cumulative counter delta can
// borrow bytes that belong to a neighbour request.
func TestC353StreamingBodyCap(t *testing.T) {
	ce := startCredEnv(t, m35Grants, nil)
	e := ce.env
	h1c := e.proxyClient(t, "tok-one", e.combinedPool(t, "s1"), "http/1.1")
	h2c := e.proxyClient(t, "tok-one", e.combinedPool(t, "s1"))
	s2c := e.proxyClient(t, "tok-two", e.combinedPool(t, "s2"), "http/1.1")

	// stream POSTs n zero bytes to url through cl — chunked when
	// declared < 0, a declared Content-Length otherwise — and returns
	// the response plus the request's slot in sink's ledger, so its body
	// count is attributed to this request and no other.
	stream := func(cl *http.Client, sink *headerSink, url string, n, declared int64) (*http.Response, int) {
		t.Helper()
		c0 := sink.count()
		req, err := http.NewRequest("POST", url, io.NopCloser(io.LimitReader(zeroReader{}, n)))
		if err != nil {
			t.Fatal(err)
		}
		req.ContentLength = declared
		if declared < 0 {
			req.TransferEncoding = []string{"chunked"}
		}
		res, err := cl.Do(req)
		if err != nil {
			t.Fatalf("stream request: %v", err)
		}
		_ = res.Body.Close()
		return res, c0
	}
	// delivered returns the body bytes upstream attributed to request i;
	// a mid-write denial's entry lands when the conn abort unblocks the
	// upstream's ReadAll, which can lag the client's 403.
	delivered := func(sink *headerSink, i int) int64 {
		t.Helper()
		sink.waitSeen(i, 3*time.Second)
		return sink.bodyLenAt(i)
	}

	// 1.1 chunked, exactly at the cap: allowed and complete upstream.
	res, i := stream(h1c, ce.anthro, "https://api.anthropic.com/lim/stream", 4096, -1)
	if res.StatusCode != 200 {
		t.Fatalf("at-limit chunked denied: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
	if got := delivered(ce.anthro, i); got != 4096 {
		t.Fatalf("at-limit chunked incomplete: upstream got %d of 4096", got)
	}
	// Over the cap: denied mid-write, at most the cap delivered.
	for _, n := range []int64{4097, 8192} {
		res, i = stream(h1c, ce.anthro, "https://api.anthropic.com/lim/stream", n, -1)
		if res.StatusCode != http.StatusForbidden || denyReason(res) != "LIMIT_BODY" {
			t.Fatalf("chunked %d over limit: status=%d reason=%q", n, res.StatusCode, denyReason(res))
		}
		if got := delivered(ce.anthro, i); got > 4096 {
			t.Fatalf("chunked %d: upstream received %d bytes, cap is 4096", n, got)
		}
	}

	// 1.1 declared Content-Length, deferred (> bufferLimit): at cap
	// complete; one over is denied pre-wire — no upstream request.
	res, i = stream(h1c, ce.anthro, "https://api.anthropic.com/lim/stream", 4096, 4096)
	if res.StatusCode != 200 {
		t.Fatalf("at-limit declared denied: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
	if got := delivered(ce.anthro, i); got != 4096 {
		t.Fatalf("at-limit declared incomplete: upstream got %d of 4096", got)
	}
	res, i = stream(h1c, ce.anthro, "https://api.anthropic.com/lim/stream", 4097, 4097)
	if res.StatusCode != http.StatusForbidden || denyReason(res) != "LIMIT_BODY" {
		t.Fatalf("declared 4097: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
	if ce.anthro.count() != i {
		t.Fatal("declared over-limit reached upstream")
	}

	// h2 DATA frames end to end (both legs h2 on h2.anthropic.example):
	// same boundary — at cap complete, over cap ≤ cap upstream.
	res, i = stream(h2c, ce.h2, "https://h2.anthropic.example/lim/stream", 4096, -1)
	if res.StatusCode != 200 {
		t.Fatalf("at-limit h2 denied: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
	if got := delivered(ce.h2, i); got != 4096 {
		t.Fatalf("at-limit h2 incomplete: upstream got %d of 4096", got)
	}
	res, i = stream(h2c, ce.h2, "https://h2.anthropic.example/lim/stream", 8192, -1)
	if res.StatusCode != http.StatusForbidden || denyReason(res) != "LIMIT_BODY" {
		t.Fatalf("h2 8192 over limit: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
	if got := delivered(ce.h2, i); got > 4096 {
		t.Fatalf("h2 8192: upstream received %d bytes, cap is 4096", got)
	}

	// Concurrency: two sessions streaming over the cap simultaneously —
	// each request's own delivery is still ≤ cap.
	c0 := ce.anthro.count()
	resCh := make(chan *http.Response, 2)
	var wg sync.WaitGroup
	for _, cl := range []*http.Client{h1c, s2c} {
		wg.Add(1)
		go func(c *http.Client) {
			defer wg.Done()
			req, err := http.NewRequest("POST", "https://api.anthropic.com/lim/stream",
				io.NopCloser(io.LimitReader(zeroReader{}, 8192)))
			if err != nil {
				resCh <- nil
				return
			}
			req.ContentLength = -1
			req.TransferEncoding = []string{"chunked"}
			res, err := c.Do(req)
			if err != nil {
				resCh <- nil
				return
			}
			resCh <- res
		}(cl)
	}
	wg.Wait()
	close(resCh)
	nres := 0
	for res := range resCh {
		nres++
		if res == nil {
			t.Fatal("concurrent stream request failed")
		}
		if res.StatusCode != http.StatusForbidden || denyReason(res) != "LIMIT_BODY" {
			t.Fatalf("concurrent over-limit: status=%d reason=%q", res.StatusCode, denyReason(res))
		}
		_ = res.Body.Close()
	}
	if nres != 2 {
		t.Fatalf("concurrent streams: %d responses, want 2", nres)
	}
	if !ce.anthro.waitSeen(c0+1, 3*time.Second) {
		t.Fatal("concurrent over-limit requests never reached upstream")
	}
	for j := c0; j <= c0+1; j++ {
		if got := ce.anthro.bodyLenAt(j); got > 4096 || got < 0 {
			t.Fatalf("concurrent stream %d: upstream received %d bytes, cap is 4096", j, got)
		}
	}

	// The result record lands in the handler's defer — poll briefly.
	var resErr string
	for i := 0; i < 50; i++ {
		recs := recordsOfType[ResultBody](t, e.readSessionRecords(t, "s1"), "effect.http.result")
		for j := len(recs) - 1; j >= 0; j-- {
			if recs[j].Error == "limit-body" {
				resErr = recs[j].Error
			}
		}
		if resErr != "" {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if resErr != "limit-body" {
		t.Fatalf("result.error = %q, want limit-body", resErr)
	}
}

// zeroReader is an infinite zero source (LimitReader caps it).
type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = '0'
	}
	return len(b), nil
}

// --- C3.5.4 -------------------------------------------------------------
// Redirects: the broker never follows them — the 3xx reaches the client
// and the follow-up is evaluated on its own grant. A redirect off a
// credentialed host therefore carries no credential.
func TestC354Redirects(t *testing.T) {
	ce := startCredEnv(t, m35Grants, nil)
	e := ce.env

	target := "https://pypi.org/other"
	client := e.proxyClient(t, "tok-one", e.combinedPool(t, "s1"))
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	res, err := client.Get("https://api.anthropic.com/redir?to=" + url.QueryEscape(target))
	if err != nil {
		t.Fatalf("redirect request: %v", err)
	}
	rbody, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("status %d, want the raw 302", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != target {
		t.Fatalf("Location = %q, want %q", loc, target)
	}
	canaryFree(t, "redirect response", rbody)

	// Follow-up on the new host: evaluated on the pypi grant — no
	// credential material crosses.
	res2, _ := doCred(t, e, "tok-one", "GET", target, nil, nil)
	if res2.StatusCode != 200 {
		t.Fatalf("follow-up status %d reason=%q", res2.StatusCode, denyReason(res2))
	}
	l := ce.pypi.last()
	if l.Get("X-Api-Key") != "" || l.Get("Authorization") != "" {
		t.Fatalf("credential followed the redirect to another host")
	}
	// And the redirect source itself injected as usual (credentialed
	// grant on api.anthropic.com).
	if got := ce.anthro.last().Get("X-Api-Key"); got != fxlib.Canary("anthropic") {
		t.Fatalf("redirect source grant did not inject")
	}
}
