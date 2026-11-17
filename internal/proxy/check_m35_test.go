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
	pad := strings.Repeat("a", 87)
	res, _ := doCred(t, e, "tok-one", "GET", "https://api.anthropic.com/lim/"+pad+"?abcd", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("at-limit URL denied: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
	res, body := doCred(t, e, "tok-one", "GET", "https://api.anthropic.com/lim/"+pad+"?abcde", nil, nil)
	if res.StatusCode != http.StatusForbidden || denyReason(res) != "LIMIT_URL" {
		t.Fatalf("over-limit URL: status=%d reason=%q body=%s", res.StatusCode, denyReason(res), body)
	}
	// The URL rule sees the QUERY too (sabotage target): a path alone
	// under the limit is denied once the query pushes it over.
	res, _ = doCred(t, e, "tok-one", "GET",
		"https://api.anthropic.com/lim/u?"+strings.Repeat("q", 91), nil, nil)
	if res.StatusCode != http.StatusForbidden || denyReason(res) != "LIMIT_URL" {
		t.Fatalf("query-pushed URL: status=%d reason=%q", res.StatusCode, denyReason(res))
	}

	// Body: limit 100 via declared length.
	res, _ = doCred(t, e, "tok-one", "POST", "https://api.anthropic.com/lim/b",
		nil, bytes.Repeat([]byte{'x'}, 100))
	if res.StatusCode != 200 {
		t.Fatalf("at-limit body denied: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
	res, _ = doCred(t, e, "tok-one", "POST", "https://api.anthropic.com/lim/b",
		nil, bytes.Repeat([]byte{'x'}, 101))
	if res.StatusCode != http.StatusForbidden || denyReason(res) != "LIMIT_BODY" {
		t.Fatalf("over-limit body: status=%d reason=%q", res.StatusCode, denyReason(res))
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
	// Session B on the same grant: unaffected (own table).
	res, _ := doCred(t, e, "tok-two", "GET", lim, nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("session B denied by session A's rate: reason=%q", denyReason(res))
	}
	// Session A on another grant: unaffected (bucket is per grant).
	res, _ = doCred(t, e, "tok-one", "GET", "https://api.anthropic.com/open-r", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("other grant denied by lim's rate: reason=%q", denyReason(res))
	}
}

// --- C3.5.3 -------------------------------------------------------------
// The body cap holds while streaming: with a deferred (chunked, >buffer)
// body the upstream receives at most the limit, the wire write aborts,
// and the result record carries error "limit-body".
func TestC353StreamingBodyCap(t *testing.T) {
	ce := startCredEnv(t, m35Grants, nil)
	e := ce.env

	before := ce.anthro.bodyBytes()
	// Chunked 8 KiB body — length unknown, so the broker buffers up to
	// the grant's 1 KiB bufferLimit and streams the rest; the cap is 4 KiB.
	// h1 on the tunnel leg: chunked needs a protocol that has chunks.
	client := e.proxyClient(t, "tok-one", e.combinedPool(t, "s1"), "http/1.1")
	req, err := http.NewRequest("POST", "https://api.anthropic.com/lim/stream",
		io.NopCloser(io.LimitReader(zeroReader{}, 8192)))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("stream request: %v", err)
	}
	_ = res.Body.Close()

	if res.StatusCode != http.StatusForbidden || denyReason(res) != "LIMIT_BODY" {
		t.Fatalf("streaming over-limit: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
	got := ce.anthro.bodyBytes() - before
	if got > 4096 {
		t.Fatalf("upstream received %d bytes, cap is 4096", got)
	}
	// The result record lands in the handler's defer — poll briefly.
	var resErr string
	for i := 0; i < 50; i++ {
		recs := recordsOfType[ResultBody](t, e.readSessionRecords(t, "s1"), "effect.http.result")
		if len(recs) > 0 {
			resErr = recs[len(recs)-1].Error
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
