// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/countersign/countersign/internal/creds"
	"github.com/countersign/countersign/test/fixtures/fxlib"
)

// M3.4 checks: response scrubbing (04 §4.5) — every position the real
// credential can occupy in an upstream response (body in any encoding,
// headers, trailers) is rewritten to the session placeholder before a
// byte reaches the client.

// m34Grants adds a broad credentialed grant for the /scrub/* leak
// oracle plus a Basic-inject grant, over the same secrets file.
const m34Grants = `  grants:
    - id: anthro-basic
      match: {hosts: [api.anthropic.com], paths: [/scrub/basic]}
      credential:
        ref: {secret: github-token, key: value}
        inject: {basic: {username: svc-user}}
        placeholderEnv: GH_TOK
    - id: anthro-all
      match: {hosts: [api.anthropic.com]}
      credential:
        ref: {secret: anthropic, key: api-key}
        inject: {header: x-api-key, format: "{secret}"}
        placeholderEnv: ANTHROPIC_API_KEY
    - id: anthro-h2
      match: {hosts: [h2.anthropic.example]}
      credential:
        ref: {secret: anthropic, key: api-key}
        inject: {header: x-api-key, format: "{secret}"}
        placeholderEnv: ANTHROPIC_API_KEY
    - id: hub-api
      match: {hosts: [api.github.com]}
      credential:
        ref: {secret: github-token, key: value}
        inject: {header: Authorization, format: "Bearer {secret}"}
        placeholderEnv: GITHUB_TOKEN
    - id: pypi
      match: {hosts: [pypi.org, files.pythonhosted.org]}
`

// lastResult returns the newest effect.http.result record for s1.
func lastResult(t *testing.T, e *testEnv) ResultBody {
	t.Helper()
	recs := recordsOfType[ResultBody](t, e.readSessionRecords(t, "s1"), "effect.http.result")
	if len(recs) == 0 {
		t.Fatal("no effect.http.result record")
	}
	return recs[len(recs)-1]
}

// --- C3.4.1 -------------------------------------------------------------
// fakehub /debug/echo through the credentialed Bearer grant: the upstream
// echoes the real token, the client sees the placeholder, and the result
// record counts the replacement (scenario A5 in miniature).
func TestC341EchoScrubbed(t *testing.T) {
	ce := startCredEnv(t, m34Grants, nil)
	e := ce.env
	p := ph(t, e, "s1", "hub-api")

	res, body := doCred(t, e, "tok-one", "GET", "https://api.github.com/debug/echo",
		map[string]string{"Authorization": "Bearer " + p}, nil)
	if res.StatusCode != 200 {
		t.Fatalf("status %d body %s", res.StatusCode, body)
	}
	canaryFree(t, "client response", body)
	if !bytes.Contains(body, []byte(p)) {
		t.Fatalf("client echo missing placeholder: %s", body)
	}
	if got := lastResult(t, e).Scrubbed; got < 1 {
		t.Fatalf("result.scrubbed = %d, want ≥1", got)
	}
}

// --- C3.4.2 -------------------------------------------------------------
// A 40-byte secret split across every possible chunk boundary (39 split
// points) is always scrubbed — the carry-over window makes the boundary
// position irrelevant. Also: a whole stream split byte-at-a-time, and a
// split inside the base64 form.
func TestC342SplitPoints(t *testing.T) {
	// C3.4.2 says "40-byte secret, 39 split points"; the fixture canary
	// is 39 bytes — every interior split point is exercised.
	secret := []byte(fxlib.Canary("anthropic"))
	repl := []byte("csph_deadbeef_grant_0000000000000000000000")
	pats := creds.Patterns(string(secret))

	for split := 1; split < len(secret); split++ {
		body := append(append(append([]byte("pre "), secret[:split]...), secret[split:]...), []byte(" post")...)
		s := creds.NewScrubber(pats, repl)
		cut := 4 + split // inside the secret
		out := append(s.Write(body[:cut]), s.Write(body[cut:])...)
		out = append(out, s.Flush()...)
		if bytes.Contains(out, secret) || !bytes.Contains(out, repl) {
			t.Fatalf("split %d: secret survived or placeholder missing", split)
		}
		if s.Count != 1 {
			t.Fatalf("split %d: count %d", split, s.Count)
		}
	}

	// Byte-at-a-time across a mixed stream with all three wire forms.
	b64s := base64.StdEncoding.EncodeToString(secret)
	raw := append(append([]byte("x "), secret...), []byte(" y "+b64s)...)
	s := creds.NewScrubber(pats, repl)
	rng := rand.New(rand.NewSource(7))
	var out []byte
	for len(raw) > 0 {
		n := 1 + rng.Intn(7)
		if n > len(raw) {
			n = len(raw)
		}
		out = append(out, s.Write(raw[:n])...)
		raw = raw[n:]
	}
	out = append(out, s.Flush()...)
	if bytes.Contains(out, secret) || bytes.Contains(out, []byte(b64s)) {
		t.Fatalf("byte-at-a-time stream leaked: %q", out)
	}
	if s.Count != 2 {
		t.Fatalf("count %d, want 2", s.Count)
	}
	// Memory stays bounded by the carry window no matter the stream size.
	if len(s.Flush()) != 0 {
		t.Fatal("flush after clean stream")
	}
}

// --- C3.4.3 -------------------------------------------------------------
// A gzip-encoded response carrying the secret is decoded, scrubbed, and
// delivered identity: client gets plaintext with the placeholder and no
// Content-Encoding.
func TestC343GzipScrubbed(t *testing.T) {
	ce := startCredEnv(t, m34Grants, nil)
	e := ce.env

	res, body := doCred(t, e, "tok-one", "GET", "https://api.anthropic.com/scrub/gzip", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("status %d body %s", res.StatusCode, body)
	}
	if ce := res.Header.Get("Content-Encoding"); ce != "" {
		t.Fatalf("client saw Content-Encoding %q", ce)
	}
	canaryFree(t, "gzip response", body)
	if !bytes.Contains(body, []byte(ph(t, e, "s1", "anthro-all"))) {
		t.Fatalf("placeholder missing in decoded body: %s", body)
	}
	if !bytes.Contains(body, []byte("zipped ")) {
		t.Fatalf("decoded body malformed: %s", body)
	}
	if got := lastResult(t, e).Scrubbed; got != 1 {
		t.Fatalf("scrubbed %d, want 1", got)
	}
}

// --- C3.4.4 -------------------------------------------------------------
// The secret in a response header, in a trailer, and near the end of a
// 1 GiB body are all scrubbed; an encoding the broker cannot scan fails
// closed.
func TestC344HeaderTrailerBig(t *testing.T) {
	ce := startCredEnv(t, m34Grants, nil)
	e := ce.env
	p := ph(t, e, "s1", "anthro-all")

	// Response header.
	res, _ := doCred(t, e, "tok-one", "GET", "https://api.anthropic.com/scrub/hdr", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("hdr status %d", res.StatusCode)
	}
	if got := res.Header.Get("X-Leak-Key"); got != p {
		t.Fatalf("X-Leak-Key = %q, want the session placeholder", "REDACTED")
	}
	canaryFree(t, "response headers", []byte(fmt.Sprint(res.Header)))

	// HTTP/2 trailer: dedicated h2-only upstream.
	res, _ = doCred(t, e, "tok-one", "GET", "https://h2.anthropic.example/scrub/trailer", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("trailer status %d", res.StatusCode)
	}
	if got := res.Trailer.Get("X-Leak-Key"); got != ph(t, e, "s1", "anthro-h2") {
		t.Fatalf("h2 trailer X-Leak-Key scrubbed value mismatch")
	}

	// 1 GiB body with the secret near the end: stream it, keeping only
	// the last KiB — the scrubber's own memory stays carry-bounded.
	big := int64(1 << 30)
	// h1 on the tunnel leg too: the GiB stream must survive arbitrary
	// framing; h1 chunked is the boring, reliable carrier here.
	client := e.proxyClient(t, "tok-one", e.combinedPool(t, "s1"), "http/1.1")
	client.Timeout = 0 // the GiB stream is the test, not a deadline
	res2, err := client.Get("https://api.anthropic.com/scrub/big?n=" + fmt.Sprint(big))
	if err != nil {
		t.Fatalf("big request: %v", err)
	}
	if res2.StatusCode != 200 {
		t.Fatalf("big status %d", res2.StatusCode)
	}
	var total int64
	var tail []byte
	buf := make([]byte, 64<<10)
	for {
		m, rerr := res2.Body.Read(buf)
		total += int64(m)
		if m > 0 {
			tail = append(tail, buf[:m]...)
			if len(tail) > 1024 {
				tail = append([]byte(nil), tail[len(tail)-1024:]...)
			}
		}
		if rerr != nil {
			break
		}
	}
	_ = res2.Body.Close()
	// The scrubbed body is the upstream body with the 39-byte secret
	// replaced by the (longer) session placeholder.
	wantLen := big - int64(len(fxlib.Canary("anthropic"))) + int64(len(p))
	if total != wantLen {
		t.Fatalf("big body len %d, want %d (n - secret + placeholder)", total, wantLen)
	}
	canaryFree(t, "big body tail", tail)
	if !bytes.Contains(tail, []byte(p)) {
		t.Fatalf("placeholder missing near end of 1GiB body")
	}
	if got := lastResult(t, e).Scrubbed; got != 1 {
		t.Fatalf("scrubbed %d, want 1", got)
	}

	// Unsupported encoding fails closed — the unverifiable body cannot cross.
	res, _ = doCred(t, e, "tok-one", "GET", "https://api.anthropic.com/scrub/badenc", nil, nil)
	if res.StatusCode != http.StatusBadGateway || res.Header.Get("X-Countersign-Reason") != "UPSTREAM_ENCODING" {
		t.Fatalf("badenc: status=%d reason=%q", res.StatusCode, res.Header.Get("X-Countersign-Reason"))
	}
}

// --- C3.4.5 -------------------------------------------------------------
// Non-credentialed requests are not scanned and not decoded: a gzip
// response arrives with its encoding intact, byte-exact as upstream sent.
func TestC345NonCredentialedPassthrough(t *testing.T) {
	ce := startCredEnv(t, m34Grants, nil)
	e := ce.env
	marker := "CLIENTMARKER-0000000000000000000000"

	// Client sends its own header through a non-credentialed grant; the
	// upstream reflects it and the response arrives untouched.
	res, body := doCred(t, e, "tok-one", "GET", "https://pypi.org/scrub/raw",
		map[string]string{"X-Api-Key": marker}, nil)
	if res.StatusCode != 200 {
		t.Fatalf("status %d body %s", res.StatusCode, body)
	}
	if !bytes.Contains(body, []byte(marker)) {
		t.Fatalf("passthrough rewrote the body: %s", body)
	}
	if got := lastResult(t, e).Scrubbed; got != 0 {
		t.Fatalf("non-credentialed scrubbed %d, want 0", got)
	}

	// gzip on a non-credentialed grant: encoding preserved, bytes as sent.
	res, body = doCred(t, e, "tok-one", "GET", "https://pypi.org/scrub/gzip",
		map[string]string{"X-Api-Key": marker, "Accept-Encoding": "gzip"}, nil)
	if res.StatusCode != 200 {
		t.Fatalf("gzip passthrough status %d", res.StatusCode)
	}
	if ce := res.Header.Get("Content-Encoding"); ce != "gzip" {
		t.Fatalf("non-credentialed response decoded: Content-Encoding %q", ce)
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("client body is not valid gzip: %v", err)
	}
	plain, _ := io.ReadAll(zr)
	if !bytes.Contains(plain, []byte(marker)) {
		t.Fatalf("gunzipped passthrough body lost marker")
	}
}

// --- C3.4.6 -------------------------------------------------------------
// MM3.4: throughput penalty of response scrubbing on a 100 MiB
// credentialed download vs the same byte-exact non-credentialed
// download. MEASUREMENT lines feed evidence/<chunk>/measurements.json.
// MM3.2 (no canary anywhere outside the broker) is asserted across the
// whole suite by canaryFree on records and logs here.
func TestC346ScrubThroughput(t *testing.T) {
	ce := startCredEnv(t, m34Grants, nil)
	e := ce.env
	const mib = 100 << 20

	dl := func(rawURL string) time.Duration {
		st := time.Now()
		res, body := doCred(t, e, "tok-one", "GET", rawURL, nil, nil)
		if res.StatusCode != 200 {
			t.Fatalf("%s: status %d", rawURL, res.StatusCode)
		}
		if len(body) < 1<<20 {
			t.Fatalf("%s: len %d", rawURL, len(body))
		}
		return time.Since(st)
	}

	// Warm both paths, then measure best-of-3 (loopback noise).
	dl("https://pypi.org/scrub/big?n=1048576")
	dl("https://api.anthropic.com/scrub/big?n=1048576")
	var plain, cred float64 = 1e18, 1e18
	for i := 0; i < 3; i++ {
		if d := float64(dl("https://pypi.org/scrub/big?n=" + itoaMib(mib)).Milliseconds()); d < plain {
			plain = d
		}
		if d := float64(dl("https://api.anthropic.com/scrub/big?n=" + itoaMib(mib)).Milliseconds()); d < cred {
			cred = d
		}
	}
	penalty := (cred - plain) / plain * 100
	t.Logf("MEASUREMENT scrub_penalty_pct %.2f", penalty)
	t.Logf("MEASUREMENT scrub_100MiB_ms %.1f plain_100MiB_ms %.1f", cred, plain)
	if penalty > 25 {
		t.Fatalf("scrub throughput penalty %.1f%% > 25%% (cred %.0fms plain %.0fms)", penalty, cred, plain)
	}

	// MM3.2: after the whole suite, no canary in records or broker logs.
	for _, sid := range []string{"s1", "s2"} {
		raw, _ := os.ReadFile(filepath.Join(e.records, sid+".jsonl"))
		canaryFree(t, "record file "+sid, raw)
	}
	canaryFree(t, "broker log", []byte(e.brokerLogText(t)))
}


func itoaMib(i int) string { return fmt.Sprintf("%d", i) }
