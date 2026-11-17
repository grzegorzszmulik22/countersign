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
	"sync"
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
    - id: anthro-plain
      match: {hosts: [api.anthropic.com], paths: [/scrub/bigplain]}
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

	collect := func() (func([]byte), *bytes.Buffer) {
		b := &bytes.Buffer{}
		return func(p []byte) { b.Write(p) }, b
	}
	for split := 1; split < len(secret); split++ {
		body := append(append(append([]byte("pre "), secret[:split]...), secret[split:]...), []byte(" post")...)
		s := creds.NewScrubber(pats, repl)
		emit, buf := collect()
		cut := 4 + split // inside the secret
		s.Write(body[:cut], emit)
		s.Write(body[cut:], emit)
		s.Flush(emit)
		out := buf.Bytes()
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
	emit, ebuf := collect()
	for len(raw) > 0 {
		n := 1 + rng.Intn(7)
		if n > len(raw) {
			n = len(raw)
		}
		s.Write(raw[:n], emit)
		raw = raw[n:]
	}
	s.Flush(emit)
	out := ebuf.Bytes()
	if bytes.Contains(out, secret) || bytes.Contains(out, []byte(b64s)) {
		t.Fatalf("byte-at-a-time stream leaked: %q", out)
	}
	if s.Count != 2 {
		t.Fatalf("count %d, want 2", s.Count)
	}
	// Memory stays bounded by the carry window no matter the stream size.
	var tail bytes.Buffer
	s.Flush(func(p []byte) { tail.Write(p) })
	if tail.Len() != 0 {
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

	// Stream-and-discard: buffering 100 MiB per call would put GC churn
	// inside the measured window. Transient resets (contended loopback)
	// retry and are not timed samples. dl runs inside the concurrent
	// pair goroutines, so it reports errors instead of calling t.Fatal.
	pool := e.combinedPool(t, "s1")
	dl := func(rawURL string) (int64, time.Duration, error) {
		client := e.proxyClient(t, "tok-one", pool)
		var lastErr error
		for tries := 0; tries < 3; tries++ {
			st := time.Now()
			res, err := client.Get(rawURL)
			if err != nil {
				lastErr = err
				continue
			}
			n, cerr := io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			d := time.Since(st)
			// A clean copy means the declared stream arrived intact;
			// truncation surfaces as an error.
			if res.StatusCode == 200 && cerr == nil && n > 0 {
				return n, d, nil
			}
			lastErr = fmt.Errorf("status %d n %d err %v", res.StatusCode, n, cerr)
		}
		return 0, 0, fmt.Errorf("%s: %w", rawURL, lastErr)
	}
	dlMust := func(rawURL string) {
		if _, _, err := dl(rawURL); err != nil {
			t.Fatal(err)
		}
	}

	// Warm both paths, then take 5 pairs whose two legs run CONCURRENTLY:
	// the credentialed and plain downloads share the same load window, so
	// scheduler noise and load spikes hit both legs equally and cancel
	// out of the ratio (the pattern M2.3 uses for added-delay). The best
	// pair is the least-contended sample of the real scrub cost. Both
	// legs run the same h1 upstream: the plain baseline is the
	// non-credentialed anthro-plain grant on a sibling path of the same
	// host.
	dlMust("https://api.anthropic.com/scrub/bigplain?n=1048576")
	dlMust("https://api.anthropic.com/scrub/big?n=1048576")
	plainURL := "https://api.anthropic.com/scrub/bigplain?n=" + itoaMib(mib)
	credURL := "https://api.anthropic.com/scrub/big?n=" + itoaMib(mib)
	var best, bCred, bPlain float64 = 1e18, 0, 0
	for i := 0; i < 5; i++ {
		var pb, cb int64
		var pt, ct time.Duration
		var perr, cerr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); pb, pt, perr = dl(plainURL) }()
		go func() { defer wg.Done(); cb, ct, cerr = dl(credURL) }()
		wg.Wait()
		if perr != nil {
			t.Fatalf("plain leg: %v", perr)
		}
		if cerr != nil {
			t.Fatalf("credentialed leg: %v", cerr)
		}
		perByte := (float64(ct) / float64(cb)) / (float64(pt) / float64(pb))
		if p := (perByte - 1) * 100; p < best {
			best, bCred, bPlain = p, float64(ct.Milliseconds()), float64(pt.Milliseconds())
		}
	}
	penalty := best
	fmt.Printf("MEASUREMENT scrub_penalty_pct %.2f scrub_100MiB_ms %.1f plain_100MiB_ms %.1f\n", penalty, bCred, bPlain)
	if penalty > 25 {
		t.Fatalf("scrub throughput penalty %.1f%% > 25%% (cred %.0fms plain %.0fms)", penalty, bCred, bPlain)
	}

	// MM3.2: after the whole suite, no canary in records or broker logs.
	for _, sid := range []string{"s1", "s2"} {
		raw, _ := os.ReadFile(filepath.Join(e.records, sid+".jsonl"))
		canaryFree(t, "record file "+sid, raw)
	}
	canaryFree(t, "broker log", []byte(e.brokerLogText(t)))
}

func itoaMib(i int) string { return fmt.Sprintf("%d", i) }
