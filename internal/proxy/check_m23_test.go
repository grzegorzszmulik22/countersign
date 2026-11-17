// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package proxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// m23Grants grants the streaming test hosts.
const m23Grants = `  grants:
    - id: any
      match: {hosts: ["*"]}
`

// patternReader generates a deterministic position-dependent byte stream
// without storing it (1 GiB measurement bodies are generated, never
// written to files).
type patternReader struct{ pos, n int64 }

func (r *patternReader) Read(b []byte) (int, error) {
	if r.pos >= r.n {
		return 0, io.EOF
	}
	m := int64(len(b))
	if r.pos+m > r.n {
		m = r.n - r.pos
	}
	for i := int64(0); i < m; i++ {
		b[i] = patternByte(r.pos + i)
	}
	r.pos += m
	return int(m), nil
}

func patternByte(i int64) byte { return byte((uint64(i) * 2654435761) >> 24) }

// patternSHA computes the expected sha256 of the first n pattern bytes.
func patternSHA(n int64) [32]byte {
	h := sha256.New()
	_, _ = io.Copy(h, &patternReader{n: n})
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// patternSHAHex is patternSHA rendered as hex.
func patternSHAHex(n int64) string {
	sum := patternSHA(n)
	return hex.EncodeToString(sum[:])
}

// hashSink reads the whole request body and reports its digest — the
// "digest seen by upstream" arm of C2.3.1.
type hashSink struct{}

func (h *hashSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sum := sha256.New()
	n, _ := io.Copy(sum, r.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = fmt.Fprintf(w, `{"body_sha256":%q,"body_len":%d}`, hex.EncodeToString(sum.Sum(nil)), n)
}

// patternSource streams n pattern bytes downstream with an X-Body-Len
// trailer (also exercises trailer preservation, M2.3).
type patternSource struct{ n int64 }

func (p *patternSource) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Trailer", "X-Body-Len")
	w.WriteHeader(200)
	// Flush before the first body byte: commits chunked framing so the
	// trailer is on the wire for every size.
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	_, _ = io.Copy(w, &patternReader{n: p.n})
	w.Header().Set("X-Body-Len", strconv.FormatInt(p.n, 10))
}

// --- C2.3.1 ---------------------------------------------------------------
// Byte equality: for bodies of 0, 1, 1 KiB, 1 MiB, 1 MiB+1 and 1 GiB, the
// digest upstream saw equals what the client sent and what the result
// record holds — request (upload) and response (download) directions.
func TestC231ByteEquality(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", m23Grants)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)

	sink := &hashSink{}
	sinkAddr, closeSink := startTLSUpstream(t, e.ca, []string{"sink.example"}, nil, sink)
	defer closeSink()
	routes["sink.example"] = sinkAddr

	sizes := []int64{0, 1, 1 << 10, 1 << 20, (1 << 20) + 1, 1 << 30}
	cli := e.proxyClient(t, "tok-one", e.combinedPool(t, "s1"), "http/1.1")
	for _, n := range sizes {
		body := &patternReader{n: n}
		req, err := http.NewRequest("POST", "https://sink.example/up", body)
		if err != nil {
			t.Fatal(err)
		}
		req.ContentLength = n
		req.Header.Set("Content-Type", "application/octet-stream")
		res, err := cli.Do(req)
		if err != nil {
			t.Fatalf("upload %d: %v", n, err)
		}
		var doc struct {
			SHA string `json:"body_sha256"`
			Len int64  `json:"body_len"`
		}
		if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
			t.Fatalf("upload %d decode: %v", n, err)
		}
		_ = res.Body.Close()
		want := patternSHAHex(n)
		if doc.SHA != want {
			t.Errorf("upload %d: upstream saw %s, want %s", n, doc.SHA, want)
		}
		if doc.Len != n {
			t.Errorf("upload %d: upstream len %d", n, doc.Len)
		}
	}

	// Each upload's result record carries the same digest both ends saw.
	for _, n := range sizes {
		if !hasResultRecord(t, e, "s1", n, true) {
			t.Errorf("upload %d: no result record with matching request_body", n)
		}
	}

	// Download direction.
	dlAddr, closeDL := startTLSUpstream(t, e.ca, []string{"dl.example"}, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/dl/"), 10, 64)
		(&patternSource{n: n}).ServeHTTP(w, r)
	}))
	defer closeDL()
	routes["dl.example"] = dlAddr
	for _, n := range sizes {
		res, err := cli.Get(fmt.Sprintf("https://dl.example/dl/%d", n))
		if err != nil {
			t.Fatalf("download %d: %v", n, err)
		}
		got := sha256.New()
		m, err := io.Copy(got, res.Body)
		_ = res.Body.Close()
		if err != nil {
			t.Fatalf("download %d read: %v", n, err)
		}
		if m != n {
			t.Fatalf("download %d: got %d bytes", n, m)
		}
		if tl := res.Trailer.Get("X-Body-Len"); tl != strconv.FormatInt(n, 10) {
			t.Errorf("download %d: trailer X-Body-Len %q", n, tl)
		}
		if hex.EncodeToString(got.Sum(nil)) != patternSHAHex(n) {
			t.Errorf("download %d: client digest mismatch", n)
		}
	}
	for _, n := range sizes {
		if !hasResultRecord(t, e, "s1", n, false) {
			t.Errorf("download %d: no result record with matching response body", n)
		}
	}
}

// hasResultRecord waits until a result record with the expected digest
// exists (request side when req=true, response side otherwise).
func hasResultRecord(t *testing.T, e *testEnv, sessionID string, n int64, req bool) bool {
	t.Helper()
	want := patternSHAHex(n)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		for _, r := range recordsOfType[ResultBody](t, e.readSessionRecords(t, sessionID), "effect.http.result") {
			if req {
				if r.RequestBody.Len == n && r.RequestBody.SHA256 == want {
					return true
				}
			} else if r.Response.BodyLen == n && r.Response.BodySHA256 == want {
				return true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// waitForResults polls until at least n effect.http.result records exist.
func waitForResults(t *testing.T, e *testEnv, sessionID string, n int) []ResultBody {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		rs := recordsOfType[ResultBody](t, e.readSessionRecords(t, sessionID), "effect.http.result")
		if len(rs) >= n {
			return rs
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d result records", n)
	return nil
}

// --- C2.3.2 ---------------------------------------------------------------
// SSE: 1,000 events at 10 ms spacing arrive as 1,000 distinct reads; MM2.3.
func TestC232SSEFlush(t *testing.T) {
	// The whole chain (upstream, broker, client) runs in this process;
	// a GC stop-the-world lands on every hop at once and shows up as
	// added delay that is not the broker's. Freeze it for the window.
	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", m23Grants)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)

	const N = 1000
	sse := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fl := w.(http.Flusher)
		for i := 0; i < N; i++ {
			// The payload carries the event index and the upstream flush
			// instant so per-event delay is measurable end to end.
			_, _ = fmt.Fprintf(w, "data: %d:%d\n\n", i, time.Now().UnixNano())
			fl.Flush()
			if i != N-1 {
				time.Sleep(10 * time.Millisecond)
			}
		}
	})
	addr, closeUp := startTLSUpstream(t, e.ca, []string{"sse.example"}, nil, sse)
	defer closeUp()
	routes["sse.example"] = addr

	// Control arm: the identical stream direct to the upstream. MM2.3's
	// "added per-event delay" is the delay the broker adds — subtracting
	// the concurrent direct-path delay removes scheduler noise that the
	// broker does not cause (a shared host or a GC pause inflates both
	// arms equally).
	direct := &http.Client{Transport: &http.Transport{
		ForceAttemptHTTP2: false,
		TLSClientConfig:   &tls.Config{RootCAs: e.ca.Pool(), NextProtos: []string{"http/1.1"}},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}
	proxied := e.proxyClient(t, "tok-one", e.combinedPool(t, "s1"), "http/1.1")

	readStream := func(cli *http.Client) ([]float64, int, int, int, error) {
		res, err := cli.Get("https://sse.example/sse")
		if err != nil {
			return nil, 0, 0, 0, err
		}
		defer func() { _ = res.Body.Close() }()
		var (
			events, reads, coalesced int
			delays                   = make([]float64, N)
			pending                  []byte
		)
		buf := make([]byte, 1<<16)
		for events < N {
			n, rerr := res.Body.Read(buf)
			readAt := time.Now()
			if n > 0 {
				reads++
				data := append(pending, buf[:n]...)
				var evs [][]byte
				for {
					i := bytesIndex(data, []byte("\n\n"))
					if i < 0 {
						break
					}
					evs = append(evs, data[:i])
					data = data[i+2:]
				}
				pending = append(pending[:0], data...)
				if len(evs) > 1 {
					coalesced += len(evs) - 1
				}
				for _, ev := range evs {
					events++
					var seq int
					var ts int64
					if _, perr := fmt.Sscanf(strings.TrimPrefix(string(ev), "data: "), "%d:%d", &seq, &ts); perr == nil {
						delays[seq] = float64(readAt.UnixNano()-ts) / 1e6
					}
				}
			}
			if rerr != nil {
				return delays, reads, coalesced, events, rerr
			}
		}
		return delays, reads, coalesced, events, nil
	}

	start := time.Now()
	type out struct {
		delays               []float64
		reads, coalesced, ev int
		err                  error
	}
	pch, dch := make(chan out, 1), make(chan out, 1)
	go func() { d, r, c, v, err := readStream(proxied); pch <- out{d, r, c, v, err} }()
	go func() { d, r, c, v, err := readStream(direct); dch <- out{d, r, c, v, err} }()
	p, d := <-pch, <-dch
	if p.err != nil && p.err != io.EOF {
		t.Fatalf("proxied stream: %v", p.err)
	}
	if d.err != nil && d.err != io.EOF {
		t.Fatalf("direct stream: %v", d.err)
	}
	if p.ev != N || d.ev != N {
		t.Fatalf("events proxied=%d direct=%d, want %d each", p.ev, d.ev, N)
	}
	// MM2.3: events coalesced ≤ 1% (the proxied stream must deliver
	// essentially one read per event).
	if p.coalesced > N/100 {
		t.Errorf("coalesced events = %d (>1%% of %d)", p.coalesced, N)
	}
	// MM2.3: p99 added delay ≤ 2 ms, with a wide absolute bound as
	// backstop (a held-back stream shows seconds, noise never does).
	added := make([]float64, N)
	abs := make([]float64, N)
	for i := 0; i < N; i++ {
		added[i] = p.delays[i] - d.delays[i]
		abs[i] = p.delays[i]
	}
	sort.Float64s(added)
	sort.Float64s(abs)
	dsrt := append([]float64(nil), d.delays...)
	sort.Float64s(dsrt)
	i99 := int(0.99 * float64(len(added)-1))
	p99 := added[i99]
	ap99 := abs[i99]
	if p99 > 2.0 {
		t.Errorf("p99 added delay %.3f ms > 2 ms (MM2.3; proxied p99 %.3f ms)", p99, ap99)
	}
	if ap99 > 25.0 {
		t.Errorf("p99 end-to-end delay %.3f ms: stream held back (MM2.3)", ap99)
	}
	t.Logf("SSE: %d events in %v (%d proxied reads), p99 added %.3f ms (proxied p99 %.3f, direct p99 %.3f), coalesced %d",
		N, time.Since(start), p.reads, p99, ap99, dsrt[i99], p.coalesced)
}

func bytesIndex(b, needle []byte) int {
	for i := 0; i+len(needle) <= len(b); i++ {
		if string(b[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}

// --- C2.3.3 ---------------------------------------------------------------
// Request body <= bufferLimit: body_sha256 and request_digest in the
// write-ahead effect.http. Larger: body_deferred, digest in the result.
func TestC233WriteAheadDigest(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", m23Grants)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)
	sinkAddr, closeSink := startTLSUpstream(t, e.ca, []string{"sink.example"}, nil, &hashSink{})
	defer closeSink()
	routes["sink.example"] = sinkAddr

	cli := e.proxyClient(t, "tok-one", e.combinedPool(t, "s1"), "http/1.1")
	for _, n := range []int64{1 << 10, (1 << 20) + 1} {
		req, err := http.NewRequest("POST", "https://sink.example/up", &patternReader{n: n})
		if err != nil {
			t.Fatal(err)
		}
		req.ContentLength = n
		req.Header.Set("Content-Type", "application/octet-stream")
		res, err := cli.Do(req)
		if err != nil {
			t.Fatalf("post %d: %v", n, err)
		}
		_ = res.Body.Close()
	}

	waitForResults(t, e, "s1", 2)
	effects := recordsOfType[EffectHTTPBody](t, e.readSessionRecords(t, "s1"), "effect.http")
	var small, big *EffectHTTPBody
	for i := range effects {
		ef := &effects[i]
		if ef.Decision.Action != "allow" {
			continue
		}
		if ef.Request.BodyLen == 1<<10 {
			small = ef
		} else if ef.Request.BodyLen == -1 || ef.Request.BodyDeferred {
			big = ef
		}
	}
	if small == nil {
		t.Fatal("no effect.http for the small request")
	}
	if small.Request.BodySHA256 != patternSHAHex(1<<10) {
		t.Errorf("small: write-ahead body_sha256 %q", small.Request.BodySHA256)
	}
	if small.RequestDigest == "" {
		t.Error("small: no request_digest in write-ahead record")
	} else {
		want := wantDigest("POST", "https", "sink.example", "/up", "", patternSHA(1<<10), "application/octet-stream")
		if small.RequestDigest != want {
			t.Errorf("small: request_digest %s, want %s", small.RequestDigest, want)
		}
	}
	if big == nil {
		t.Fatal("no effect.http for the >limit request")
	}
	if !big.Request.BodyDeferred {
		t.Error("big: body_deferred not set in write-ahead record")
	}
	if big.Request.BodySHA256 != "" || big.RequestDigest != "" {
		t.Error("big: digest must not be in the write-ahead record")
	}
	results := waitForResults(t, e, "s1", 2)
	var bigRes *ResultBody
	for i := range results {
		if results[i].RequestBody.Len == (1<<20)+1 {
			bigRes = &results[i]
		}
	}
	if bigRes == nil {
		t.Fatal("no result record for the deferred request")
	}
	if bigRes.RequestBody.SHA256 != patternSHAHex((1<<20)+1) {
		t.Errorf("big: result request sha %q", bigRes.RequestBody.SHA256)
	}
	if bigRes.ReqDigest != wantDigest("POST", "https", "sink.example", "/up", "", patternSHA((1<<20)+1), "application/octet-stream") {
		t.Errorf("big: result request_digest %q", bigRes.ReqDigest)
	}
}

// wantDigest independently recomputes the 04 §3 request digest.
func wantDigest(method, scheme, authority, path, query string, bodySHA [32]byte, contentType string) string {
	h := sha256.New()
	h.Write([]byte("countersign-request-v1\n"))
	h.Write([]byte(method + "\n"))
	h.Write([]byte(scheme + "\n"))
	h.Write([]byte(authority + "\n"))
	h.Write([]byte(path + "\n"))
	q := sha256.Sum256([]byte(query))
	h.Write([]byte(hex.EncodeToString(q[:]) + "\n"))
	h.Write([]byte(hex.EncodeToString(bodySHA[:]) + "\n"))
	if contentType != "" {
		h.Write([]byte("content-type:" + strings.TrimSpace(contentType) + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// --- C2.3.4 ---------------------------------------------------------------
// Client aborts mid-download: the upstream connection is closed within
// 1 s; the result record has error: client-abort and the partial count.
func TestC234ClientAbort(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", m23Grants)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)

	closedAt := make(chan time.Time, 1)
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fl := w.(http.Flusher)
		_, _ = w.Write(make([]byte, 4096))
		fl.Flush()
		// Drip until the client goes away.
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		deadline := time.After(30 * time.Second)
		for {
			select {
			case <-r.Context().Done():
				closedAt <- time.Now()
				return
			case <-deadline:
				return
			case <-tick.C:
				if _, err := w.Write(make([]byte, 512)); err != nil {
					closedAt <- time.Now()
					return
				}
				fl.Flush()
			}
		}
	})
	addr, closeUp := startTLSUpstream(t, e.ca, []string{"slow.example"}, nil, slow)
	defer closeUp()
	routes["slow.example"] = addr

	tc, _ := e.tunnelTLS(t, "tok-one", "slow.example:443", &tls.Config{RootCAs: e.combinedPool(t, "s1")})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := tc.Write([]byte("GET /big HTTP/1.1\r\nHost: slow.example\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(tc)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Read a little then slam the tunnel conn shut — a hard client abort.
	_, _ = io.CopyN(io.Discard, res.Body, 1024)
	abortAt := time.Now()
	_ = tc.Close()
	_ = res.Body.Close()

	select {
	case at := <-closedAt:
		if d := at.Sub(abortAt); d > time.Second {
			t.Errorf("upstream conn closed %v after abort (>1s)", d)
		}
	case <-time.After(3 * time.Second):
		t.Error("upstream never saw the connection close")
	}

	// The result record says client-abort with the partial byte count.
	var rec *ResultBody
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rs := recordsOfType[ResultBody](t, e.readSessionRecords(t, "s1"), "effect.http.result")
		for i := range rs {
			if rs[i].Error == "client-abort" {
				rec = &rs[i]
			}
		}
		if rec != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if rec == nil {
		t.Fatal("no client-abort result record")
	}
	if rec.Response.BodyLen <= 0 || rec.Response.BodyLen > 8*1024*1024 {
		t.Errorf("partial body_len %d", rec.Response.BodyLen)
	}
}

// --- C2.3.5 ---------------------------------------------------------------
// MM2.5: resident memory growth while relaying a 1 GiB body, either
// direction, stays under 64 MiB.
func TestC235MemoryBound(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", m23Grants)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)
	sinkAddr, closeSink := startTLSUpstream(t, e.ca, []string{"sink.example"}, nil, &hashSink{})
	defer closeSink()
	routes["sink.example"] = sinkAddr
	srcAddr, closeSrc := startTLSUpstream(t, e.ca, []string{"src.example"}, nil, &patternSource{n: 1 << 30})
	defer closeSrc()
	routes["src.example"] = srcAddr

	cli := e.proxyClient(t, "tok-one", e.combinedPool(t, "s1"), "http/1.1")

	rss := func() int64 {
		runtime.GC()
		b, err := os.ReadFile("/proc/self/status")
		if err != nil {
			t.Fatalf("read status: %v", err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				f := strings.Fields(line)
				kb, _ := strconv.ParseInt(f[1], 10, 64)
				return kb * 1024
			}
		}
		t.Fatal("VmRSS not found")
		return 0
	}

	const limit = 64 << 20
	before := rss()
	req, _ := http.NewRequest("POST", "https://sink.example/up", &patternReader{n: 1 << 30})
	req.ContentLength = 1 << 30
	res, err := cli.Do(req)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	_ = res.Body.Close()
	if d := rss() - before; d > limit {
		t.Errorf("upload RSS growth %d MiB > 64 MiB", d>>20)
	}

	before = rss()
	res, err = cli.Get("https://src.example/big")
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if d := rss() - before; d > limit {
		t.Errorf("download RSS growth %d MiB > 64 MiB", d>>20)
	}
}
