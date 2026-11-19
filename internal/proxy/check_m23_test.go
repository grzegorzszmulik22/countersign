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
	"sync"
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

// stallWatchdog returns a context that is canceled when no byte moves for
// the stall window, and a progress channel to ping on every read. The
// byte-equality and memory-bound checks assert correctness — equal
// digests, bounded RSS — never speed (throughput is MM2.5's measured
// number, reported rather than asserted through a request timeout), so
// the only deadline they carry is this one derived from bytes moved: a
// slow or contended host cannot trip it; only a hung relay can.
func stallWatchdog(stall time.Duration) (context.Context, chan<- struct{}, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ping := make(chan struct{}, 256)
	go func() {
		tm := time.NewTimer(stall)
		defer tm.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ping:
				if !tm.Stop() {
					select {
					case <-tm.C:
					default:
					}
				}
				tm.Reset(stall)
			case <-tm.C:
				cancel()
				return
			}
		}
	}()
	return ctx, ping, cancel
}

// beatReader pings the stall watchdog for every byte read — progress is
// what resets the hang deadline.
type beatReader struct {
	r    io.Reader
	ping chan<- struct{}
}

func (b *beatReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if n > 0 {
		select {
		case b.ping <- struct{}{}:
		default:
		}
	}
	return n, err
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
	dir := shmTempDir(t)
	pol := writePolicy(t, dir, "p", m23Grants)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)

	sink := &hashSink{}
	sinkAddr, closeSink := startTLSUpstream(t, e.ca, []string{"sink.example"}, nil, sink)
	defer closeSink()
	routes["sink.example"] = sinkAddr

	sizes := []int64{0, 1, 1 << 10, 1 << 20, (1 << 20) + 1, 1 << 30}
	cli := e.proxyClient(t, "tok-one", e.combinedPool(t, "s1"), "http/1.1")
	// Byte equality has no wall-clock budget: the only deadline is the
	// stall watchdog's, derived from bytes moved — it catches a hung
	// relay, never a slow host.
	cli.Timeout = 0
	for _, n := range sizes {
		ctx, ping, cancel := stallWatchdog(2 * time.Minute)
		req, err := http.NewRequestWithContext(ctx, "POST", "https://sink.example/up",
			&beatReader{r: &patternReader{n: n}, ping: ping})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		req.ContentLength = n
		req.Header.Set("Content-Type", "application/octet-stream")
		res, err := cli.Do(req)
		if err != nil {
			cancel()
			t.Fatalf("upload %d: %v", n, err)
		}
		var doc struct {
			SHA string `json:"body_sha256"`
			Len int64  `json:"body_len"`
		}
		derr := json.NewDecoder(res.Body).Decode(&doc)
		_ = res.Body.Close()
		cancel()
		if derr != nil {
			t.Fatalf("upload %d decode: %v", n, derr)
		}
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
		ctx, ping, cancel := stallWatchdog(2 * time.Minute)
		req, err := http.NewRequestWithContext(ctx, "GET",
			fmt.Sprintf("https://dl.example/dl/%d", n), nil)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		res, err := cli.Do(req)
		if err != nil {
			cancel()
			t.Fatalf("download %d: %v", n, err)
		}
		got := sha256.New()
		m, err := io.Copy(got, &beatReader{r: res.Body, ping: ping})
		_ = res.Body.Close()
		cancel()
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
	dir := shmTempDir(t)
	pol := writePolicy(t, dir, "p", m23Grants)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)

	const N = 1000
	// One generator stamps each event once and broadcasts it to every
	// connected subscriber, so the proxied and direct arms carry identical
	// send timestamps. Per-connection senders would let two independent
	// 10 ms sleep loops drift against each other under host load, and that
	// send-side skew would count as broker-added delay. With a shared ts,
	// e2e_proxied - e2e_direct for an event is exactly the delay the broker
	// (and only the broker) added.
	hub := &sseHub{n: N, want: 2}
	sse := http.HandlerFunc(hub.serve)
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
	// The hub starts only once both arms are subscribed; a client timeout
	// turns a never-started or stalled stream into a failure, not a hang.
	proxied.Timeout, direct.Timeout = 60*time.Second, 60*time.Second

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

// sseHub generates a paced SSE stream once and fans the identical frames
// out to every subscriber, starting only when `want` subscribers arrived.
// Each frame carries its index and the single generation timestamp.
type sseHub struct {
	n, want int
	mu      sync.Mutex
	subs    map[chan []byte]struct{}
	started bool
}

func (h *sseHub) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(200)
	fl := w.(http.Flusher)
	ch := make(chan []byte, h.n+1)
	h.mu.Lock()
	if h.subs == nil {
		h.subs = map[chan []byte]struct{}{}
	}
	h.subs[ch] = struct{}{}
	goGen := len(h.subs) >= h.want && !h.started
	h.started = h.started || goGen
	h.mu.Unlock()
	if goGen {
		go h.generate()
	}
	for ev := range ch {
		if _, err := w.Write(ev); err != nil {
			return
		}
		fl.Flush()
	}
}

func (h *sseHub) generate() {
	for i := 0; i < h.n; i++ {
		ev := []byte(fmt.Sprintf("data: %d:%d\n\n", i, time.Now().UnixNano()))
		h.mu.Lock()
		for ch := range h.subs {
			select {
			case ch <- ev:
			default: // a subscriber that fell a whole window behind stalls nobody
			}
		}
		h.mu.Unlock()
		if i != h.n-1 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	h.mu.Lock()
	for ch := range h.subs {
		close(ch)
	}
	h.mu.Unlock()
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
// The second half perturbs every request_digest input of 04 §3 through
// the live pipeline: changing exactly one input must change the digest,
// and the two normalizations (authority case fold, default-port drop)
// must hold.
const m233Grants = `  grants:
    - id: any
      match: {hosts: ["*"]}
    - id: h1http
      match: {hosts: [h1.example], scheme: http}
`

func TestC233WriteAheadDigest(t *testing.T) {
	dir := shmTempDir(t)
	pol := writePolicy(t, dir, "p", m233Grants)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)
	sinkAddr, closeSink := startTLSUpstream(t, e.ca, []string{"sink.example", "sink2.example", "SINK3.EXAMPLE"}, nil, &hashSink{})
	defer closeSink()
	routes["sink.example"] = sinkAddr
	routes["sink2.example"] = sinkAddr
	routes["sink3.example"] = sinkAddr
	plainAddr, closePlain := startUpstream(t, &hashSink{})
	defer closePlain()
	routes["h1.example"] = plainAddr

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

	// ---- request_digest input coverage (04 §3) -------------------------
	// The baseline request; every sibling below changes exactly one
	// digest input and must produce a different digest — and equal the
	// independently recomputed one.
	bodySHA := sha256.Sum256([]byte("abc"))
	abcSHA := hex.EncodeToString(bodySHA[:])
	mk := func(method, url, body string, hdr map[string]string) *http.Request {
		req, err := http.NewRequest(method, url, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		return req
	}
	octet := map[string]string{"Content-Type": "application/octet-stream"}
	base := wantDigest("POST", "https", "sink.example", "/up", "q=1", bodySHA, "application/octet-stream")
	d := map[string]string{}
	d["base"] = sendAndDigest(t, cli, e, "s1", mk("POST", "https://sink.example/up?q=1", "abc", octet), bodySHA)
	if d["base"] != base {
		t.Fatalf("baseline digest %s, want %s", d["base"], base)
	}

	siblings := []struct {
		name string
		req  *http.Request
		want string // independently recomputed digest
		diff bool   // must differ from baseline (false = must equal it)
	}{
		{"query", mk("POST", "https://sink.example/up?q=2", "abc", octet),
			wantDigest("POST", "https", "sink.example", "/up", "q=2", bodySHA, "application/octet-stream"), true},
		{"path", mk("POST", "https://sink.example/up2?q=1", "abc", octet),
			wantDigest("POST", "https", "sink.example", "/up2", "q=1", bodySHA, "application/octet-stream"), true},
		{"method", mk("PUT", "https://sink.example/up?q=1", "abc", octet),
			wantDigest("PUT", "https", "sink.example", "/up", "q=1", bodySHA, "application/octet-stream"), true},
		{"authority", mk("POST", "https://sink2.example/up?q=1", "abc", octet),
			wantDigest("POST", "https", "sink2.example", "/up", "q=1", bodySHA, "application/octet-stream"), true},
		{"content-type", mk("POST", "https://sink.example/up?q=1", "abc", map[string]string{"Content-Type": "text/plain"}),
			wantDigest("POST", "https", "sink.example", "/up", "q=1", bodySHA, "text/plain"), true},
		{"ct-absent", mk("POST", "https://sink.example/up?q=1", "abc", nil),
			wantDigest("POST", "https", "sink.example", "/up", "q=1", bodySHA, ""), true},
		{"ct-whitespace", mk("POST", "https://sink.example/up?q=1", "abc", map[string]string{"Content-Type": "  application/octet-stream "}),
			base, false},
		{"credential-header", mk("POST", "https://sink.example/up?q=1", "abc", map[string]string{
			"Content-Type": "application/octet-stream", "Authorization": "Bearer secret"}),
			base, false},
		{"authority-case", mk("POST", "https://SINK3.EXAMPLE/up?q=1", "abc", octet),
			wantDigest("POST", "https", "sink3.example", "/up", "q=1", bodySHA, "application/octet-stream"), false},
	}
	for _, s := range siblings {
		d[s.name] = sendAndDigest(t, cli, e, "s1", s.req, bodySHA)
		if s.diff {
			if d[s.name] == base {
				t.Errorf("digest input %s changed nothing (digest ignores it)", s.name)
			} else if d[s.name] != s.want {
				t.Errorf("digest input %s: digest %s, want %s", s.name, d[s.name], s.want)
			}
		} else if d[s.name] != s.want {
			t.Errorf("digest normalization %s: digest %s, want %s (=baseline)", s.name, d[s.name], s.want)
		}
	}

	// Body input: same request, different body bytes.
	otherSHA := sha256.Sum256([]byte("abd"))
	d["body"] = sendAndDigest(t, cli, e, "s1", mk("POST", "https://sink.example/up?q=1", "abd", octet), otherSHA)
	if d["body"] == base {
		t.Error("digest ignores request body")
	} else if want := wantDigest("POST", "https", "sink.example", "/up", "q=1", otherSHA, "application/octet-stream"); d["body"] != want {
		t.Errorf("body digest %s, want %s", d["body"], want)
	}

	// Same query, different body-less GETs: the query must change the
	// digest even with an empty body.
	get1 := func(q string) *http.Request {
		req, err := http.NewRequest("GET", "https://sink.example/x?"+q, nil)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}
	emptySHA := sha256.Sum256(nil)
	d["get-q1"] = sendAndDigest(t, cli, e, "s1", get1("a=1"), emptySHA)
	d["get-q2"] = sendAndDigest(t, cli, e, "s1", get1("a=2"), emptySHA)
	if d["get-q1"] == d["get-q2"] {
		t.Error("digest ignores the raw query")
	} else if want := wantDigest("GET", "https", "sink.example", "/x", "a=1", emptySHA, ""); d["get-q1"] != want {
		t.Errorf("get digest %s, want %s", d["get-q1"], want)
	}

	// Default-port normalization: http://h1.example:80 and http://h1.example
	// are the same authority in the digest (plain listener, scheme http).
	hreq := func(url string) *http.Request {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}
	d["http-port"] = sendAndDigest(t, cli, e, "s1", hreq("http://h1.example:80/x?q=1"), emptySHA)
	d["http-noport"] = sendAndDigest(t, cli, e, "s1", hreq("http://h1.example/x?q=1"), emptySHA)
	if d["http-port"] != d["http-noport"] {
		t.Error("default :80 not normalized away: digests differ")
	} else if want := wantDigest("GET", "http", "h1.example", "/x", "q=1", emptySHA, ""); d["http-port"] != want {
		t.Errorf("http digest %s, want %s", d["http-port"], want)
	}

	// Every recorded digest so far came through the write-ahead record;
	// spot-check the query made it into the record fields too.
	recs := recordsOfType[EffectHTTPBody](t, e.readSessionRecords(t, "s1"), "effect.http")
	found := false
	for _, ef := range recs {
		if ef.Request.Authority == "sink.example" && ef.Request.Path == "/up" &&
			ef.Request.QuerySHA256 == querySHA("q=1") && ef.Request.BodySHA256 == abcSHA {
			found = true
		}
	}
	if !found {
		t.Error("no effect.http record carries the baseline request fields")
	}
}

// effectForRequest returns the first allow-effect at index >= before
// whose recorded request fields match what the client sent.
func effectForRequest(effects []EffectHTTPBody, before int, method, authority, path, rawQuery string, bodyLen int64) *EffectHTTPBody {
	for i := before; i < len(effects); i++ {
		ef := &effects[i]
		if ef.Decision.Action != "allow" {
			continue
		}
		r := ef.Request
		if r.Method == method && r.Authority == authority && r.Path == path &&
			r.QuerySHA256 == querySHA(rawQuery) && r.BodyLen == bodyLen {
			return ef
		}
	}
	return nil
}

// sendAndDigest issues req through the proxied client and returns the
// request_digest of the write-ahead effect.http it produced.
func sendAndDigest(t *testing.T, cli *http.Client, e *testEnv, sessionID string, req *http.Request, wantBodySHA [32]byte) string {
	t.Helper()
	before := len(recordsOfType[EffectHTTPBody](t, e.readSessionRecords(t, sessionID), "effect.http"))
	res, err := cli.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("%s %s: status %d", req.Method, req.URL, res.StatusCode)
	}
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	authority := req.URL.Host
	deadline := time.Now().Add(30 * time.Second)
	for {
		effects := recordsOfType[EffectHTTPBody](t, e.readSessionRecords(t, sessionID), "effect.http")
		if ef := effectForRequest(effects, before, req.Method, authority, path, req.URL.RawQuery, req.ContentLength); ef != nil {
			if ef.RequestDigest == "" {
				t.Fatalf("%s %s: write-ahead record has no request_digest", req.Method, req.URL)
			}
			if ef.Request.BodySHA256 != hex.EncodeToString(wantBodySHA[:]) {
				t.Fatalf("%s %s: body_sha256 %q, want %q", req.Method, req.URL, ef.Request.BodySHA256, hex.EncodeToString(wantBodySHA[:]))
			}
			return ef.RequestDigest
		}
		if time.Now().After(deadline) {
			t.Fatalf("no write-ahead effect.http for %s %s", req.Method, req.URL)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRequestDigestInputs pins the 04 §3 request_digest formula at the
// unit level: each input perturbed changes the digest; each required
// normalization holds.
func TestRequestDigestInputs(t *testing.T) {
	bodyA := sha256.Sum256([]byte("a"))
	bodyB := sha256.Sum256([]byte("b"))
	hdr := func(ct string) http.Header {
		h := http.Header{}
		if ct != "" {
			h.Set("Content-Type", ct)
		}
		return h
	}
	base := requestDigest("POST", "https", "example.com", "/p", "q=1", bodyA, hdr("text/plain"))
	for name, got := range map[string]string{
		"method":       requestDigest("PUT", "https", "example.com", "/p", "q=1", bodyA, hdr("text/plain")),
		"scheme":       requestDigest("POST", "http", "example.com", "/p", "q=1", bodyA, hdr("text/plain")),
		"authority":    requestDigest("POST", "https", "other.com", "/p", "q=1", bodyA, hdr("text/plain")),
		"raw path":     requestDigest("POST", "https", "example.com", "/q", "q=1", bodyA, hdr("text/plain")),
		"raw query":    requestDigest("POST", "https", "example.com", "/p", "q=2", bodyA, hdr("text/plain")),
		"body":         requestDigest("POST", "https", "example.com", "/p", "q=1", bodyB, hdr("text/plain")),
		"content-type": requestDigest("POST", "https", "example.com", "/p", "q=1", bodyA, hdr("text/html")),
		"ct absent":    requestDigest("POST", "https", "example.com", "/p", "q=1", bodyA, nil),
	} {
		if got == base {
			t.Errorf("request_digest ignores %s", name)
		}
	}
	// The content-type line hashes the trimmed value only when present.
	if got := requestDigest("POST", "https", "example.com", "/p", "q=1", bodyA, hdr("  text/plain  ")); got != base {
		t.Error("content-type value not trimmed")
	}
	// Authority normalization: case folded, default ports dropped,
	// non-default ports kept.
	for _, c := range []struct {
		host   string
		port   int
		scheme string
		want   string
	}{
		{"EXAMPLE.com", 443, "https", "example.com"},
		{"example.com", 443, "https", "example.com"},
		{"example.com", 80, "http", "example.com"},
		{"example.com", 8443, "https", "example.com:8443"},
		{"example.com", 8080, "http", "example.com:8080"},
		{"example.com", 0, "https", "example.com"},
	} {
		if got := digestAuthority(c.host, c.port, c.scheme); got != c.want {
			t.Errorf("digestAuthority(%q,%d,%q) = %q, want %q", c.host, c.port, c.scheme, got, c.want)
		}
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
	dir := shmTempDir(t)
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
	dir := shmTempDir(t)
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

	// The memory bound has no wall-clock budget either: transfers report
	// progress to the stall watchdog, which only fires on a true hang.
	cli.Timeout = 0
	const limit = 64 << 20
	before := rss()
	ctx, ping, cancel := stallWatchdog(2 * time.Minute)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://sink.example/up",
		&beatReader{r: &patternReader{n: 1 << 30}, ping: ping})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	req.ContentLength = 1 << 30
	res, err := cli.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("upload: %v", err)
	}
	_ = res.Body.Close()
	cancel()
	if d := rss() - before; d > limit {
		t.Errorf("upload RSS growth %d MiB > 64 MiB", d>>20)
	}

	before = rss()
	ctx, ping, cancel = stallWatchdog(2 * time.Minute)
	req, err = http.NewRequestWithContext(ctx, "GET", "https://src.example/big", nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	res, err = cli.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("download: %v", err)
	}
	_, _ = io.Copy(io.Discard, &beatReader{r: res.Body, ping: ping})
	_ = res.Body.Close()
	cancel()
	if d := rss() - before; d > limit {
		t.Errorf("download RSS growth %d MiB > 64 MiB", d>>20)
	}
}

// C2.3.3 (write-ahead completeness) across shutdown: a request in flight
// when the broker closes still gets its result record, and Close returns
// only after it is written. An HTTP/2 or HTTP/1.1 handler outlives its
// tunnel's Serve; without waiting for it, the record is appended after the
// sink closed and is lost (seen as a panic: Log after the test completed).
// The loss is a race between Close returning and the handler's append, so
// the scenario runs 20 times: one missed record fails the test.
func TestC233CloseWaitsForInFlightRecords(t *testing.T) {
	for i := 0; i < 20; i++ {
		t.Run(fmt.Sprintf("run%02d", i), closeWaitsOnce)
	}
}

func closeWaitsOnce(t *testing.T) {
	dir := shmTempDir(t)
	pol := writePolicy(t, dir, "p", m23Grants)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)

	started := make(chan struct{}, 1)
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write(make([]byte, 4096))
		w.(http.Flusher).Flush()
		started <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-time.After(30 * time.Second):
		}
	})
	addr, closeUp := startTLSUpstream(t, e.ca, []string{"slow.example"}, nil, slow)
	defer closeUp()
	routes["slow.example"] = addr

	tc, _ := e.tunnelTLS(t, "tok-one", "slow.example:443", &tls.Config{RootCAs: e.combinedPool(t, "s1")})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tc.Close() }()
	if _, err := tc.Write([]byte("GET /hold HTTP/1.1\r\nHost: slow.example\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.CopyN(io.Discard, res.Body, 1024)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never started the response")
	}

	done := make(chan error, 1)
	go func() { done <- e.broker.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Close: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return within 10s")
	}

	// Close has returned: the in-flight request's result record is already
	// on disk. No polling: a record that appears later was written after
	// the sink closed.
	rs := recordsOfType[ResultBody](t, e.readSessionRecords(t, "s1"), "effect.http.result")
	if len(rs) == 0 {
		t.Fatal("no effect.http.result for the request in flight at Close: evidence lost on shutdown")
	}
}
