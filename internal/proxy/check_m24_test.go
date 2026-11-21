// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package proxy

// M2.4 check suite: write-ahead evidence and fail-closed.
//
//   C2.4.1  ordering proof — over 100,000 requests at mixed concurrency,
//           every request's durable-ack precedes its first upstream byte.
//   C2.4.2  crash proof — SIGKILL the real csbroker process 200 times
//           under load; every request echo saw has an effect.http in the
//           recovered ledger, and only in-flight requests lack results.
//   C2.4.3  fail closed — append error, >500 ms append, read-only store:
//           every request 502s and nothing reaches upstream.
//   C2.4.4  every denied request produces exactly one record.
//   C2.4.5  over a 100,000-request mixed run, record count equals echo
//           count plus denied count exactly.
//   C2.4.6  a broker-produced session seals and exports to a bundle that
//           csverify and the python reference verifier both accept.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/ledger"
)

const m24Grants = `  mode: enforce
  grants:
    - id: echo
      action: allow
      match: {hosts: [up.test], scheme: http}
    - id: echo443
      action: allow
      match: {hosts: [up.test], ports: [443]}
`

// m24Volume returns the spec-mandated scale for the durability proofs
// when test/checks/check-M2.4.sh runs them (it exports
// CS_M24_SPEC_VOLUME=1, so make check-M2.4, make sabotage-M2.4 and
// make regress always get the full 100,000-request / 200-kill counts).
// An un-env'd `go test -race` — e.g. the whole-package race pass — uses
// the smaller raced volume, which still exercises every concurrent
// path (workers, kills, replay scans) inside Go's 10-minute default
// package timeout.
func m24Volume(spec, raced int) int {
	if os.Getenv("CS_M24_SPEC_VOLUME") == "1" {
		return spec
	}
	return raced
}

// fastDir returns a tmpfs-backed directory for the write-heavy runs so
// per-record fsync stays honest but cheap; falls back to t.TempDir.
func fastDir(t *testing.T, name string) string {
	t.Helper()
	if st, err := os.Stat("/dev/shm"); err == nil && st.IsDir() {
		if d, err := os.MkdirTemp("/dev/shm", name); err == nil {
			t.Cleanup(func() { _ = os.RemoveAll(d) })
			return d
		}
	}
	return shmTempDir(t)
}

// --- upstream first-byte instrumentation -----------------------------------

// reqWatchConn observes a cleartext HTTP/1.1 upstream conn and records the
// arrival time of each request's first byte. Requests are self-describing:
// "GET /r-<n>" — the byte offset of "GET" maps to the Read that carried it,
// so segmentation cannot skew the stamp.
type reqWatchConn struct {
	net.Conn
	t       *testing.T
	off     int64        // stream offset of buf[0]
	buf     []byte       // unscanned stream suffix
	chunks  []watchChunk // read slices still covering buf
	deliver func(n int, at time.Time)
}

type watchChunk struct {
	start, end int64
	at         time.Time
}

func (c *reqWatchConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		at := time.Now()
		data := p[:n]
		c.chunks = append(c.chunks, watchChunk{c.off + int64(len(c.buf)), c.off + int64(len(c.buf)) + int64(n), at})
		c.buf = append(c.buf, data...)
		c.scan()
	}
	return n, err
}

// scan walks the buffered stream for request starts. A marker spans reads
// freely: the stamp is the Read that carried the marker's first byte —
// an upper bound on wire arrival, and therefore a safe bound for the
// ack-before-byte check (a byte upstream before the append committed would
// arrive earlier than the stamp, not later).
func (c *reqWatchConn) scan() {
	for {
		i := bytes.Index(c.buf, []byte("GET /r-"))
		if i < 0 {
			// Keep a small suffix in case a marker straddles the edge.
			if len(c.buf) > 6 {
				drop := len(c.buf) - 6
				c.off += int64(drop)
				c.buf = c.buf[drop:]
				var keep []watchChunk
				for _, ch := range c.chunks {
					if ch.end > c.off {
						keep = append(keep, ch)
					}
				}
				c.chunks = keep
			}
			return
		}
		start := c.off + int64(i)
		rest := c.buf[i:]
		sp := bytes.IndexByte(rest, ' ')
		if sp < 0 {
			return // head incomplete; wait for more bytes
		}
		num := rest[len("GET /r-"):]
		end := bytes.IndexAny(num, " ?")
		if end < 0 {
			return
		}
		id, err := strconv.Atoi(string(num[:end]))
		if err == nil {
			at := c.chunks[len(c.chunks)-1].at
			for _, ch := range c.chunks {
				if start >= ch.start && start < ch.end {
					at = ch.at
					break
				}
			}
			c.deliver(id, at)
		}
		// Consume through the marker so the next scan finds the next request.
		take := i + len("GET /r-") + end + 1
		c.off += int64(take)
		c.buf = c.buf[take:]
	}
}

// timingSink wraps a RecordSink and stamps each durable append-ack with the
// request id carried in the record's path ("/r-<n>").
type timingSink struct {
	inner RecordSink
	mu    sync.Mutex
	acks  map[int]time.Time
}

func (s *timingSink) Append(session string, rec *Record) error {
	err := s.inner.Append(session, rec)
	if err == nil && rec.Type == "effect.http" {
		var b struct {
			Request struct {
				Path     string `json:"path"`
				Decision struct {
					Action string `json:"action"`
				} `json:"-"`
			} `json:"request"`
			Decision struct {
				Action string `json:"action"`
			} `json:"decision"`
		}
		if json.Unmarshal(rec.Body, &b) == nil && b.Decision.Action == "allow" {
			if n, ok := reqNum(b.Request.Path); ok {
				s.mu.Lock()
				s.acks[n] = time.Now()
				s.mu.Unlock()
			}
		}
	}
	return err
}

func (s *timingSink) PendingEffects() ([]PendingEffect, error) { return s.inner.PendingEffects() }
func (s *timingSink) Close() error                             { return s.inner.Close() }

// reqNum parses "/r-<n>" or "/r-<n>?..." into n.
func reqNum(path string) (int, bool) {
	if !strings.HasPrefix(path, "/r-") {
		return 0, false
	}
	rest := path[3:]
	end := strings.IndexAny(rest, "?/")
	if end < 0 {
		end = len(rest)
	}
	n, err := strconv.Atoi(rest[:end])
	return n, err == nil
}

// TestC241OrderingProof drives 100,000 requests at mixed concurrency and
// asserts the write-ahead order on every one: the effect.http durable-ack
// timestamp precedes the first byte the upstream observed for that request.
func TestC241OrderingProof(t *testing.T) {
	dir := fastDir(t, "m241-")
	pol := writePolicy(t, dir, "p", m24Grants)

	// Instrumented upstream: stamps each request's first byte.
	var dmu sync.Mutex
	deliver := map[int]time.Time{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upLn := &watchListener{Listener: ln, wrap: func(c net.Conn) net.Conn {
		return &reqWatchConn{Conn: c, t: t, deliver: func(n int, at time.Time) {
			dmu.Lock()
			deliver[n] = at
			dmu.Unlock()
		}}
	}}
	up := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})}
	go func() { _ = up.Serve(upLn) }()
	t.Cleanup(func() { _ = up.Close() })

	inner, err := NewFileRecordSink(filepath.Join(dir, "records"), "broker/m241")
	if err != nil {
		t.Fatal(err)
	}
	ts := &timingSink{inner: inner, acks: map[int]time.Time{}}
	e := newTestEnvFull(t, dir,
		[]SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)},
		map[string]string{"up.test": ln.Addr().String()}, nil, ts)

	total := m24Volume(100000, 4000)
	cli := e.proxyClient(t, "tok-one", nil)

	var wg sync.WaitGroup
	var seq atomic.Int64
	var failed atomic.Int64
	worker := func(n int) {
		for i := 0; i < n; i++ {
			id := seq.Add(1) - 1
			res, err := cli.Get(fmt.Sprintf("http://up.test/r-%d", id))
			if err != nil {
				failed.Add(1)
				continue
			}
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			if res.StatusCode != 200 {
				failed.Add(1)
			}
		}
	}

	// Mixed concurrency: a serial phase, then waves of 4, 16 and 64.
	worker(total / 8)
	remaining := total - int(seq.Load())
	waves := []int{4, 16, 64}
	for wi, conc := range waves {
		share := remaining / (len(waves) - wi)
		remaining -= share
		per := share / conc
		for k := 0; k < conc; k++ {
			n := per
			if k == conc-1 {
				n = share - per*(conc-1)
			}
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				worker(n)
			}(n)
		}
		wg.Wait()
	}

	if got := failed.Load(); got > 0 {
		t.Fatalf("%d of %d requests failed", got, total)
	}
	if got := int(seq.Load()); got != total {
		t.Fatalf("issued %d requests, want %d", got, total)
	}

	// Every request: durable ack strictly before first byte at upstream.
	var worst time.Duration
	worstN := -1
	dmu.Lock()
	defer dmu.Unlock()
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if len(deliver) != total {
		t.Fatalf("upstream observed %d requests, want %d", len(deliver), total)
	}
	if len(ts.acks) != total {
		t.Fatalf("sink acked %d effects, want %d", len(ts.acks), total)
	}
	for n := 0; n < total; n++ {
		ack, ok1 := ts.acks[n]
		fb, ok2 := deliver[n]
		if !ok1 || !ok2 {
			t.Fatalf("request %d: ack=%v deliver=%v", n, ok1, ok2)
		}
		if !ack.Before(fb) {
			t.Fatalf("request %d: durable ack %s NOT before first upstream byte %s (write-ahead violated)",
				n, ack.Format(time.RFC3339Nano), fb.Format(time.RFC3339Nano))
		}
		if d := fb.Sub(ack); d > worst {
			worst, worstN = d, n
		}
	}
	t.Logf("C2.4.1: %d requests, all acks preceded first-byte; max margin %s", total, worst)
	_ = worstN
}

// watchListener wraps accepted conns (the upstream first-byte clock).
type watchListener struct {
	net.Listener
	wrap func(net.Conn) net.Conn
}

func (l *watchListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.wrap(c), nil
}

// --- C2.4.2 crash proof -----------------------------------------------------

// m24Bins builds (or finds) the csbroker and csverify binaries the suite
// drives. M24_BIN skips the build the way M27_BIN does for M2.7.
var m24Bins struct {
	once     sync.Once
	dir      string
	err      error
	csbroker string
	csverify string
}

func m24Bin(t *testing.T, which string) string {
	t.Helper()
	m24Bins.once.Do(func() {
		if d := os.Getenv("M24_BIN"); d != "" {
			m24Bins.dir = d
		} else {
			gob, err := exec.LookPath("go")
			if err != nil {
				m24Bins.err = fmt.Errorf("go toolchain: %w", err)
				return
			}
			d, err := os.MkdirTemp("", "m24bin-")
			if err != nil {
				m24Bins.err = err
				return
			}
			for _, b := range [][2]string{{"csbroker", "./cmd/csbroker"}, {"csverify", "./cmd/csverify"}} {
				out := filepath.Join(d, b[0])
				cmd := exec.Command(gob, "build", "-tags", "fixtures", "-o", out, b[1])
				root, _ := filepath.Abs("../..")
				cmd.Dir = root
				if o, err := cmd.CombinedOutput(); err != nil {
					m24Bins.err = fmt.Errorf("go build %s: %v\n%s", b[1], err, o)
					return
				}
			}
			m24Bins.dir = d
		}
		m24Bins.csbroker = filepath.Join(m24Bins.dir, "csbroker")
		m24Bins.csverify = filepath.Join(m24Bins.dir, "csverify")
	})
	if m24Bins.err != nil {
		t.Fatal(m24Bins.err)
	}
	return map[string]string{"csbroker": m24Bins.csbroker, "csverify": m24Bins.csverify}[which]
}

// TestC242CrashProof SIGKILLs the real broker process 200 times under
// load. After every kill, every request the upstream observed has a
// durable effect.http in the recovered ledger, and the only effects
// without a result are the ones in flight at the kill.
func TestC242CrashProof(t *testing.T) {
	bin := m24Bin(t, "csbroker")
	dir := fastDir(t, "m242-")
	pol := writePolicy(t, dir, "p", m24Grants)

	// The counting upstream: every request it ever sees lands in seen.
	var mu sync.Mutex
	seen := map[int]bool{}
	upAddr, upClose := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n, ok := reqNum(r.URL.Path); ok {
			mu.Lock()
			seen[n] = true
			mu.Unlock()
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upClose)

	// Session table, records dir, ledger dir and the broker key.
	sessFile := filepath.Join(dir, "sessions.yaml")
	sessYAML := "sessions:\n  - id: s1\n    token: tok-one\n    client_ip: 127.0.0.1\n    policy: " + pol + "\n"
	if err := os.WriteFile(sessFile, []byte(sessYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	recordsDir := filepath.Join(dir, "records")
	ledgerDir := filepath.Join(dir, "ledger")
	if err := os.MkdirAll(recordsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "broker.key")
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	signer := keys.NewSigner(seed[:])
	if err := keys.SaveSigner(signer, keyFile); err != nil {
		t.Fatal(err)
	}

	kills := m24Volume(200, 20)
	var nextID atomic.Int64
	// inflightWindow accumulates, per kill, the ids that could legitimately
	// lack a result record: the last couple issued when the kill landed
	// (a request mid-flight, plus a completed response whose result append
	// was still pending).
	inflightWindow := map[int]bool{}
	effected := map[int]bool{}
	effects := map[string]int{}
	results := map[string]bool{}

	// The ledger's durable truth is log/entries.jsonl — one canonical
	// record per line. Scanning it incrementally by byte offset is O(bytes)
	// across all kills (ledger.Open would replay the whole log per kill).
	entriesPath := filepath.Join(ledgerDir, "log", "entries.jsonl")
	var scanOff int64
	scanNew := func() {
		f, err := os.Open(entriesPath)
		if err != nil {
			if os.IsNotExist(err) {
				return
			}
			t.Fatalf("open entries: %v", err)
		}
		defer func() { _ = f.Close() }()
		if _, err := f.Seek(scanOff, io.SeekStart); err != nil {
			t.Fatalf("seek entries: %v", err)
		}
		data, err := io.ReadAll(f)
		if err != nil {
			t.Fatalf("read entries: %v", err)
		}
		nl := 0
		for i, b := range data {
			if b == '\n' {
				line := data[nl:i]
				nl = i + 1
				if len(line) == 0 {
					continue
				}
				_, _, rec, err := evidence.DecodeRecordLine(line)
				if err != nil {
					continue
				}
				switch rec.Type {
				case "effect.http":
					if b, ok := rec.Body.(*evidence.EffectHTTPBody); ok {
						if n, ok := reqNum(b.Request.Path); ok {
							effects[b.EffectID] = n
							effected[n] = true
						}
					}
				case "effect.http.result":
					if b, ok := rec.Body.(*evidence.EffectHTTPResultBody); ok {
						results[b.EffectID] = true
					}
				}
			}
		}
		// A SIGKILL can leave a torn tail line; only consume through the
		// last complete newline — the rest joins the next scan.
		scanOff += int64(nl)
	}

	for k := 0; k < kills; k++ {
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, bin,
			"--local", "--sessions", sessFile,
			"--records-dir", recordsDir,
			"--ledger-dir", ledgerDir,
			"--broker-key", keyFile,
			"--listen", "127.0.0.1:0")
		cmd.Env = append(os.Environ(), "CS_FIXTURE_RESOLVE=up.test="+upAddr)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatalf("kill %d: broker start: %v", k, err)
		}
		br := bufio.NewReader(stdout)
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("kill %d: no listen line: %v", k, err)
		}
		addr := strings.TrimSpace(strings.TrimPrefix(line, "listening"))
		go func() { _, _ = io.Copy(io.Discard, br) }()

		// Load: one conn issuing a request every few ms — a kill lands
		// mid-stream so the tail is genuinely in flight, while total
		// records stay small enough that 200 ledger replays stay cheap.
		clientDone := make(chan struct{})
		var lastIssued atomic.Int64
		lastIssued.Store(-1)
		go func() {
			defer close(clientDone)
			conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			auth := "Proxy-Authorization: " + basicAuth("cs", "tok-one") + "\r\n"
			r := bufio.NewReader(conn)
			for {
				id := nextID.Add(1) - 1
				_, err := fmt.Fprintf(conn,
					"GET http://up.test/r-%d HTTP/1.1\r\nHost: up.test\r\n%s\r\n", id, auth)
				if err != nil {
					return
				}
				lastIssued.Store(id)
				res, err := http.ReadResponse(r, nil)
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
				time.Sleep(4 * time.Millisecond)
			}
		}()

		// Random instant under load, then SIGKILL.
		var rb [1]byte
		_, _ = rand.Read(rb[:])
		time.Sleep(time.Duration(10+int(rb[0])%140) * time.Millisecond)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		<-clientDone
		cancel()

		last := int(lastIssued.Load())
		for i := 0; i < 2 && last-i >= 0; i++ {
			inflightWindow[last-i] = true
		}

		// Recover: the appended bytes since the last scan are the durable
		// record of what this kill's run committed before dying.
		scanNew()

		// The hard requirement, this kill: every request upstream has
		// ever observed is backed by a durable effect.http.
		mu.Lock()
		missing := []int{}
		for n := range seen {
			if !effected[n] {
				missing = append(missing, n)
			}
		}
		mu.Unlock()
		if len(missing) > 0 {
			sort.Ints(missing)
			t.Fatalf("kill %d: %d upstream-observed requests have no effect.http, first: %v",
				k, len(missing), missing[:min(5, len(missing))])
		}

		// Effects without results must be in-flight requests: every one
		// was issued, and each belongs to some kill's in-flight window.
		for id, n := range effects {
			if !results[id] && !inflightWindow[n] {
				t.Fatalf("kill %d: effect for /r-%d has no result but was not in flight at a kill", k, n)
			}
		}
	}
	t.Logf("C2.4.2: %d SIGKILLs, %d requests issued, every observed request evidenced",
		kills, nextID.Load())
}

// --- C2.4.3 fail closed ------------------------------------------------------

// delaySink wraps a RecordSink making every Append take at least d —
// past maxAppend the broker's bound must fail the request closed.
type delaySink struct {
	inner RecordSink
	d     time.Duration
}

func (s *delaySink) Append(session string, rec *Record) error {
	time.Sleep(s.d)
	return s.inner.Append(session, rec)
}

func (s *delaySink) PendingEffects() ([]PendingEffect, error) { return s.inner.PendingEffects() }
func (s *delaySink) Close() error                             { return s.inner.Close() }

// TestC243FailClosed proves the three M2.4 failure shapes all fail closed:
// an append error, an append delayed past the 500 ms bound, and a store
// the broker cannot write at all. Every request 502s with
// LEDGER_UNAVAILABLE and nothing reaches upstream.
func TestC243FailClosed(t *testing.T) {
	dir := shmTempDir(t)
	pol := writePolicy(t, dir, "p", m24Grants)

	var hits atomic.Int64
	upAddr, upClose := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer upClose()

	// (a) Append errors: every request 502 LEDGER_UNAVAILABLE.
	t.Run("append-error", func(t *testing.T) {
		inner, err := NewFileRecordSink(filepath.Join(dir, "ra"), "broker/t")
		if err != nil {
			t.Fatal(err)
		}
		fs := &failableSink{inner: inner, rejected: make(chan string, 64)}
		e := newTestEnvFull(t, filepath.Join(dir, "ea"),
			[]SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)},
			map[string]string{"up.test": upAddr}, nil, fs)
		fs.fail.Store(true)
		before := hits.Load()
		for i := 0; i < 8; i++ {
			cli := e.proxyClient(t, "tok-one", nil)
			res, err := cli.Get(fmt.Sprintf("http://up.test/x%d", i))
			if err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
			_ = res.Body.Close()
			if res.StatusCode != http.StatusBadGateway {
				t.Fatalf("request %d: status %d, want 502", i, res.StatusCode)
			}
			if r := res.Header.Get("X-Countersign-Reason"); r != "LEDGER_UNAVAILABLE" {
				t.Fatalf("request %d: reason %q, want LEDGER_UNAVAILABLE", i, r)
			}
		}
		if got := hits.Load() - before; got != 0 {
			t.Fatalf("upstream saw %d requests during sink failure, want 0", got)
		}
	})

	// (b) Append delayed past the 500 ms bound: the request fails closed
	// even though the append eventually commits (the record may or may
	// not have landed — the bound is the contract).
	t.Run("append-slow", func(t *testing.T) {
		inner, err := NewFileRecordSink(filepath.Join(dir, "rb"), "broker/t")
		if err != nil {
			t.Fatal(err)
		}
		ds := &delaySink{inner: inner, d: maxAppend + 300*time.Millisecond}
		e := newTestEnvFull(t, filepath.Join(dir, "eb"),
			[]SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)},
			map[string]string{"up.test": upAddr}, nil, ds)
		before := hits.Load()
		cli := e.proxyClient(t, "tok-one", nil)
		cli.Timeout = 10 * time.Second
		start := time.Now()
		res, err := cli.Get("http://up.test/slow")
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusBadGateway {
			t.Fatalf("status %d, want 502", res.StatusCode)
		}
		if r := res.Header.Get("X-Countersign-Reason"); r != "LEDGER_UNAVAILABLE" {
			t.Fatalf("reason %q, want LEDGER_UNAVAILABLE", r)
		}
		if took := time.Since(start); took >= ds.d {
			t.Fatalf("response took %s ≥ delay %s — the bound did not fire", took, ds.d)
		}
		if got := hits.Load() - before; got != 0 {
			t.Fatalf("upstream saw %d requests during slow-ledger, want 0", got)
		}
	})

	// (c) Records dir read-only at start: the broker cannot open its
	// record store — fail closed at construction (nothing is served at
	// all, the strongest form of closed).
	t.Run("readonly-store", func(t *testing.T) {
		if err := os.MkdirAll(filepath.Join(dir, "ro"), 0o755); err != nil {
			t.Fatal(err)
		}
		rd := filepath.Join(dir, "ro", "records")
		if err := os.Mkdir(rd, 0o555); err != nil {
			t.Fatal(err)
		}
		sessFile := filepath.Join(dir, "ro", "sessions.yaml")
		sessYAML := "sessions:\n  - id: s1\n    token: tok-one\n    client_ip: 127.0.0.1\n    policy: " + pol + "\n"
		if err := os.WriteFile(sessFile, []byte(sessYAML), 0o644); err != nil {
			t.Fatal(err)
		}
		srv, err := NewServer(Config{SessionsFile: sessFile, RecordsDir: rd})
		if err == nil {
			_ = srv.Close()
			t.Fatal("NewServer on a read-only records dir succeeded; want fail-closed")
		}
	})
}

// --- C2.4.4 denied requests: exactly one record each ------------------------

// TestC244DeniedCounted drives denied requests of every shape — a
// policy-denied request, a CONNECT to an ungranted host and a conn-level
// smuggling denial — and asserts each produces exactly one record.
func TestC244DeniedCounted(t *testing.T) {
	dir := shmTempDir(t)
	pol := writePolicy(t, dir, "p", m24Grants)
	var hits atomic.Int64
	upAddr, upClose := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer upClose()
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)},
		map[string]string{"up.test": upAddr})

	// (a) Policy denies: ungranted host, unique path per request.
	const denies = 20
	for i := 0; i < denies; i++ {
		st, head, _, conn := e.rawProxyExchange(t, fmt.Sprintf(
			"GET http://denied.test/d-%d HTTP/1.1\r\nHost: denied.test\r\nProxy-Authorization: %s\r\n\r\n",
			i, basicAuth("cs", "tok-one")))
		_ = conn.Close()
		if st != 403 {
			t.Fatalf("denied request %d: status %d", i, st)
		}
		_ = head
	}

	// (b) CONNECT to an ungranted authority: effect.denied each.
	const connDenies = 10
	for i := 0; i < connDenies; i++ {
		st, conn := e.rawConnect(t, "tok-one", fmt.Sprintf("ungranted-%d.example:443", i))
		_ = conn.Close()
		if st != 403 {
			t.Fatalf("CONNECT deny %d: status %d, want 403", i, st)
		}
	}

	// (c) Conn-level smuggling denials (CL+TE): one effect.denied each.
	const headDenies = 10
	for i := 0; i < headDenies; i++ {
		conn, err := net.DialTimeout("tcp", e.proxyURL.Host, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintf(conn, "POST http://up.test/sm-%d HTTP/1.1\r\nHost: up.test\r\nProxy-Authorization: %s\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
			i, basicAuth("cs", "tok-one"))
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		head, _ := bufio.NewReader(conn).ReadString('\n')
		_ = conn.Close()
		if !strings.Contains(head, "403") {
			t.Fatalf("smuggling deny %d: first line %q, want 403", i, head)
		}
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("upstream saw %d requests, want 0", got)
	}

	// Records: policy denies land as effect.http{deny} — exactly one per
	// request, correlated by path. Conn-level and CONNECT denials land as
	// effect.denied — exactly one per conn.
	recs := e.readSessionRecords(t, "s1")
	denyEffects := recordsOfType[EffectHTTPBody](t, recs, "effect.http")
	denyRecs := recordsOfType[DeniedBody](t, recs, "effect.denied")

	paths := map[string]int{}
	allowEffects := 0
	for _, b := range denyEffects {
		if b.Decision.Action == "deny" {
			paths[b.Request.Path]++
		} else {
			allowEffects++
		}
	}
	if allowEffects != 0 {
		t.Fatalf("%d allow effects recorded; all requests were denied", allowEffects)
	}
	for i := 0; i < denies; i++ {
		p := fmt.Sprintf("/d-%d", i)
		if paths[p] != 1 {
			t.Fatalf("path %s: %d deny records, want exactly 1", p, paths[p])
		}
	}
	if len(denyRecs) != connDenies+headDenies {
		t.Fatalf("effect.denied count %d, want %d", len(denyRecs), connDenies+headDenies)
	}
	// Every record is accounted: total == per-request denies + conn denies.
	if len(recs) != denies+connDenies+headDenies {
		t.Fatalf("total records %d, want %d (exactly one per denied request)",
			len(recs), denies+connDenies+headDenies)
	}
}

// --- C2.4.5 record count equality -------------------------------------------

// TestC245CountEquality runs a 100,000-request mix — allowed and denied —
// and requires exact equality: effect.http(allow) count == echo's count,
// effect.http(deny) == the denied count, and every allow effect has its
// result record.
func TestC245CountEquality(t *testing.T) {
	dir := fastDir(t, "m245-")
	pol := writePolicy(t, dir, "p", m24Grants)

	var hits atomic.Int64
	upAddr, upClose := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upClose()
	e := newTestEnvFull(t, dir, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)},
		map[string]string{"up.test": upAddr}, nil, nil)

	total := m24Volume(100000, 4000)
	cli := e.proxyClient(t, "tok-one", nil)
	cliDeny := e.proxyClient(t, "tok-one", nil)

	var seq atomic.Int64
	var deniedSent, failedReq atomic.Int64
	var wg sync.WaitGroup
	worker := func(n int) {
		defer wg.Done()
		for i := 0; i < n; i++ {
			id := seq.Add(1) - 1
			var res *http.Response
			var err error
			if id%10 == 0 {
				// One in ten goes to an ungranted host: a denied request.
				res, err = cliDeny.Get(fmt.Sprintf("http://denied.test/x-%d", id))
				if err == nil {
					deniedSent.Add(1)
				}
			} else {
				res, err = cli.Get(fmt.Sprintf("http://up.test/x-%d", id))
			}
			if err != nil {
				failedReq.Add(1)
				continue
			}
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			if res.StatusCode != 200 && res.StatusCode != 403 {
				failedReq.Add(1)
			}
		}
	}
	const conc = 32
	per := total / conc
	for k := 0; k < conc; k++ {
		n := per
		if k == conc-1 {
			n = total - per*(conc-1)
		}
		wg.Add(1)
		go worker(n)
	}
	wg.Wait()

	if f := failedReq.Load(); f > 0 {
		t.Fatalf("%d transport-level failures", f)
	}
	echoN := hits.Load()
	denyN := deniedSent.Load()
	allowed := total - int(denyN)
	if int(echoN) != allowed {
		t.Fatalf("echo observed %d requests, want %d (total %d - denied %d)",
			echoN, allowed, total, denyN)
	}

	recs := e.readSessionRecords(t, "s1")
	effects := recordsOfType[EffectHTTPBody](t, recs, "effect.http")
	results := recordsOfType[ResultBody](t, recs, "effect.http.result")
	var allows, denies int
	allowIDs := map[string]bool{}
	for _, b := range effects {
		switch b.Decision.Action {
		case "allow":
			allows++
			allowIDs[b.EffectID] = true
		case "deny":
			denies++
		}
	}
	if allows != allowed {
		t.Fatalf("effect.http allow=%d, want %d", allows, allowed)
	}
	if denies != int(denyN) {
		t.Fatalf("effect.http deny=%d, want %d", denies, denyN)
	}
	if len(results) != allowed {
		t.Fatalf("effect.http.result=%d, want %d (one per allowed request)", len(results), allowed)
	}
	for _, b := range results {
		if !allowIDs[b.EffectID] {
			t.Fatalf("result for unknown effect %s (a result must never outlive its effect)", b.EffectID)
		}
	}
	if len(recs) != 2*allowed+int(denyN) {
		t.Fatalf("record count %d, want %d = 2*%d + %d (echo + denied, exact)",
			len(recs), 2*allowed+int(denyN), allowed, denyN)
	}
	// B2-02: file order is eseq order — sequence assignment and durable
	// append are one critical section, so concurrent workers can never
	// interleave the chain.
	for i, rec := range recs {
		if rec.Eseq != uint64(i) {
			t.Fatalf("record %d has eseq %d — the chain is out of append order", i, rec.Eseq)
		}
	}
	t.Logf("C2.4.5: %d requests -> %d records (echo %d, denied %d)", total, len(recs), echoN, denyN)
}

// --- C2.4.6 seal, export, verify ---------------------------------------------

// testEmitter tracks a keys.Emitter's chain head so the test can build
// SealEmitter entries the way chainEmitter.sealRef does.
type testEmitter struct {
	em   *keys.Emitter
	eseq uint64
	head string
	n    int
}

func newTestEmitter(role, session string, s keys.Signer) *testEmitter {
	return &testEmitter{em: keys.NewEmitter(role, session, s), head: evidence.ZeroHash}
}

// sealRef is the pre-seal head — the emitter.seal record itself advances
// the chain after this is captured.
func (e *testEmitter) sealRef() evidence.SealEmitter {
	return evidence.SealEmitter{
		Emitter: e.em.Name(), FinalEseq: e.eseq, HeadHash: e.head,
		Clean: e.n == int(e.eseq)+1,
	}
}

// TestC246SealExportVerify runs the broker against the real ledger sink,
// seals the session the way the runner does, exports the bundle, and
// checks both verifiers accept it: the Go csverify binary and the Python
// reference (test/runner/refcheck.py).
func TestC246SealExportVerify(t *testing.T) {
	dir := fastDir(t, "m246-")
	pol := writePolicy(t, dir, "p", m24Grants)

	echoAddr, echoClose := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer echoClose()

	ledgerDir := filepath.Join(dir, "ledger")
	brokerSigner := keys.NewSigner(bytes.Repeat([]byte{0x42}, 32))
	logSigner := keys.NewSigner(bytes.Repeat([]byte{0x43}, 32))
	ctlSigner := keys.NewSigner(bytes.Repeat([]byte{0x44}, 32))
	worldSigner := keys.NewSigner(bytes.Repeat([]byte{0x45}, 32))

	ls, err := NewLedgerSink(ledgerDir, "countersign/broker", logSigner, brokerSigner)
	if err != nil {
		t.Fatalf("NewLedgerSink: %v", err)
	}
	led := ls.Ledger()
	world := newTestEmitter("world", "s1", worldSigner)
	ctl := newTestEmitter("controller", "s1", ctlSigner)
	emit := func(e *testEmitter, rtype string, body any) {
		t.Helper()
		line, _, err := e.em.Emit(rtype, body, nowTS())
		if err != nil {
			t.Fatalf("emit %s: %v", rtype, err)
		}
		env, _, rec, err := evidence.DecodeRecordLine(line)
		if err != nil {
			t.Fatalf("decode %s: %v", rtype, err)
		}
		if _, err := led.Append(line); err != nil {
			t.Fatalf("append %s: %v", rtype, err)
		}
		e.eseq = rec.Eseq
		e.head = evidence.RecordHash(env)
		e.n++
	}

	// session.open is the session's first ledger record — the controller
	// writes it before the broker sees any traffic (the runner's shape).
	polBytes, err := os.ReadFile(pol)
	if err != nil {
		t.Fatal(err)
	}
	polSum := sha256.Sum256(polBytes)
	boundary := "enforced"
	emit(ctl, "session.open", &evidence.SessionOpenBody{
		Kind:            "agent",
		Mode:            "enforce",
		PolicyDigest:    hex.EncodeToString(polSum[:]),
		ContractDigests: []string{},
		LogOrigin:       "countersign/broker",
		Boundary:        &boundary,
		World:           evidence.WorldRef{ID: "w0"},
		Start:           evidence.SessionStart{Workspace: json.RawMessage("null")},
		Tape:            evidence.TapeConf{Enabled: false},
	})

	e := newTestEnvMut(t, dir, []SessionEntry{
		{ID: "s1", Token: "tok-one", ClientIP: "127.0.0.1", Policy: pol},
	}, map[string]string{"up.test": echoAddr}, nil, ls, nil)

	// Drive a mixed workload: granted requests plus ungranted denies.
	cli := e.proxyClient(t, "tok-one", nil)
	var denied int
	for i := 0; i < 12; i++ {
		var res *http.Response
		var err error
		if i%3 == 0 {
			res, err = cli.Get(fmt.Sprintf("http://denied.test/seal-%d", i))
		} else {
			res, err = cli.Get(fmt.Sprintf("http://up.test/seal-%d", i))
		}
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		switch res.StatusCode {
		case 200:
		case 403:
			denied++
		default:
			t.Fatalf("request %d: unexpected status %d", i, res.StatusCode)
		}
	}
	if denied == 0 {
		t.Fatal("workload produced no denials; the bundle must contain deny evidence")
	}

	// Wait for every in-flight effect to reach its terminal record —
	// closing the broker would close the ledger under the sink, so the
	// seal has to happen while it is still open.
	for i := 0; i < 100; i++ {
		pend, err := ls.PendingEffects()
		if err == nil && len(pend) == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if pend, err := ls.PendingEffects(); err != nil || len(pend) > 0 {
		t.Fatalf("still %d pending effects before seal (err %v)", len(pend), err)
	}

	// Seal: broker emitter.seal (sink), then mirror the runner close-out —
	// world closes empty and seals, controller emits session.seal naming
	// all three heads, then the ledger exports the bundle.
	brokerRef, err := ls.SealSession("s1")
	if err != nil {
		t.Fatalf("broker SealSession: %v", err)
	}
	emit(world, "world.closed", &evidence.WorldClosedBody{Outcome: "empty", Commits: []string{}})
	emit(world, "emitter.seal", &evidence.EmitterSealBody{Final: true})

	// Counts from the broker chain's lines, the runner's rule: effect.*
	// records are effects; deny-action effects and effect.denied are
	// denials.
	counts := evidence.SealCounts{}
	for _, idx := range mustSessionIndices(t, led, "s1") {
		line, err := led.Line(idx)
		if err != nil {
			t.Fatal(err)
		}
		_, _, r, err := evidence.DecodeRecordLine(line)
		if err != nil {
			t.Fatal(err)
		}
		if r.Emitter != brokerRef.Emitter {
			continue
		}
		switch r.Type {
		case "effect.http", "effect.tunnel", "effect.exec", "effect.connect":
			counts.Effects++
		}
		if r.Type == "effect.denied" {
			counts.Denials++
		}
		if h, ok := r.Body.(*evidence.EffectHTTPBody); ok && h.Decision.Action == "deny" {
			counts.Denials++
		}
	}
	seal := &evidence.SessionSealBody{
		Reason:   "test-complete",
		Emitters: []evidence.SealEmitter{brokerRef, world.sealRef(), ctl.sealRef()},
		Counts:   counts,
	}
	emit(ctl, "session.seal", seal)
	if err := led.Checkpoint(); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}

	// Manifest + keys.json covering every signer used.
	nb := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	m, err := keys.NewManifest([]keys.ManifestEntry{
		{Role: "emitter:broker", NotBefore: nb, Signer: brokerSigner},
		{Role: "emitter:controller", NotBefore: nb, Signer: ctlSigner},
		{Role: "emitter:world", NotBefore: nb, Signer: worldSigner},
		{Role: "log", NotBefore: nb, Signer: logSigner},
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := led.ExportBundle("s1", m, map[string][]byte{"policy.yaml": polBytes})
	if err != nil {
		t.Fatalf("ExportBundle: %v", err)
	}
	bundlePath := filepath.Join(dir, "s1.tar")
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	mj, err := keys.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	keysPath := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(keysPath, mj, 0o600); err != nil {
		t.Fatal(err)
	}

	// Verifier 1: the Go csverify binary.
	ver := m24Bin(t, "csverify")
	out, err := exec.Command(ver, bundlePath, "--keys", keysPath).CombinedOutput()
	res := map[string]any{}
	if jerr := json.Unmarshal(bytes.TrimSpace(out), &res); jerr != nil {
		t.Fatalf("csverify output not JSON: %v\n%s", jerr, out)
	}
	if err != nil {
		t.Fatalf("csverify failed: %v\n%s", err, out)
	}
	if res["verdict"] != "CLEAN" && res["verdict"] != "CLEAN_WITH_DENIALS" {
		t.Fatalf("csverify verdict %v\n%s", res["verdict"], out)
	}

	// Verifier 2: the Python reference implementation.
	root, _ := filepath.Abs("../..")
	py := filepath.Join(root, ".tools/bin/python3")
	refpy := filepath.Join(root, "test/runner/refcheck.py")
	if out, err := exec.Command(py, refpy, bundlePath, keysPath).CombinedOutput(); err != nil {
		t.Fatalf("refcheck: %v\n%s", err, out)
	}
	t.Logf("C2.4.6: bundle sealed+exported, verdict=%v, refcheck ok", res["verdict"])
}

func mustSessionIndices(t *testing.T, led *ledger.Ledger, session string) []uint64 {
	t.Helper()
	idxs, err := led.SessionIndices(session)
	if err != nil {
		t.Fatalf("SessionIndices: %v", err)
	}
	return idxs
}
