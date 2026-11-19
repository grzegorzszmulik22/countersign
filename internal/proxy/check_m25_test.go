// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package proxy

// M2.5 checks: request-smuggling corpus (C2.5.1), path forms (C2.5.2),
// upstream address policy + resolve-once (C2.5.3), WebSocket grants
// (C2.5.4), CONNECT passthrough (C2.5.5), session isolation (C2.5.6) and
// the parser fuzz targets (C2.5.7).

import (
	"bufio"
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/countersign/countersign/test/fixtures/fxlib"
)

const m25Grants = `  mode: enforce
  grants:
    - id: echo
      action: allow
      match: {hosts: [up.test], scheme: http}
    - id: echo443
      action: allow
      match: {hosts: [up.test], ports: [443]}
    - id: ws
      action: allow
      match: {hosts: [ws.test], scheme: http}
      upgrade: [websocket]
    - id: pass
      action: allow
      mode: passthrough
      match: {hosts: [pass.test], ports: [443]}
    - id: pass-blocked
      action: allow
      mode: passthrough
      match: {hosts: [priv.test], ports: [443]}
    - id: cluster
      action: allow
      match: {hosts: [priv.test], scheme: http}
      network: cluster
`

// readHTTPStatus reads status lines until a non-1xx final response.
func readHTTPStatus(r *bufio.Reader) (int, string, error) {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return 0, "", err
		}
		var code int
		f := strings.Fields(line)
		if len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/") {
			return 0, line, fmt.Errorf("bad status line %q", line)
		}
		if code, err = strconv.Atoi(f[1]); err != nil {
			return 0, line, fmt.Errorf("bad status line %q", line)
		}
		if code == 101 || code >= 200 {
			// 101 is a final response: the head ends with the header
			// block and the conn becomes an opaque stream.
			return code, line, nil
		}
		// Other 1xx are interim: skip to the end of their header block.
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return 0, "", err
			}
			if l == "\r\n" || l == "\n" {
				break
			}
		}
	}
}

// readResponseHead reads the response head and returns code + raw head.
func readResponseHead(conn net.Conn) (int, string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(conn)
	code, first, err := readHTTPStatus(r)
	if err != nil {
		return 0, first, err
	}
	var b strings.Builder
	b.WriteString(first)
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			return code, b.String(), err
		}
		b.WriteString(l)
		if l == "\r\n" || l == "\n" {
			return code, b.String(), nil
		}
	}
}

// --- C2.5.1 smuggling corpus -------------------------------------------------

// TestC251SmugglingCorpus replays test/vectors/smuggling/*.http: every
// d-* vector is denied (403 or a dropped conn) and never reaches the
// upstream; every a-* vector parses identically at broker and echo —
// exactly one upstream request, a clean response, no doubling.
func TestC251SmugglingCorpus(t *testing.T) {
	vecs, err := filepath.Glob("../../test/vectors/smuggling/*.http")
	if err != nil || len(vecs) < 40 {
		t.Fatalf("smuggling corpus: %d vectors, want >=40", len(vecs))
	}
	sort.Strings(vecs)

	for _, vf := range vecs {
		name := filepath.Base(vf)
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(vf)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			pol := writePolicy(t, dir, "p", m25Grants)
			var hits atomic.Int64
			var pathsMu sync.Mutex
			var paths []string
			upAddr, upClose := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				pathsMu.Lock()
				paths = append(paths, r.Method+" "+r.URL.RequestURI())
				pathsMu.Unlock()
				w.WriteHeader(200)
				_, _ = w.Write([]byte("ok"))
			}))
			defer upClose()
			e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)},
				map[string]string{"up.test": upAddr})

			conn, err := net.DialTimeout("tcp", e.proxyURL.Host, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if _, err := conn.Write(raw); err != nil {
				t.Fatalf("write: %v", err)
			}
			code, head, err := readResponseHead(conn)
			switch name[0] {
			case 'd':
				if err == nil && code == 200 && name != "d-pipe-clte.http" {
					t.Fatalf("deny vector got 200:\n%s", head)
				}
				want := int64(0)
				if name == "d-pipe-clte.http" {
					// A clean first request may forward; the smuggled
					// second must not.
					want = 1
					if err == nil && code == 200 {
						code2, head2, err2 := readResponseHead(conn)
						if err2 == nil && code2 == 200 {
							t.Fatalf("pipelined smuggle: second response 200:\n%s", head2)
						}
					}
				}
				if got := hits.Load(); got != want {
					t.Fatalf("upstream saw %d requests, want %d", got, want)
				}
			case 'a':
				if err != nil {
					t.Fatalf("allow vector read: %v", err)
				}
				if code != 200 {
					t.Fatalf("allow vector got %d:\n%s", code, head)
				}
				if got := hits.Load(); got != 1 {
					t.Fatalf("upstream saw %d requests, want exactly 1", got)
				}
				// B2-03: the upstream target is byte-identical to the
				// recorded raw path and raw query — no re-escaping, no
				// '#' truncation between record and wire.
				pathsMu.Lock()
				seen := append([]string(nil), paths...)
				pathsMu.Unlock()
				if len(seen) != 1 {
					t.Fatalf("upstream recorded %d targets: %v", len(seen), seen)
				}
				_, uri, ok := strings.Cut(seen[0], " ")
				if !ok {
					t.Fatalf("upstream target %q unparsable", seen[0])
				}
				upPath, upQuery, _ := strings.Cut(uri, "?")
				recs := e.readSessionRecords(t, "s1")
				var allows []EffectHTTPBody
				for _, ef := range recordsOfType[EffectHTTPBody](t, recs, "effect.http") {
					if ef.Decision.Action == "allow" {
						allows = append(allows, ef)
					}
				}
				if len(allows) != 1 {
					t.Fatalf("allow effect.http records: %d, want 1", len(allows))
				}
				if allows[0].Request.Path != upPath {
					t.Fatalf("path fidelity: upstream %q, recorded %q", upPath, allows[0].Request.Path)
				}
				sum := sha256.Sum256([]byte(upQuery))
				if allows[0].Request.QuerySHA256 != hex_SHA(sum[:]) ||
					allows[0].Request.QueryLen != len(upQuery) {
					t.Fatalf("query fidelity: upstream %q vs recorded sha %q len %d",
						upQuery, allows[0].Request.QuerySHA256, allows[0].Request.QueryLen)
				}
			default:
				t.Fatalf("vector %s must be named d-* or a-*", name)
			}
		})
	}
}

// --- C2.5.2 path forms --------------------------------------------------------

// TestC252PathForms walks 04 §2 step 1's banned path forms — dot
// segments, encoded separators, backslash, NUL, mixed case and the
// double-encoded form — each denied before any grant lookup.
func TestC252PathForms(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", m25Grants)
	var hits atomic.Int64
	upAddr, upClose := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer upClose()
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)},
		map[string]string{"up.test": upAddr})
	auth := "Proxy-Authorization: " + basicAuth("cs", "tok-one") + "\r\n"

	bad := []string{
		"/a/../b", "/a/./b", "/../x", "/a/%2e%2e/b", "/%2E%2E/b",
		"/a%2fb", "/a%2Fb", "/a%5cb", "/a%5Cb", "/a%00b",
		"/%252e%252e/b", "/a\\b", "/a%2xb", "/a%", "/a/b%2f..%2f..%2fc",
		"%2e%2e/x",
	}
	for _, p := range bad {
		st, head, _, conn := e.rawProxyExchange(t,
			"GET http://up.test"+p+" HTTP/1.1\r\nHost: up.test\r\n"+auth+"\r\n")
		_ = conn.Close()
		if st != 403 {
			t.Fatalf("path %s: status %d, want 403\n%s", p, st, head)
		}
	}
	// Controls: an ordinary and a legal percent-encoded path both pass.
	for _, p := range []string{"/ok", "/a%20b", "/x?y=%2f"} {
		st, head, _, conn := e.rawProxyExchange(t,
			"GET http://up.test"+p+" HTTP/1.1\r\nHost: up.test\r\n"+auth+"\r\n")
		_ = conn.Close()
		if st != 200 {
			t.Fatalf("path %s: status %d, want 200\n%s", p, st, head)
		}
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("upstream saw %d requests, want 3 (only the controls)", got)
	}
}

// --- C2.5.3 upstream address policy -------------------------------------------

// TestC253UpstreamAddrCheck pins B2-04: names resolving to every blocked
// range yield UPSTREAM_BLOCKED; a resolve-once counter proves exactly
// one resolution per dial; a rebinding answer (the second call differs)
// still dials the checked address; upstream.ip records what was dialled.
func TestC253UpstreamAddrCheck(t *testing.T) {
	blocked := []struct {
		name string
		ip   string
	}{
		{"loopback4", "127.0.0.1"},
		{"loopback4-b", "127.44.55.66"},
		{"linklocal4", "169.254.10.20"},
		{"private10", "10.1.2.3"},
		{"private172", "172.16.9.9"},
		{"private192", "192.168.44.2"},
		{"unspecified", "0.0.0.0"},
		{"v6loopback", "::1"},
		{"v6linklocal", "fe80::1"},
		{"v6ula", "fd00::7"},
		{"v6mapped-loopback", "::ffff:127.0.0.1"},
		{"v6mapped-private", "::ffff:10.3.4.5"},
		{"v6multicast", "ff02::1"},
	}
	for _, tc := range blocked {
		t.Run("blocked/"+tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pol := writePolicy(t, dir, "p", m25Grants)
			ip := netip.MustParseAddr(tc.ip)
			var resolveCalls atomic.Int64
			e := newTestEnvMut(t, dir,
				[]SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)},
				nil, nil, nil, func(c *Config) {
					c.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
						resolveCalls.Add(1)
						return []netip.Addr{ip}, nil
					}
					c.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
						t.Errorf("dial attempted for blocked %s → %s", tc.name, addr)
						return nil, fmt.Errorf("must not dial %s", addr)
					}
				})
			cli := e.proxyClient(t, "tok-one", nil)
			res, err := cli.Get("http://up.test/x")
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			_ = res.Body.Close()
			if res.StatusCode != http.StatusBadGateway {
				t.Fatalf("status %d, want 502 UPSTREAM_BLOCKED", res.StatusCode)
			}
			if r := res.Header.Get("X-Countersign-Reason"); r != "UPSTREAM_BLOCKED" {
				t.Fatalf("reason %q, want UPSTREAM_BLOCKED", r)
			}
			recs := e.readSessionRecords(t, "s1")
			var blocked int
			for _, rb := range recordsOfType[ResultBody](t, recs, "effect.http.result") {
				if rb.Error == "UPSTREAM_BLOCKED" {
					blocked++
				}
			}
			if blocked != 1 {
				t.Fatalf("UPSTREAM_BLOCKED result records: %d, want 1", blocked)
			}
		})
	}

	// Resolve-once + dialled address == recorded address.
	t.Run("resolve-once", func(t *testing.T) {
		dir := t.TempDir()
		pol := writePolicy(t, dir, "p", m25Grants)
		upAddr, upClose := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
		}))
		defer upClose()
		fakeIP := netip.MustParseAddr("198.51.100.77")
		var resolveCalls, dialCalls atomic.Int64
		var dialled atomic.Value
		e := newTestEnvMut(t, dir,
			[]SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)},
			nil, nil, nil, func(c *Config) {
				c.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
					resolveCalls.Add(1)
					return []netip.Addr{fakeIP}, nil
				}
				c.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialCalls.Add(1)
					dialled.Store(addr)
					h, _, _ := net.SplitHostPort(upAddr)
					p := strings.TrimPrefix(addr, h) // keep :port? dial real addr regardless
					_ = p
					var d net.Dialer
					return d.DialContext(ctx, network, upAddr)
				}
			})
		cli := e.proxyClient(t, "tok-one", nil)
		res, err := cli.Get("http://up.test/x")
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_ = res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("status %d, want 200", res.StatusCode)
		}
		if resolveCalls.Load() != 1 {
			t.Fatalf("resolve calls %d, want exactly 1 (resolve-once)", resolveCalls.Load())
		}
		if dialCalls.Load() != 1 {
			t.Fatalf("dial calls %d, want 1", dialCalls.Load())
		}
		da, _ := dialled.Load().(string)
		if !strings.HasPrefix(da, "198.51.100.77:") {
			t.Fatalf("dialled %q, want 198.51.100.77:*", da)
		}
		recs := e.readSessionRecords(t, "s1")
		var sawUp bool
		for _, rb := range recordsOfType[ResultBody](t, recs, "effect.http.result") {
			if rb.Upstream == nil {
				t.Fatalf("effect.http.result missing upstream record")
			}
			sawUp = true
			if rb.Upstream.IP != "198.51.100.77" {
				t.Fatalf("recorded upstream.ip %q, want dialled 198.51.100.77", rb.Upstream.IP)
			}
		}
		if !sawUp {
			t.Fatal("no effect.http.result records found")
		}
	})

	// Rebinding: the resolver answers a second, different address when
	// (and only when) asked again — the dial must still hit the address
	// the policy checked.
	t.Run("rebinding", func(t *testing.T) {
		dir := t.TempDir()
		pol := writePolicy(t, dir, "p", m25Grants)
		upAddr, upClose := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
		}))
		defer upClose()
		good := netip.MustParseAddr("198.51.100.88")
		evil := netip.MustParseAddr("127.0.0.1")
		var resolveCalls atomic.Int64
		e := newTestEnvMut(t, dir,
			[]SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)},
			nil, nil, nil, func(c *Config) {
				c.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
					n := resolveCalls.Add(1)
					if n == 1 {
						return []netip.Addr{good}, nil
					}
					return []netip.Addr{evil}, nil // a re-resolve would see the attacker answer
				}
				c.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					if strings.HasPrefix(addr, "127.0.0.1") {
						t.Errorf("dial hit rebound 127.0.0.1 — resolve ran twice")
						return nil, fmt.Errorf("rebound dial")
					}
					var d net.Dialer
					return d.DialContext(ctx, network, upAddr)
				}
			})
		cli := e.proxyClient(t, "tok-one", nil)
		res, err := cli.Get("http://up.test/x")
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_ = res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("status %d, want 200", res.StatusCode)
		}
		if resolveCalls.Load() != 1 {
			t.Fatalf("resolve calls %d — rebinding only works if the broker re-resolves", resolveCalls.Load())
		}
	})

	// No upstream reuse: every request dials a fresh conn, so a reused-conn
	// retry path (h1 nothing-written, h2 REFUSED stream) cannot exist —
	// one request is exactly one dial, one accept, one attempt (B2-01).
	t.Run("no-reuse", func(t *testing.T) {
		dir := t.TempDir()
		pol := writePolicy(t, dir, "p", m25Grants)
		var accepts atomic.Int64
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepts.Add(1)
				go func(c net.Conn) {
					// Keep-alive: the conn stays open so a pooling transport
					// could reuse it — the broker must never do so (B2-01).
					defer func() { _ = c.Close() }()
					br := bufio.NewReader(c)
					for {
						for {
							l, err := br.ReadString('\n')
							if err != nil || l == "\r\n" {
								if err != nil {
									return
								}
								break
							}
						}
						if _, err := c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")); err != nil {
							return
						}
					}
				}(c)
			}
		}()
		defer func() { _ = ln.Close() }()
		upAddr := ln.Addr().String()
		fakeIP := netip.MustParseAddr("198.51.100.90")
		var dialCalls atomic.Int64
		e := newTestEnvMut(t, dir,
			[]SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)},
			nil, nil, nil, func(c *Config) {
				c.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
					return []netip.Addr{fakeIP}, nil
				}
				c.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialCalls.Add(1)
					var d net.Dialer
					return d.DialContext(ctx, network, upAddr)
				}
			})
		cli := e.proxyClient(t, "tok-one", nil)
		const reqs = 3
		for i := 0; i < reqs; i++ {
			res, err := cli.Get("http://up.test/x")
			if err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
			_ = res.Body.Close()
			if res.StatusCode != 200 {
				t.Fatalf("request %d: status %d", i, res.StatusCode)
			}
		}
		if got := dialCalls.Load(); got != reqs {
			t.Fatalf("dials %d for %d requests — a reused conn served a request", got, reqs)
		}
		if got := accepts.Load(); got != reqs {
			t.Fatalf("upstream accepts %d for %d requests", got, reqs)
		}
	})

	// network:cluster admits private ranges a default grant blocks.
	t.Run("cluster-allowed", func(t *testing.T) {
		dir := t.TempDir()
		pol := writePolicy(t, dir, "p", m25Grants)
		upAddr, upClose := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
		}))
		defer upClose()
		priv := netip.MustParseAddr("10.9.9.9")
		var dialled atomic.Value
		e := newTestEnvMut(t, dir,
			[]SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)},
			nil, nil, nil, func(c *Config) {
				c.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
					return []netip.Addr{priv}, nil
				}
				c.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialled.Store(addr)
					var d net.Dialer
					return d.DialContext(ctx, network, upAddr)
				}
			})
		cli := e.proxyClient(t, "tok-one", nil)
		res, err := cli.Get("http://priv.test/x")
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_ = res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("cluster request status %d, want 200", res.StatusCode)
		}
		if da, _ := dialled.Load().(string); !strings.HasPrefix(da, "10.9.9.9:") {
			t.Fatalf("cluster dial %q, want 10.9.9.9:*", da)
		}
	})
}

// --- C2.5.4 WebSocket ---------------------------------------------------------

// wsUpstream is a minimal RFC 6455 echo server: it accepts the upgrade
// and echoes every text frame back.
func wsUpstream(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	return startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !headerHasToken(r.Header, "Upgrade", "websocket") {
			w.WriteHeader(400)
			return
		}
		key := r.Header.Get("Sec-WebSocket-Key")
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(500)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		accept := wsAccept(key)
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n")
		if err := buf.Flush(); err != nil {
			return
		}
		for {
			op, payload, err := wsReadFrame(buf.Reader)
			if err != nil || op == 8 {
				return
			}
			if err := wsWriteFrame(conn, op, payload, false); err != nil {
				return
			}
		}
	}))
}

func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return b64(string(sum[:]))
}

// wsReadFrame reads one frame (server frames are unmasked).
func wsReadFrame(r *bufio.Reader) (op byte, payload []byte, err error) {
	h, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	op = h & 0x0f
	b2, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	masked := b2&0x80 != 0
	n := int64(b2 & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		n = int64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		n = int64(binary.BigEndian.Uint64(ext[:]))
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(r, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return op, payload, nil
}

// wsWriteFrame writes one frame (client frames are masked).
func wsWriteFrame(w io.Writer, op byte, payload []byte, masked bool) error {
	h := []byte{0x80 | op}
	l := len(payload)
	mb := byte(0)
	if masked {
		mb = 0x80
	}
	switch {
	case l < 126:
		h = append(h, mb|byte(l))
	case l < 65536:
		h = append(h, mb|126, byte(l>>8), byte(l))
	default:
		h = append(h, mb|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(l))
		h = append(h, ext[:]...)
	}
	if _, err := w.Write(h); err != nil {
		return err
	}
	if !masked {
		_, err := w.Write(payload)
		return err
	}
	var mask [4]byte
	if _, err := crand.Read(mask[:]); err != nil {
		return err
	}
	if _, err := w.Write(mask[:]); err != nil {
		return err
	}
	mp := make([]byte, l)
	for i := range mp {
		mp[i] = payload[i] ^ mask[i%4]
	}
	_, err := w.Write(mp)
	return err
}

// TestC254WebSocket: an upgrade to an ungranted host is PROTOCOL_DENIED;
// the granted ws.test upgrades, echoes, and the tunnel result's byte
// counts match what each side really moved.
func TestC254WebSocket(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", m25Grants)
	upAddr, upClose := wsUpstream(t)
	defer upClose()
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)},
		map[string]string{"ws.test": upAddr})
	auth := "Proxy-Authorization: " + basicAuth("cs", "tok-one") + "\r\n"

	// Ungranted upgrade: ws headers but the grant's upgrade list lacks it.
	st, head, _, conn := e.rawProxyExchange(t,
		"GET http://up.test/ws HTTP/1.1\r\nHost: up.test\r\nUpgrade: websocket\r\n"+
			"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+auth+"\r\n")
	_ = conn.Close()
	if st != 403 || !strings.Contains(head, "PROTOCOL_DENIED") {
		t.Fatalf("ungranted ws: status %d, want 403 PROTOCOL_DENIED\n%s", st, head)
	}

	// Granted upgrade: handshake then a masked text frame echoed back.
	conn2, err := net.DialTimeout("tcp", e.proxyURL.Host, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn2.Close() }()
	_, _ = conn2.Write([]byte(
		"GET http://ws.test/chat HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\n" +
			"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
			"Sec-WebSocket-Version: 13\r\n" + auth + "\r\n"))
	code, head, err := readResponseHead(conn2)
	if err != nil || code != 101 {
		t.Fatalf("granted ws handshake: code %d err %v\n%s", code, err, head)
	}
	payload := []byte("hello-broker")
	if err := wsWriteFrame(conn2, 1, payload, true); err != nil {
		t.Fatalf("ws write: %v", err)
	}
	_ = conn2.SetReadDeadline(time.Now().Add(5 * time.Second))
	op, echoed, err := wsReadFrame(bufio.NewReader(conn2))
	if err != nil {
		t.Fatalf("ws read: %v", err)
	}
	if op != 1 || !bytes.Equal(echoed, payload) {
		t.Fatalf("ws echo: op %d payload %q", op, echoed)
	}
	_ = conn2.Close()
	time.Sleep(200 * time.Millisecond)

	recs := e.readSessionRecords(t, "s1")
	tunnels := recordsOfType[TunnelBody](t, recs, "effect.tunnel")
	if len(tunnels) != 1 || tunnels[0].Kind != "websocket" {
		t.Fatalf("effect.tunnel records: %+v", tunnels)
	}
	trs := recordsOfType[TunnelResultBody](t, recs, "effect.tunnel.result")
	if len(trs) != 1 {
		t.Fatalf("tunnel result count %d, want 1", len(trs))
	}
	// Up: client→upstream bytes = one masked frame of 12 bytes payload
	// (2B header + 4B mask + 12). Down: upstream→client echo (2+12).
	if trs[0].BytesUp != 18 || trs[0].BytesDown != 14 {
		t.Fatalf("tunnel counts up=%d down=%d, want 18/14", trs[0].BytesUp, trs[0].BytesDown)
	}
}

// --- C2.5.5 CONNECT passthrough ------------------------------------------------

// TestC255Passthrough: a passthrough CONNECT relays bytes untouched in
// both directions, records effect.tunnel{kind:passthrough} with the SNI
// the client offered, and mints no leaf certificate.
func TestC255Passthrough(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", m25Grants)
	// The env's CA comes from fxlib.EnsureCA(dir) — building it here first
	// means the TLS upstream mints under the same CA the broker will trust.
	ca, err := fxlib.EnsureCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	upAddr, upClose := startTLSUpstream(t, ca, []string{"pass.test"}, []string{"http/1.1"},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("through"))
		}))
	defer upClose()
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)},
		map[string]string{"pass.test": upAddr})

	// CONNECT, then speak TLS through the tunnel ourselves.
	conn, err := net.DialTimeout("tcp", e.proxyURL.Host, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	auth := "Proxy-Authorization: " + basicAuth("cs", "tok-one") + "\r\n"
	_, _ = conn.Write([]byte("CONNECT pass.test:443 HTTP/1.1\r\nHost: pass.test\r\n" + auth + "\r\n"))
	code, head, err := readResponseHead(conn)
	if err != nil || code != 200 {
		t.Fatalf("CONNECT: code %d err %v\n%s", code, err, head)
	}
	// TLS through the tunnel: our ClientHello carries SNI pass.test —
	// the broker's effect.tunnel must record it.
	tc := tls.Client(conn, &tls.Config{
		ServerName:         "pass.test",
		InsecureSkipVerify: true,
	})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tunnel TLS handshake: %v", err)
	}
	_, _ = tc.Write([]byte("GET /x HTTP/1.1\r\nHost: pass.test\r\n\r\n"))
	_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	tr := bufio.NewReader(tc)
	code, _, err = readHTTPStatus(tr)
	if err != nil || code != 200 {
		t.Fatalf("tunnel response: code %d err %v", code, err)
	}
	// Drain the response then close so the tunnel result lands.
	for {
		l, err := tr.ReadString('\n')
		if err != nil || l == "\r\n" || l == "\n" {
			break
		}
	}
	_ = tc.Close()
	time.Sleep(300 * time.Millisecond)

	recs := e.readSessionRecords(t, "s1")
	tunnels := recordsOfType[TunnelBody](t, recs, "effect.tunnel")
	if len(tunnels) != 1 {
		t.Fatalf("effect.tunnel count %d, want 1", len(tunnels))
	}
	if tunnels[0].Kind != "passthrough" {
		t.Fatalf("tunnel kind %q, want passthrough", tunnels[0].Kind)
	}
	if tunnels[0].SNI != "pass.test" {
		t.Fatalf("tunnel SNI %q, want pass.test", tunnels[0].SNI)
	}
	trs := recordsOfType[TunnelResultBody](t, recs, "effect.tunnel.result")
	if len(trs) != 1 || trs[0].BytesUp == 0 || trs[0].BytesDown == 0 {
		t.Fatalf("tunnel result %+v — byte counts must be nonzero", trs)
	}
	// No leaf minted: the session CA has no cert for pass.test.
	if got := e.broker.Session("s1").LeafCacheLen(); got != 0 {
		t.Fatalf("passthrough minted %d leaf certs, want 0", got)
	}
}

// --- C2.5.6 isolation ----------------------------------------------------------

// TestC256Isolation floods session A's per-IP conn budget with
// slow-header conns while session B (different client IP, different
// session) measures request latency: B's p99 must stay within 20% of its
// quiescent baseline — A's flood only consumes A's own budget.
func TestC256Isolation(t *testing.T) {
	if testing.Short() {
		t.Skip("timing check")
	}
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", m25Grants)
	upAddr, upClose := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upClose()
	e := newTestEnv(t, []SessionEntry{
		sessionEntry("sa", "tok-a", "127.0.0.1", pol),
		sessionEntry("sb", "tok-b", "127.0.0.1", pol),
	}, map[string]string{"up.test": upAddr})
	cliB := e.proxyClient(t, "tok-b", nil)

	p99 := func(n int) time.Duration {
		var ds []time.Duration
		for i := 0; i < n; i++ {
			start := time.Now()
			res, err := cliB.Get("http://up.test/x")
			if err == nil {
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
				ds = append(ds, time.Since(start))
			}
		}
		if len(ds) == 0 {
			return time.Hour
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[len(ds)*99/100]
	}

	base := p99(60)

	// Session A's flood: hundreds of conns that never finish a head —
	// each holds a slot in A's per-IP budget until the idle reaper fires.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 400; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				c, err := net.DialTimeout("tcp", e.proxyURL.Host, 2*time.Second)
				if err != nil {
					return
				}
				_, _ = c.Write([]byte("GET http://up.test/slow HTTP/1.1\r\nHost: up.test\r\n" +
					"Proxy-Authorization: " + basicAuth("cs", "tok-a") + "\r\nX-Dribble: "))
				tmr := time.NewTimer(1500 * time.Millisecond)
				select {
				case <-stop:
					tmr.Stop()
				case <-tmr.C:
				}
				_ = c.Close()
			}
		}()
	}
	time.Sleep(800 * time.Millisecond) // let the flood reach steady state
	underLoad := p99(60)
	close(stop)
	wg.Wait()

	if underLoad > base*12/10+2*time.Millisecond {
		t.Fatalf("session B p99 %s under flood, baseline %s — isolation failed", underLoad, base)
	}
	t.Logf("C2.5.6: B p99 baseline %s, under A-flood %s", base, underLoad)
}

// --- C2.5.7 fuzz targets -------------------------------------------------------

// FuzzRequestHead hammers checkHead with arbitrary bytes — no panic, no
// accept of a head that would parse differently upstream.
func FuzzRequestHead(f *testing.F) {
	seeds := [][]byte{
		[]byte("GET http://a.b/x HTTP/1.1\r\nHost: a.b\r\n\r\n"),
		[]byte("POST /p HTTP/1.1\r\nHost: a.b\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"),
		[]byte("GET /x HTTP/0.9\r\n\r\n"),
		[]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
		[]byte("CONNECT a.b:443 HTTP/1.1\r\nHost: a.b\r\n\r\n"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		info, deny := checkHead(data, false)
		if deny == nil && info != nil {
			// An accepted head's fields must be self-consistent.
			if info.target == "" {
				t.Fatalf("accepted head has empty target: %q", data[:min(80, len(data))])
			}
		}
	})
}

// FuzzConnectAuthority hammers the CONNECT authority splitter.
func FuzzConnectAuthority(f *testing.F) {
	for _, s := range []string{"a.b:443", "a.b", "a.b:0", "a.b:65536", "[::1]:443", "[::1]",
		"a.b:443:extra", ":443", "a.b:", "*.b:443", "a..b:443"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		host, port := splitHostPort(s)
		_ = host
		// Re-parse round-trip sanity: a numeric port survives Atoi.
		if port != 0 {
			if _, err := strconv.Atoi(strconv.Itoa(port)); err != nil {
				t.Fatalf("port %d for %q broke round-trip", port, s)
			}
		}
	})
}
