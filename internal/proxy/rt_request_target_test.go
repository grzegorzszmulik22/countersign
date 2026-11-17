// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

// Red-team reproduction: forward() rebuilds the upstream URL with
// url.URL{Path: <escaped path>, RawPath: <same>}. Because that RawPath is
// not a valid encoding of Path, URL.String() escapes the percent signs
// again and the upstream receives a different request-target. A raw '#'
// in the query survives into URL.String() and is then parsed as a fragment,
// truncating the query on the wire. The effect.http record (request.path,
// query_sha256/query_len) and request_digest are computed from the original
// target, so they do not describe the bytes the upstream saw: 04 §3 defines
// the digest over the "raw-path ... exactly as received" and the raw query.
//
// Run: go test -tags fixtures ./internal/proxy -run TestRTRequestTarget -count=1 -v

package proxy

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"testing"
)

func TestRTRequestTarget(t *testing.T) {
	t.Run("tunnel", func(t *testing.T) {
		dir := t.TempDir()
		pol := writePolicy(t, dir, "p", `  grants:
    - id: allowed
      match: {hosts: [allowed.example.com]}
`)
		routes := map[string]string{}
		e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)
		up := &rtHits{}
		addr, closeUp := startTLSUpstream(t, e.ca, []string{"allowed.example.com"}, []string{"http/1.1"}, up)
		defer closeUp()
		routes["allowed.example.com"] = addr
		pool := e.combinedPool(t, "s1")

		send := func(target string) {
			tc, st := e.tunnelTLS(t, "tok-one", "allowed.example.com:443", &tls.Config{RootCAs: pool})
			if st != 200 {
				t.Fatalf("%s: CONNECT status %d", target, st)
			}
			if err := tc.Handshake(); err != nil {
				t.Fatalf("%s: handshake: %v", target, err)
			}
			code, _ := innerRequest(t, tc, "GET "+target+" HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n")
			_ = tc.Close()
			if code != 200 {
				t.Fatalf("%s: inner status %d, want 200", target, code)
			}
		}
		send("/a%41b")
		send("/q?x=1#frag")

		hits := up.snapshot()
		recs := recordsOfType[EffectHTTPBody](t, e.readSessionRecords(t, "s1"), "effect.http")
		if len(hits) != 2 || len(recs) != 2 {
			t.Fatalf("hits=%d records=%d, want 2/2", len(hits), len(recs))
		}

		// Path case: the record holds /a%41b; the upstream saw /a%2541b.
		if hits[0].RequestURI != "/a%41b" {
			t.Errorf("path: upstream request-target %q, broker record path %q; the forwarded path was re-escaped",
				hits[0].RequestURI, recs[0].Request.Path)
		}
		if recs[0].Request.Path != "/a%41b" {
			t.Errorf("path: broker record path %q, want the raw client path /a%%41b", recs[0].Request.Path)
		}

		// Query case: record query hash covers x=1#frag; upstream saw x=1.
		qsum := sha256.Sum256([]byte("x=1#frag"))
		if got, want := recs[1].Request.QuerySHA256, hex.EncodeToString(qsum[:]); got != want {
			t.Errorf("query: record query_sha256 %s, want %s (x=1#frag)", got, want)
		}
		if recs[1].Request.QueryLen != len("x=1#frag") {
			t.Errorf("query: record query_len %d, want %d", recs[1].Request.QueryLen, len("x=1#frag"))
		}
		if hits[1].RequestURI != "/q?x=1#frag" {
			t.Errorf("query: upstream request-target %q, broker recorded path %q and query_len %d; "+
				"the '#' truncated the forwarded query", hits[1].RequestURI, recs[1].Request.Path, recs[1].Request.QueryLen)
		}
	})

	t.Run("plain", func(t *testing.T) {
		dir := t.TempDir()
		pol := writePolicy(t, dir, "p", `  grants:
    - id: allowed-http
      match: {hosts: [allowed.example.com], scheme: http}
`)
		routes := map[string]string{}
		e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)
		up := &rtHits{}
		addr, closeUp := startUpstream(t, up)
		defer closeUp()
		routes["allowed.example.com"] = addr

		auth := "Proxy-Authorization: " + basicAuth("cs", "tok-one") + "\r\n"
		st, _, _, conn := e.rawProxyExchange(t,
			"GET http://allowed.example.com/a%41b HTTP/1.1\r\nHost: allowed.example.com\r\n"+auth+"\r\n")
		_ = conn.Close()
		if st != 200 {
			t.Fatalf("plain status %d, want 200", st)
		}
		hits := up.snapshot()
		if len(hits) != 1 || hits[0].RequestURI != "/a%41b" {
			recs := recordsOfType[EffectHTTPBody](t, e.readSessionRecords(t, "s1"), "effect.http")
			recPath := ""
			if len(recs) > 0 {
				recPath = recs[len(recs)-1].Request.Path
			}
			t.Fatalf("plain: upstream request-target %q, broker record path %q; want /a%%41b on both",
				func() string {
					if len(hits) > 0 {
						return hits[0].RequestURI
					}
					return "<none>"
				}(), recPath)
		}
	})
}
