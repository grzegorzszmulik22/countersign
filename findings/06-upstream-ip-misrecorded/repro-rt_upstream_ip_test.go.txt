// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

// Red-team reproduction: effect.http.result records upstream.ip as the
// requested host name, not the address actually dialed. 03 §4.2 defines
// upstream{ip,...}; 04 §2 step 3 says "The broker resolves the name once
// and connects to that address. ... The resolved address is recorded."
// A record whose ip field is a name cannot show which address was reached.
//
// Run: go test -tags fixtures ./internal/proxy -run TestRTUpstreamIP -count=1 -v

package proxy

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestRTUpstreamIP(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p", `  grants:
    - id: allowed
      match: {hosts: [allowed.example.com]}
`)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)
	up := &rtHits{}
	addr, closeUp := startTLSUpstream(t, e.ca, []string{"allowed.example.com"}, nil, up)
	defer closeUp()
	routes["allowed.example.com"] = addr
	pool := e.combinedPool(t, "s1")

	cli := e.proxyClient(t, "tok-one", pool)
	res, err := cli.Get("https://allowed.example.com/x")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	var result *ResultBody
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rs := recordsOfType[ResultBody](t, e.readSessionRecords(t, "s1"), "effect.http.result")
		if len(rs) > 0 && rs[len(rs)-1].Upstream != nil {
			r := rs[len(rs)-1]
			result = &r
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if result == nil {
		t.Fatal("no result record with an upstream object")
	}
	if net.ParseIP(result.Upstream.IP) == nil {
		t.Fatalf("upstream.ip = %q is not an IP address; 04 §2 step 3 requires the resolved address to be recorded",
			result.Upstream.IP)
	}
	if result.Upstream.Port != 443 {
		t.Errorf("upstream.port = %d, want 443", result.Upstream.Port)
	}
}
