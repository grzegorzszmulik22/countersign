// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

// Red-team reproduction: 04 §2 step 3 requires the broker to resolve a
// granted name once and refuse it with UPSTREAM_BLOCKED when the resolved
// address is loopback, link-local, private, unique-local or a cluster
// range, unless the grant sets network: cluster. The default is public.
// In this build there is no address check at all: the harness resolver
// points the granted name at a loopback sink and the broker dials it,
// delivering the canary. This is the documented M2.5 gap (spec/PROGRESS.md
// says M2.5 is TODO; docs/policy-schema.md says §2 steps 3-6 are later
// chunks), reproduced here because the brief's first goal is exfiltration
// via DNS answers under the harness resolver.
//
// Run: go test -tags fixtures ./internal/proxy -run TestRTDNSUpstreamBlocked -count=1 -v

package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRTDNSUpstreamBlocked(t *testing.T) {
	dir := t.TempDir()
	// network is unset: 04 §1 default is public.
	pol := writePolicy(t, dir, "p", `  grants:
    - id: allowed
      match: {hosts: [allowed.example.com]}
`)
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{sessionEntry("s1", "tok-one", "127.0.0.1", pol)}, routes)

	// The sink is a loopback listener we started; the broker is given a DNS
	// answer pointing the granted name at it.
	sink := &rtHits{}
	sAddr, closeSink := startTLSUpstream(t, e.ca, []string{"allowed.example.com"}, nil, sink)
	defer closeSink()
	routes["allowed.example.com"] = sAddr

	pool := e.combinedPool(t, "s1")
	cli := e.proxyClient(t, "tok-one", pool)

	res, err := cli.Post("https://allowed.example.com/exfil", "text/plain", strings.NewReader("CANARY-RT-DNS"))
	if err == nil {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}

	hits := sink.snapshot()
	if len(hits) > 0 {
		t.Fatalf("granted name resolved to a loopback address and the broker dialed it: sink received %s %s body=%q "+
			"(status %d, client err %v); 04 §2 step 3 requires UPSTREAM_BLOCKED for a loopback answer under network: public",
			hits[0].Method, hits[0].RequestURI, hits[0].Body, statusOf(res), err)
	}
	if err == nil && res.StatusCode != 403 && res.StatusCode != 502 {
		t.Fatalf("loopback upstream: status %d, want a refusal", res.StatusCode)
	}
}

func statusOf(res *http.Response) int {
	if res == nil {
		return 0
	}
	return res.StatusCode
}
