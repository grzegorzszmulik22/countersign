// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

// Red-team reproduction: appends to one session's record log are not
// serialized with the eseq/eprev chain assignment. Under a burst of
// concurrent requests the JSONL file is not in chain order: 03 §2 says
// eseq "increments by exactly 1" and eprev is the previous record's hash
// for that emitter; §7 requires records.jsonl in log order; V5 rejects a
// gap/reuse/mismatch as E_CHAIN. A client can therefore make its own
// session's evidence fail verification with ordinary concurrent traffic.
//
// Run: go test -tags fixtures ./internal/proxy -run TestRTRecordOrder -count=1 -v

package proxy

import (
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestRTRecordOrder(t *testing.T) {
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

	cli := e.proxyClient(t, "tok-one", pool, "h2")
	tr := cli.Transport.(*http.Transport)
	tr.MaxConnsPerHost = 200
	tr.MaxIdleConnsPerHost = 200

	const (
		rounds   = 3
		requests = 120
	)
	wantTotal := 0
	for round := 0; round < rounds; round++ {
		var wg sync.WaitGroup
		for i := 0; i < requests; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := cli.Get("https://allowed.example.com/load")
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
			}()
		}
		wg.Wait()
		wantTotal += 2 * requests // each allowed request: effect + result

		// Result records are appended by the handler's deferred writer; wait
		// for the expected count before judging file order.
		deadline := time.Now().Add(10 * time.Second)
		var recs []Record
		for {
			recs = e.readSessionRecords(t, "s1")
			if len(recs) >= wantTotal || time.Now().After(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if len(recs) < wantTotal {
			t.Fatalf("round %d: only %d records after %d requests (want %d)", round, len(recs), requests, wantTotal)
		}
		if recs[0].Eseq != 0 {
			t.Fatalf("file order is not chain order: first line has eseq %d, want 0 (round %d, %d records)",
				recs[0].Eseq, round, len(recs))
		}
		for i := 1; i < len(recs); i++ {
			if recs[i].Eseq != recs[i-1].Eseq+1 {
				t.Fatalf("file order breaks the emitter chain at line %d: eseq %d after %d (round %d); "+
					"03 §2 requires eseq previous+1 and eprev=previous record hash in log order (E_CHAIN)",
					i, recs[i].Eseq, recs[i-1].Eseq, round)
			}
		}
	}
}
