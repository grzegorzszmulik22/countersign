// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

// Red-team reproduction: 04 §2 step 1 requires the broker to reject, with
// SMUGGLING_SUSPECT, requests carrying both Content-Length and
// Transfer-Encoding, obsolete line folding, or a bare LF in headers. The
// plain listener accepts and forwards all three (M2.5's pre-check corpus is
// listed TODO in spec/PROGRESS.md; this test records the property as it
// stands in the current tree).
//
// Run: go test -tags fixtures ./internal/proxy -run TestRTSmugglingPrechecks -count=1 -v

package proxy

import (
	"net/http"
	"strings"
	"testing"
)

func TestRTSmugglingPrechecks(t *testing.T) {
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
	cases := []struct {
		name string
		raw  string
	}{
		{"cl-and-te", "POST http://allowed.example.com/x HTTP/1.1\r\nHost: allowed.example.com\r\n" + auth +
			"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"},
		{"bare-lf", "GET http://allowed.example.com/x HTTP/1.1\nHost: allowed.example.com\n" + auth + "\n"},
		{"obs-fold", "GET http://allowed.example.com/x HTTP/1.1\r\nHost: allowed.example.com\r\n" + auth +
			"X-A: one\r\n two\r\n\r\n"},
	}
	for _, c := range cases {
		before := up.count()
		st, head, _, conn := e.rawProxyExchange(t, c.raw)
		_ = conn.Close()
		forwarded := up.count() > before
		if st != http.StatusForbidden || !strings.Contains(head, "SMUGGLING_SUSPECT") || forwarded {
			t.Errorf("%s: status=%d reason=%q upstream_forwarded=%v; 04 §2 step 1 requires 403 SMUGGLING_SUSPECT and no upstream request",
				c.name, st, headerReason(head), forwarded)
		}
	}
}

func headerReason(head string) string {
	for _, line := range strings.Split(head, "\n") {
		if strings.HasPrefix(strings.ToLower(line), "x-countersign-reason:") {
			return strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}
	return ""
}
