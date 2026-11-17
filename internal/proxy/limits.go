// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/countersign/countersign/internal/policy"
)

// Request limits (04 §1 limits, M3.5): body size, URL size, and a
// per-(session, grant) token bucket for requests-per-minute with burst =
// one tenth of the per-minute value. LIMIT_BODY / LIMIT_URL / LIMIT_RATE
// are the deny reasons (04 §2 step 4).

// errBodyLimit is the sentinel a capBody reader returns once the upstream
// stream passes maxRequestBodyBytes; forward maps it to result.error
// "limit-body" (C3.5.3).
var errBodyLimit = errors.New("countersign: request body limit")

// checkLimits runs 04 §2 step 4's pre-body clauses. "" means proceed.
func checkLimits(grant *policy.Grant, r *http.Request, tgt forwardTarget) string {
	if grant == nil || grant.Limits == nil {
		return ""
	}
	lim := grant.Limits
	if lim.MaxURLBytes != nil &&
		int64(len(tgt.path)+len(tgt.rawQuery)) > int64(*lim.MaxURLBytes) {
		return "LIMIT_URL"
	}
	if lim.MaxRequestBodyBytes != nil && r.ContentLength > int64(*lim.MaxRequestBodyBytes) {
		return "LIMIT_BODY"
	}
	return ""
}

// maxBody returns the grant's request-body cap, 0 when unset.
func maxBody(grant *policy.Grant) int64 {
	if grant != nil && grant.Limits != nil && grant.Limits.MaxRequestBodyBytes != nil {
		return int64(*grant.Limits.MaxRequestBodyBytes)
	}
	return 0
}

// capBody wraps a request body so reads fail with errBodyLimit once total
// (buffered prefix + streamed remainder) crosses max. The upstream
// connection dies with the aborted write — the wire never sees a byte
// past the cap (C3.5.3).
type capBody struct {
	r     io.Reader
	count int64
	max   int64
}

func (c *capBody) Read(b []byte) (int, error) {
	if c.count >= c.max {
		return 0, errBodyLimit
	}
	if int64(len(b)) > c.max-c.count {
		b = b[:c.max-c.count]
	}
	n, err := c.r.Read(b)
	c.count += int64(n)
	if err == io.EOF {
		return n, io.EOF
	}
	if err != nil {
		return n, err
	}
	if c.count >= c.max {
		return n, errBodyLimit
	}
	return n, nil
}

// rateTable is the per-session bucket set: one token bucket per grant ID
// (04 §1: requests-per-minute is per (session, grant)). A Session owns
// its table, so isolation across sessions is structural.
type rateTable struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	now     func() time.Time // tests may inject a clock
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func newRateTable() *rateTable {
	return &rateTable{buckets: map[string]*tokenBucket{}, now: time.Now}
}

// take reports whether one request may proceed under grant's rpm. Buckets
// lazily fill to the burst cap (rpm/10, floor 1) and refill at rpm/60 per
// second; each admission costs one token.
func (t *rateTable) take(grantID string, rpm int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.buckets[grantID]
	now := t.now()
	if b == nil {
		b = &tokenBucket{tokens: burstCap(rpm), last: now}
		t.buckets[grantID] = b
	}
	if d := now.Sub(b.last).Seconds(); d > 0 {
		b.tokens += d * float64(rpm) / 60.0
		if cap := burstCap(rpm); b.tokens > cap {
			b.tokens = cap
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// burstCap is one tenth of the per-minute value (04 §1), floored at one
// token so low rpm values still admit a single request per window.
func burstCap(rpm int) float64 {
	if c := float64(rpm) / 10.0; c >= 1 {
		return c
	}
	return 1
}
