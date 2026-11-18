// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/proxy"
)

// bridgeSink is the broker's RecordSink: every record the broker appends
// is converted into the canonical evidence body of spec/03 §4.2, signed
// by the session's broker emitter and appended to the ledger before
// Append returns (the write-ahead ordering the sink contract requires).
type bridgeSink struct {
	em     *chainEmitter
	mu     sync.Mutex
	failed error
}

func newBridge(em *chainEmitter) *bridgeSink { return &bridgeSink{em: em} }

func (b *bridgeSink) Append(session string, rec *proxy.Record) error {
	body, err := bridgeBody(rec.Type, rec.Body)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failed != nil {
		return b.failed
	}
	if err != nil {
		b.failed = err
		return err
	}
	if err := b.em.emit(rec.Type, body); err != nil {
		b.failed = err
		return err
	}
	return nil
}

func (b *bridgeSink) Close() error { return nil }

func (b *bridgeSink) err() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failed
}

// bridgeBody converts a broker JSON body to its evidence twin. Unknown
// record types fail closed: a record we cannot represent is a boundary
// bug, not something to drop silently.
func bridgeBody(rtype string, raw json.RawMessage) (any, error) {
	switch rtype {
	case "effect.http":
		var p proxy.EffectHTTPBody
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		return &evidence.EffectHTTPBody{
			EffectID: p.EffectID,
			Actor:    "sandbox",
			ConnID:   p.ConnID,
			Client:   evidence.Client{IP: p.Client.IP, Port: int64(p.Client.Port)},
			Request: evidence.HTTPRequest{
				Method:       p.Request.Method,
				Scheme:       p.Request.Scheme,
				Authority:    p.Request.Authority,
				Path:         p.Request.Path,
				QuerySHA256:  p.Request.QuerySHA256,
				QueryLen:     uint64(p.Request.QueryLen),
				HeaderNames:  strs(p.Request.HeaderNames),
				BodySHA256:   strp(p.Request.BodySHA256),
				BodyLen:      uptr(p.Request.BodyLen),
				BodyDeferred: p.Request.BodyDeferred,
			},
			RequestDigest: strp(p.RequestDigest),
			Class:         p.Class,
			Decision:      bridgeDecision(p.Decision),
			Attribution: evidence.Attribution{
				Level:   bridgeLevel(p.Attribution.Level),
				Intents: strs(p.Attribution.Intents),
				Lineage: "off",
			},
			Taint:   strs(p.Taint),
			Budget:  evidence.Budget{LeakBytes: uint64(p.Budget.LeakBytes), Writes: uint64(p.Budget.Writes)},
			Inspect: p.Inspect,
		}, nil
	case "effect.http.result":
		var p proxy.ResultBody
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		var up *evidence.UpstreamRef
		if p.Upstream != nil {
			up = &evidence.UpstreamRef{
				IP:         p.Upstream.IP,
				Port:       int64(p.Upstream.Port),
				TLSVersion: strp(p.Upstream.TLSVersion),
				CertSHA256: strp(p.Upstream.CertSHA256),
			}
		}
		var status *int64
		if p.Status != 0 {
			v := int64(p.Status)
			status = &v
		}
		return &evidence.EffectHTTPResultBody{
			EffectID: p.EffectID,
			ServedBy: p.ServedBy,
			Status:   status,
			Response: evidence.HTTPResponse{
				HeaderNames: strs(p.Response.HeaderNames),
				BodySHA256:  p.Response.BodySHA256,
				BodyLen:     uint64(p.Response.BodyLen),
			},
			RequestBody: evidence.RequestBodyRef{SHA256: p.RequestBody.SHA256, Len: uint64(p.RequestBody.Len)},
			Upstream:    up,
			Timing:      evidence.Timing{TotalMS: p.Timing.TotalMS, TTFBMS: p.Timing.TTFBMS},
			Scrubbed:    uint64(p.Scrubbed),
			Error:       strp(p.Error),
		}, nil
	case "effect.denied":
		var p proxy.DeniedBody
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		return &evidence.EffectDeniedBody{
			ConnID:    p.ConnID,
			Client:    evidence.Client{IP: p.Client.IP, Port: int64(p.Client.Port)},
			Authority: strp(p.Authority),
			Reason:    p.Reason,
			Detail:    p.Detail,
		}, nil
	}
	return nil, fmt.Errorf("bridge: unknown record type %q", rtype)
}

func bridgeDecision(d proxy.DecisionRecord) evidence.Decision {
	return evidence.Decision{
		Action:      d.Action,
		Reason:      d.Reason,
		Requires:    d.Requires,
		Grant:       strp(d.Grant),
		Credentials: strs(d.Creds),
	}
}

// The broker predates the attribution enum: it emits "none" where 03
// §4.2 writes NONE.
func bridgeLevel(level string) string {
	if level == "" || strings.EqualFold(level, "none") {
		return "NONE"
	}
	return strings.ToUpper(level)
}

func strp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func uptr(n int64) *uint64 {
	if n < 0 {
		return nil
	}
	v := uint64(n)
	return &v
}

func strs(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
