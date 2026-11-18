// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// LedgerSink is the production record sink of M2.4: every broker record is
// converted to the canonical evidence body of spec/03 §4.2, signed by the
// session's broker emitter and appended to internal/ledger's Merkle log —
// Append returns only after the record is durable (the write-ahead
// property C2.4.1 measures). A failure poisons the sink: once the ledger
// cannot be trusted every later append fails too, which is what
// fail-closed means (02 §6: no fail-open mode exists).

package proxy

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/ledger"
)

// sinkEmitter is one session's broker emitter chain inside the sink: the
// keys.Emitter plus the chain head tracking a session.seal needs.
type sinkEmitter struct {
	em   *keys.Emitter
	eseq uint64
	head string
	n    int
}

// LedgerSink appends signed evidence records to a ledger directory. Each
// session gets a fresh "broker/<instance>" emitter chain on first use.
type LedgerSink struct {
	led    *ledger.Ledger
	signer keys.Signer
	mu     sync.Mutex
	ems    map[string]*sinkEmitter
	failed error
}

// NewLedgerSink opens (or creates) the ledger at dir. logSigner signs
// checkpoints (may be nil for a ledger that never checkpoints); signer
// signs the broker emitter's records.
func NewLedgerSink(dir, origin string, logSigner, signer keys.Signer) (*LedgerSink, error) {
	led, err := ledger.Open(dir, origin, logSigner)
	if err != nil {
		return nil, fmt.Errorf("ledger: %w", err)
	}
	return &LedgerSink{led: led, signer: signer, ems: map[string]*sinkEmitter{}}, nil
}

// Ledger exposes the underlying ledger (bundle export, restart scans).
func (s *LedgerSink) Ledger() *ledger.Ledger { return s.led }

// Append implements RecordSink: convert, sign, append, wait for durable.
// The whole conversion+append runs under the sink mutex so per-session
// order is exactly the caller's enqueue order (B2-02); a failure poisons
// the sink — a ledger that took a bad record or dropped one is no longer
// a write-ahead store at all.
func (s *LedgerSink) Append(session string, rec *Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return s.failed
	}
	body, err := evidenceBody(rec.Type, rec.Body)
	if err != nil {
		s.failed = err
		return err
	}
	se := s.ems[session]
	if se == nil {
		se = &sinkEmitter{em: keys.NewEmitter("broker", session, s.signer), head: evidence.ZeroHash}
		s.ems[session] = se
	}
	ts := rec.TS
	if ts == "" {
		ts = nowTS()
	}
	line, erec, err := se.em.Emit(rec.Type, body, ts)
	if err != nil {
		s.failed = fmt.Errorf("emit: %w", err)
		return s.failed
	}
	if _, err := s.led.Append(line); err != nil {
		s.failed = fmt.Errorf("ledger append: %w", err)
		return s.failed
	}
	env, _, _, err := evidence.DecodeRecordLine(line)
	if err != nil {
		s.failed = fmt.Errorf("emitted line undecodable: %w", err)
		return s.failed
	}
	se.eseq = erec.Eseq
	se.head = evidence.RecordHash(env)
	se.n++
	return nil
}

// SealSession emits emitter.seal on the session's broker chain and
// returns its SealEmitter entry — what a session.seal record written by
// the session's controller emitter names for the broker (the shutdown
// path's honest accounting of how far the chain got).
func (s *LedgerSink) SealSession(session string) (evidence.SealEmitter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return evidence.SealEmitter{}, s.failed
	}
	se := s.ems[session]
	if se == nil {
		return evidence.SealEmitter{}, fmt.Errorf("no broker records for session %s", session)
	}
	if err := s.appendLocked(session, "emitter.seal", &evidence.EmitterSealBody{Final: true}); err != nil {
		return evidence.SealEmitter{}, err
	}
	// The seal entry names the chain head AFTER emitter.seal landed —
	// emitter.seal is the last record of the chain (chainEmitter.sealRef
	// semantics: captured after the emit).
	clean := se.n == int(se.eseq)+1
	return evidence.SealEmitter{
		Emitter: se.em.Name(), FinalEseq: se.eseq, HeadHash: se.head, Clean: clean,
	}, nil
}

// appendLocked is Append's inner loop with the mutex already held: emit,
// ledger-append, head update. Only for record types a sink emitter can
// produce verbatim (emitter.seal — the sink's own lifecycle record).
func (s *LedgerSink) appendLocked(session, rtype string, body any) error {
	se := s.ems[session]
	line, erec, err := se.em.Emit(rtype, body, nowTS())
	if err != nil {
		s.failed = fmt.Errorf("emit: %w", err)
		return s.failed
	}
	if _, err := s.led.Append(line); err != nil {
		s.failed = fmt.Errorf("ledger append: %w", err)
		return s.failed
	}
	env, _, _, err := evidence.DecodeRecordLine(line)
	if err != nil {
		s.failed = fmt.Errorf("emitted line undecodable: %w", err)
		return s.failed
	}
	se.eseq = erec.Eseq
	se.head = evidence.RecordHash(env)
	se.n++
	return nil
}

// PendingEffects scans the ledger for effects without a terminal record
// (the restart dangling scan of M2.4).
func (s *LedgerSink) PendingEffects() ([]PendingEffect, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return PendingInLedger(s.led)
}

// PendingInLedger scans an open ledger for effects with no terminal
// record. Exported so the runner's bridge sink can run the same scan on
// its own ledger.
func PendingInLedger(led *ledger.Ledger) ([]PendingEffect, error) {
	open := map[string]map[string]bool{}
	n := led.Size()
	for i := uint64(0); i < n; i++ {
		line, err := led.Line(i)
		if err != nil {
			return nil, err
		}
		_, _, r, err := evidence.DecodeRecordLine(line)
		if err != nil {
			continue
		}
		raw, err := json.Marshal(r.Body)
		if err != nil {
			continue
		}
		markPending(open, Record{Type: r.Type, Session: r.Session, Body: raw})
	}
	return collectPending(open), nil
}

// Close flushes and closes the ledger.
func (s *LedgerSink) Close() error {
	if s.failed != nil {
		// The ledger still needs its files closed; a poisoned sink is
		// not a reason to leak descriptors.
		return s.led.Close()
	}
	return s.led.Close()
}

// evidenceBody converts a broker record body to its canonical evidence
// form (03 §4.2). Unknown types fail closed — a record we cannot
// represent is a boundary bug, not something to drop silently.
func evidenceBody(rtype string, raw json.RawMessage) (any, error) {
	switch rtype {
	case "effect.http":
		var p EffectHTTPBody
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
			Decision:      evidenceDecision(p.Decision),
			Attribution: evidence.Attribution{
				Level:   evidenceLevel(p.Attribution.Level),
				Intents: strs(p.Attribution.Intents),
				Lineage: "off",
			},
			Taint:   strs(p.Taint),
			Budget:  evidence.Budget{LeakBytes: uint64(p.Budget.LeakBytes), Writes: uint64(p.Budget.Writes)},
			Inspect: p.Inspect,
		}, nil
	case "effect.http.result":
		var p ResultBody
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
	case "effect.tunnel":
		var p TunnelBody
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		return &evidence.EffectTunnelBody{
			EffectID:  p.EffectID,
			Authority: p.Authority,
			SNI:       strp(p.SNI),
			Kind:      p.Kind,
			Decision:  evidenceDecision(p.Decision),
		}, nil
	case "effect.tunnel.result":
		var p TunnelResultBody
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		return &evidence.EffectTunnelResultBody{
			EffectID:   p.EffectID,
			BytesUp:    uint64(p.BytesUp),
			BytesDown:  uint64(p.BytesDown),
			DurationMS: p.DurationMS,
			Error:      strp(p.Error),
		}, nil
	case "effect.denied":
		var p DeniedBody
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
	return nil, fmt.Errorf("unknown record type %q", rtype)
}

func evidenceDecision(d DecisionRecord) evidence.Decision {
	return evidence.Decision{
		Action:      d.Action,
		Reason:      d.Reason,
		Requires:    d.Requires,
		Grant:       strp(d.Grant),
		Credentials: strs(d.Creds),
	}
}

// evidenceLevel maps the broker's attribution field to the 03 §4.2 enum.
func evidenceLevel(level string) string {
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
