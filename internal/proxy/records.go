// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Records emitted by the broker. Two sinks implement the write-ahead
// contract of M2.4: FileRecordSink (per-session JSONL, the test seam) and
// LedgerSink (the real internal/ledger DSSE+Merkle path, wired by
// --ledger-dir). The sink is synchronous: an append returns only once the
// record is durable, which is the write-ahead ordering property C2.4.1
// measures. Chain fields (eseq/eprev) are assigned inside the sink's
// critical section so a concurrent pair of requests can neither interleave
// sequence numbers nor write the chain out of log order (B2-02).

package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Record is one line in a session's record file.
type Record struct {
	V       int             `json:"v"`
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	Session string          `json:"session"`
	Emitter string          `json:"emitter"`
	Eseq    uint64          `json:"eseq"`
	Eprev   string          `json:"eprev"`
	TS      string          `json:"ts"`
	Body    json.RawMessage `json:"body"`
}

// EffectHTTPBody is the body of an effect.http record (03 §4.2).
type EffectHTTPBody struct {
	EffectID      string         `json:"effect_id"`
	Actor         string         `json:"actor"`
	ConnID        string         `json:"conn_id"`
	Client        ClientAddr     `json:"client"`
	Request       RequestRecord  `json:"request"`
	RequestDigest string         `json:"request_digest,omitempty"`
	Class         string         `json:"class"`
	Decision      DecisionRecord `json:"decision"`
	Attribution   Attribution    `json:"attribution"`
	Taint         []string       `json:"taint"`
	Budget        BudgetRecord   `json:"budget"`
	Inspect       string         `json:"inspect"`
}

// ClientAddr is the sandbox-side peer of a proxy connection.
type ClientAddr struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// RequestRecord is the recorded form of a client request.
type RequestRecord struct {
	Method       string   `json:"method"`
	Scheme       string   `json:"scheme"`
	Authority    string   `json:"authority"`
	Path         string   `json:"path"`
	QuerySHA256  string   `json:"query_sha256"`
	QueryLen     int      `json:"query_len"`
	HeaderNames  []string `json:"header_names"`
	BodySHA256   string   `json:"body_sha256,omitempty"`
	BodyLen      int64    `json:"body_len"`
	BodyDeferred bool     `json:"body_deferred"`
}

// DecisionRecord is the policy outcome attached to an effect.
type DecisionRecord struct {
	Action   string   `json:"action"`
	Reason   string   `json:"reason"`
	Requires string   `json:"requires"`
	Grant    string   `json:"grant,omitempty"`
	Creds    []string `json:"credentials"`
}

// Attribution is empty until M8-M11; the field is part of the 03 §4.2 shape.
type Attribution struct {
	Level   string   `json:"level"`
	Intents []string `json:"intents"`
	Lineage *string  `json:"lineage"`
}

// BudgetRecord is the budget this effect charged (M13); zero in local mode.
type BudgetRecord struct {
	LeakBytes int64 `json:"leak_bytes"`
	Writes    int   `json:"writes"`
}

// DeniedBody is the body of an effect.denied record: a rejection before a
// full HTTP request existed (03 §4.2).
type DeniedBody struct {
	ConnID    string     `json:"conn_id"`
	Client    ClientAddr `json:"client"`
	Authority string     `json:"authority,omitempty"`
	Reason    string     `json:"reason"`
	Detail    string     `json:"detail,omitempty"`
}

// TunnelBody is the body of an effect.tunnel record: a passthrough CONNECT
// or a granted WebSocket upgrade (03 §4.2).
type TunnelBody struct {
	EffectID  string         `json:"effect_id"`
	Authority string         `json:"authority"`
	SNI       string         `json:"sni,omitempty"`
	Kind      string         `json:"kind"` // passthrough | websocket
	Decision  DecisionRecord `json:"decision"`
}

// TunnelResultBody is the body of an effect.tunnel.result record, written
// when the relayed stream ends (03 §4.2).
type TunnelResultBody struct {
	EffectID   string  `json:"effect_id"`
	BytesUp    int64   `json:"bytes_up"`
	BytesDown  int64   `json:"bytes_down"`
	DurationMS float64 `json:"duration_ms"`
	Error      string  `json:"error,omitempty"`
}

// ResultBody is the body of an effect.http.result record (03 §4.2).
type ResultBody struct {
	EffectID    string          `json:"effect_id"`
	ServedBy    string          `json:"served_by"`
	Status      int             `json:"status,omitempty"`
	Response    ResponseRecord  `json:"response"`
	RequestBody BodyDigest      `json:"request_body"`
	ReqDigest   string          `json:"request_digest,omitempty"`
	Upstream    *UpstreamRecord `json:"upstream,omitempty"`
	Timing      TimingRecord    `json:"timing"`
	Scrubbed    int             `json:"scrubbed"`
	Error       string          `json:"error,omitempty"`
}

// ResponseRecord is the recorded form of an upstream response.
type ResponseRecord struct {
	HeaderNames []string `json:"header_names"`
	BodySHA256  string   `json:"body_sha256"`
	BodyLen     int64    `json:"body_len"`
}

// BodyDigest is a streamed body's digest and length (result records).
type BodyDigest struct {
	SHA256 string `json:"sha256"`
	Len    int64  `json:"len"`
}

// UpstreamRecord identifies the connection that served the request.
type UpstreamRecord struct {
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	TLSVersion string `json:"tls_version,omitempty"`
	ALPN       string `json:"alpn,omitempty"`
	CertSHA256 string `json:"cert_sha256,omitempty"`
}

// TimingRecord carries total and time-to-first-byte in milliseconds.
type TimingRecord struct {
	TotalMS float64 `json:"total_ms"`
	TTFBMS  float64 `json:"ttfb_ms"`
}

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// RecordSink is the broker's write-ahead append interface. Implementations
// must return only after the record is durable. The sink owns chain
// assignment: it stamps the record's V/ID/Session/Emitter/Eseq/Eprev under
// its per-session critical section (B2-02). Callers fill only Type, TS and
// Body.
type RecordSink interface {
	// Append writes rec under session; returns once durable.
	Append(session string, rec *Record) error
	// PendingEffects lists effects with no terminal record, for the
	// restart dangling scan (M2.4). Called before the first Append.
	PendingEffects() ([]PendingEffect, error)
	// Close flushes and closes the sink.
	Close() error
}

// PendingEffect names an effect that never reached a terminal record —
// what a restart scan reports as dangling (M2.4).
type PendingEffect struct {
	Session  string
	Type     string // effect.http | effect.tunnel
	EffectID string
}

// FileRecordSink appends one JSON line per record to
// <dir>/<session>.jsonl, fsyncing before returning. Lines that cannot be
// attributed to a session go to broker.log instead (see Server.Logf).
type FileRecordSink struct {
	dir     string
	emitter string
	mu      sync.Mutex
	files   map[string]*os.File
	chains  map[string]*sessionChain
}

// NewFileRecordSink creates (or reuses) a records directory. emitter is
// the "broker/<instance>" name stamped on every record.
func NewFileRecordSink(dir, emitter string) (*FileRecordSink, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("records dir: %w", err)
	}
	return &FileRecordSink{dir: dir, emitter: emitter,
		files: map[string]*os.File{}, chains: map[string]*sessionChain{}}, nil
}

// Dir returns the records directory.
func (s *FileRecordSink) Dir() string { return s.dir }

// Append implements RecordSink: chain assignment and the durable write
// share one critical section. Any failure rolls the file back to the
// pre-append offset and restores the chain, so a failed append neither
// consumes an eseq nor leaves a torn line behind.
func (s *FileRecordSink) Append(session string, rec *Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.files[session]
	if !ok {
		var err error
		name := filepath.Join(s.dir, safeFileName(session)+".jsonl")
		f, err = os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("record file: %w", err)
		}
		s.files[session] = f
	}
	ch := s.chains[session]
	if ch == nil {
		ch = &sessionChain{eprev: zeroHash}
		s.chains[session] = ch
	}
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("record stat: %w", err)
	}
	off := fi.Size()
	eseq, eprev := ch.eseq, ch.eprev
	if err := ch.fill(rec, s.emitter, session); err != nil {
		return err
	}
	fail := func(err error) error {
		// Best effort: the file position after a partial write is
		// already accounted in off; truncate drops whatever landed.
		_ = f.Truncate(off)
		ch.eseq, ch.eprev = eseq, eprev
		return err
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return fail(fmt.Errorf("record marshal: %w", err))
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fail(fmt.Errorf("record write: %w", err))
	}
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("record fsync: %w", err))
	}
	return nil
}

// PendingEffects scans the records directory for effects that never
// reached a terminal record — what a restart reports as dangling (M2.4).
// It must be called before the first Append of a run.
func (s *FileRecordSink) PendingEffects() ([]PendingEffect, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	open := map[string]map[string]bool{}
	for _, ent := range ents {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".jsonl") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, ent.Name()))
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if line == "" {
				continue
			}
			var r Record
			if json.Unmarshal([]byte(line), &r) != nil {
				continue
			}
			markPending(open, r)
		}
	}
	return collectPending(open), nil
}

// markPending folds one record into the dangling scan: effects open a
// pending entry, result/denied records close the matching one.
func markPending(open map[string]map[string]bool, r Record) {
	if r.Session == "" {
		return
	}
	effectID := ""
	switch r.Type {
	case "effect.http", "effect.tunnel":
		var b struct {
			EffectID string `json:"effect_id"`
			Decision struct {
				Action string `json:"action"`
			} `json:"decision"`
		}
		if json.Unmarshal(r.Body, &b) == nil && b.EffectID != "" {
			// A deny-decision effect is terminal: no result follows it.
			if b.Decision.Action != "deny" {
				effectID = r.Type + "/" + b.EffectID
			}
		}
	case "effect.http.result", "effect.tunnel.result":
		var b struct {
			EffectID string `json:"effect_id"`
		}
		if json.Unmarshal(r.Body, &b) == nil {
			delete(open[r.Session], r.Type[:len(r.Type)-len(".result")]+"/"+b.EffectID)
			return
		}
	default:
		return
	}
	if effectID != "" {
		m := open[r.Session]
		if m == nil {
			m = map[string]bool{}
			open[r.Session] = m
		}
		m[effectID] = true
	}
}

// collectPending renders the open-effect map into a flat list.
func collectPending(open map[string]map[string]bool) []PendingEffect {
	var out []PendingEffect
	for sess, m := range open {
		for key := range m {
			typ, id, _ := strings.Cut(key, "/")
			out = append(out, PendingEffect{Session: sess, Type: typ, EffectID: id})
		}
	}
	return out
}

// Close implements RecordSink.
func (s *FileRecordSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var first error
	for _, f := range s.files {
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
	}
	s.files = map[string]*os.File{}
	return first
}

func safeFileName(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			out = append(out, c)
		} else {
			out = append(out, '_')
		}
	}
	return string(out)
}

// sessionChain tracks eseq/eprev for one session's record chain.
type sessionChain struct {
	eseq  uint64
	eprev string
}

// fill stamps the record's identity fields and advances the chain. The
// caller owns rollback (restore eseq/eprev) when the durable write fails.
func (c *sessionChain) fill(rec *Record, emitter, session string) error {
	rec.V = 1
	if rec.ID == "" {
		rec.ID = newULID()
	}
	rec.Session = session
	rec.Emitter = emitter
	rec.Eseq = c.eseq
	rec.Eprev = c.eprev
	if rec.TS == "" {
		rec.TS = nowTS()
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(line)
	c.eprev = hex.EncodeToString(sum[:])
	c.eseq++
	return nil
}

// nowTS renders the record timestamp (03 §2: RFC3339 UTC, ns precision).
func nowTS() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.999999999Z")
}
