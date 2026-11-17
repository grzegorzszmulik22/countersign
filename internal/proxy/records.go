// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Records emitted by the broker. The evidence core (internal/evidence,
// internal/ledger) is owned by the M1/M2.4 lanes; until it lands the broker
// writes these records as one JSON line each under the records directory,
// with the body fields of spec/03 §4.2. The sink is synchronous: an append
// returns only once the line is durable (fsync), which is the write-ahead
// ordering property M2.4 re-checks against the real ledger.

package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
// must return only after the record is durable.
type RecordSink interface {
	// Append writes rec under session; returns once durable.
	Append(session string, rec *Record) error
	// Close flushes and closes the sink.
	Close() error
}

// FileRecordSink appends one JSON line per record to
// <dir>/<session>.jsonl, fsyncing before returning. Lines that cannot be
// attributed to a session go to broker.log instead (see Server.Logf).
type FileRecordSink struct {
	dir   string
	mu    sync.Mutex
	files map[string]*os.File
}

// NewFileRecordSink creates (or reuses) a records directory.
func NewFileRecordSink(dir string) (*FileRecordSink, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("records dir: %w", err)
	}
	return &FileRecordSink{dir: dir, files: map[string]*os.File{}}, nil
}

// Dir returns the records directory.
func (s *FileRecordSink) Dir() string { return s.dir }

// Append implements RecordSink.
func (s *FileRecordSink) Append(session string, rec *Record) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("record marshal: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.files[session]
	if !ok {
		name := filepath.Join(s.dir, safeFileName(session)+".jsonl")
		f, err = os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("record file: %w", err)
		}
		s.files[session] = f
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("record write: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("record fsync: %w", err)
	}
	return nil
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

func (c *sessionChain) next(bodyType string, body any, emitter, session string) (*Record, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	rec := &Record{
		V:       1,
		Type:    bodyType,
		ID:      newULID(),
		Session: session,
		Emitter: emitter,
		Eseq:    c.eseq,
		Eprev:   c.eprev,
		TS:      time.Now().UTC().Format("2006-01-02T15:04:05.999999999Z"),
		Body:    raw,
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(line)
	c.eprev = hex.EncodeToString(sum[:])
	c.eseq++
	return rec, nil
}
