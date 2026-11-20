// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Package inspect implements inference-traffic inspection (M8): it parses
// the byte stream between an unmodified agent and its model provider and
// extracts declared tool-use intents, tool results and context
// observations. It never buffers a whole response: parsers are incremental
// and report, for every completed tool-use block, the absolute byte offset
// at which forwarding must pause until the intent's record is durable.
//
// Providers (spec/04 §5.1): Anthropic Messages (non-streaming JSON and
// server-sent events), OpenAI Responses and OpenAI Chat Completions
// (both shapes each). tool_use/function_call blocks yield executor
// "sandbox"; provider-executed calls (server_tool_use, hosted *_call
// items) yield executor "provider".
package inspect

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Executor names for spec/03 §4.4 intent.declared.executor.
const (
	ExecutorSandbox  = "sandbox"
	ExecutorProvider = "provider"
)

// Provider identifiers used in intent.* records.
const (
	ProviderAnthropic = "anthropic"
	ProviderResponses = "openai-responses"
	ProviderChat      = "openai-chat"
)

// Intent is one completed tool-use call extracted from a model response.
// InputRaw is the input JSON exactly as transmitted (assembled from
// streamed fragments for SSE); InputSHA256 is the RFC 8785 canonical
// digest of the parsed input — the digest spec/04 §6.3 compares.
type Intent struct {
	ID          string
	Tool        string
	Executor    string
	InputRaw    []byte
	InputSHA256 string
	Model       string
}

// Completion marks a finished tool-use block. HoldAt is the absolute
// response-body offset of the first byte that may not reach the client
// until the intent is durably recorded: for SSE it is the offset of the
// completing event's first byte; for non-streaming JSON it is the offset
// of the block element's closing '}' byte. Bytes at or after HoldAt are
// "the bytes completing the tool-use block" (spec/03 §4.5, M8.1).
type Completion struct {
	HoldAt int64
	Intent *Intent
}

// errParse marks a malformed response: the fail-safe of spec/04 §5.4
// (bytes still flow, intent.unparsed is written, nothing is declared
// after this point).
type errParse struct{ detail string }

func (e *errParse) Error() string { return e.detail }

// ParseError returns the failure detail when err is a stream-shape
// violation, and whether err is such a violation at all.
func ParseError(err error) (string, bool) {
	var pe *errParse
	if errors.As(err, &pe) {
		return pe.detail, true
	}
	return "", false
}

func parseErrf(format string, args ...any) error {
	return &errParse{detail: fmt.Sprintf(format, args...)}
}

// ResponseParser consumes upstream response-body bytes in order.
//
// Feed may return completions and a *errParse together: completions
// before the fault are still valid; everything after is not parsed.
// A parse error is terminal — the caller stops feeding and records
// intent.unparsed.
//
// Finish is called once at body end (or on upstream-close). It reports
// whether the response completed cleanly; a non-empty detail means the
// stream was truncated or left an incomplete block and intent.unparsed
// must be written (declared intents stay declared).
type ResponseParser interface {
	Feed(b []byte) ([]Completion, error)
	Finish() (detail string, clean bool)
	Model() string
	// Pending is the smallest absolute response-body offset at which a
	// completion's hold point could still begin: bytes below it are
	// unconditionally releasable. SSE shapes report the in-flight
	// event's first byte — a completing event must not cross the client
	// in pieces before its intent is durable, so the whole event waits.
	// JSON shapes report the fed length: a completion always fires on
	// the feed carrying its completing byte, so nothing buffered can
	// still carry a hold.
	Pending() int64
}

// sha256Hex is the lowercase hex digest of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
