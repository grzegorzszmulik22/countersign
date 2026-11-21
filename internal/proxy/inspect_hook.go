// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Inference inspection hook (M8): the broker's only points of contact
// with internal/inspect. On grants with inspect: inference the request
// path selects the provider endpoint; the buffered request body feeds
// request parsing (intent.result, context.observed) after the
// effect.http write-ahead and before upstream; the response body flows
// through inspectPipe, which delays only the bytes completing a tool-use
// block until its intent.declared append is durable.
//
// Session state lives here (not on Session, which other lanes own) in a
// map keyed by session ID; it is created on the first inspected request
// and swept for seal-closure at Server.Close.
package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path"
	"sync"

	"github.com/countersign/countersign/internal/inspect"
	"github.com/countersign/countersign/internal/policy"
)

// ------------------------------------------------------------------
// record bodies (03 §4.4)

// IntentDeclaredBody is intent.declared for an inference source.
type IntentDeclaredBody struct {
	IntentID     string `json:"intent_id"`
	Source       string `json:"source"`
	Provider     string `json:"provider"`
	Model        string `json:"model,omitempty"`
	ViaEffect    string `json:"via_effect"`
	Tool         string `json:"tool"`
	Class        string `json:"class"`
	Executor     string `json:"executor"`
	InputSHA256  string `json:"input_sha256"`
	InputLen     int    `json:"input_len"`
	InputPreview string `json:"input_preview,omitempty"`
	AnchorSHA256 string `json:"anchor_sha256,omitempty"`
}

// IntentResultBody is intent.result: a closed intent window.
type IntentResultBody struct {
	IntentID      string `json:"intent_id"`
	ViaEffect     string `json:"via_effect"`
	ClosedBy      string `json:"closed_by"` // tool_result | seal | timeout
	ContentSHA256 string `json:"content_sha256,omitempty"`
	ContentLen    int    `json:"content_len,omitempty"`
	IsError       *bool  `json:"is_error,omitempty"`
}

// IntentUnparsedBody is intent.unparsed (spec/04 §5.4 fail-safe).
type IntentUnparsedBody struct {
	ViaEffect string `json:"via_effect"`
	Provider  string `json:"provider"`
	Detail    string `json:"detail"`
}

// ContextBlockBody is one new_blocks entry of context.observed.
type ContextBlockBody struct {
	Index    int    `json:"index"`
	Role     string `json:"role"`
	Kind     string `json:"kind"`
	SHA256   string `json:"sha256"`
	Len      int    `json:"len"`
	IntentID string `json:"intent_id,omitempty"`
}

// ContextObservedBody is context.observed (one per inference request).
type ContextObservedBody struct {
	ViaEffect     string             `json:"via_effect"`
	Provider      string             `json:"provider"`
	Model         string             `json:"model,omitempty"`
	BlockCount    int                `json:"block_count"`
	ContextSHA256 string             `json:"context_sha256"`
	NewBlocks     []ContextBlockBody `json:"new_blocks"`
}

// ------------------------------------------------------------------
// session state

var inspectStates sync.Map // session ID -> *inspectState

type classPattern struct {
	pat, class string
	star       bool
}

// inspectState is one session's inspection context: the tracker (window
// and context state) plus the session-immutable policy bits.
type inspectState struct {
	tracker      *inspect.Tracker
	previews     bool
	classes      map[string]string // exact tool names
	patterns     []classPattern    // glob tool patterns, literal-first
	commandField string
	// obsMu serializes the context fold, its context.observed append and
	// the commit-or-rollback: concurrent requests of one session observe
	// and record as an atomic step, so a failed request removes exactly
	// its own blocks and every recorded context_sha256 chains the blocks
	// recorded before it (spec/04 §5.3 running digest).
	obsMu sync.Mutex
}

// inspectStateFor returns the session's inspection state when the grant
// inspects inference traffic, else nil.
func (s *Server) inspectStateFor(sess *Session, grant *policy.Grant) *inspectState {
	if grant == nil || grant.Inspect != "inference" {
		return nil
	}
	if v, ok := inspectStates.Load(sess.ID); ok {
		return v.(*inspectState)
	}
	st := &inspectState{
		previews:     true,
		classes:      map[string]string{},
		commandField: "command",
	}
	spec := &sess.Policy.Spec
	if spec.Privacy != nil && spec.Privacy.Previews != nil {
		st.previews = *spec.Privacy.Previews
	}
	maxOpen := 3600
	if spec.MaxIntentOpenSeconds != nil {
		maxOpen = *spec.MaxIntentOpenSeconds
	}
	st.tracker = inspect.NewTracker(maxOpen)
	if spec.CommandField != "" {
		st.commandField = spec.CommandField
	}
	for pat, cls := range spec.ToolClasses {
		if hasGlob(pat) {
			st.patterns = append(st.patterns, classPattern{pat, cls, pat == "*"})
		} else {
			st.classes[pat] = cls
		}
	}
	// Deterministic glob order (the policy map lost document order):
	// named patterns alphabetically, catch-alls last.
	sortPatterns(st.patterns)
	actual, _ := inspectStates.LoadOrStore(sess.ID, st)
	return actual.(*inspectState)
}

func hasGlob(p string) bool {
	for _, c := range p {
		if c == '*' || c == '?' || c == '[' {
			return true
		}
	}
	return false
}

func sortPatterns(ps []classPattern) {
	for i := 1; i < len(ps); i++ {
		for j := i; j > 0 && patternLess(ps[j], ps[j-1]); j-- {
			ps[j], ps[j-1] = ps[j-1], ps[j]
		}
	}
}

func patternLess(a, b classPattern) bool {
	if a.star != b.star {
		return b.star // named before "*"
	}
	return a.pat < b.pat
}

// classOf resolves the tool's class (spec/04 §5.2): exact name, then
// glob patterns in sorted order; default "other".
func (st *inspectState) classOf(tool string) string {
	if c, ok := st.classes[tool]; ok {
		return c
	}
	for _, p := range st.patterns {
		if ok, _ := path.Match(p.pat, tool); ok {
			return p.class
		}
	}
	return "other"
}

// sealIntents closes every open intent window across sessions
// (closed_by: seal) — called once at Server.Close so no window is left
// dangling when the broker stops.
func (s *Server) sealIntents() {
	inspectStates.Range(func(k, v any) bool {
		sess := s.Session(k.(string))
		if sess == nil {
			return true
		}
		st := v.(*inspectState)
		for _, d := range st.tracker.Seal() {
			body := IntentResultBody{
				IntentID: d.ID, ViaEffect: d.ViaEffect, ClosedBy: "seal",
			}
			if err := s.appendRecord(sess, "intent.result", body); err != nil {
				s.Logf("seal intent.result for %s failed: %v", d.ID, err)
			}
		}
		return true
	})
}

// ------------------------------------------------------------------
// request path

// inspectRequest runs the M8.3 request side on a buffered inference
// request body: timeout sweep, intent.result for carried tool results,
// context.observed for new blocks. Called after the effect.http
// write-ahead, before upstream forwarding — a returned error fails
// closed (the caller denies LEDGER_UNAVAILABLE). A malformed body yields
// intent.unparsed and the request still crosses (spec/04 §5.4).
func (s *Server) inspectRequest(sess *Session, st *inspectState, ep inspect.Endpoint, effectID string, body []byte) error {
	// Timeout sweep first: windows that expired since the last inspected
	// traffic close before this request's results are evaluated — one at
	// a time, so a failed append leaves every later window still open
	// for the next sweep (exactly one intent.result each, in the end).
	for {
		d := st.tracker.NextTimeout()
		if d == nil {
			break
		}
		body := IntentResultBody{IntentID: d.ID, ViaEffect: effectID, ClosedBy: "timeout"}
		if err := s.appendRecord(sess, "intent.result", body); err != nil {
			// The record never landed: the window is still open.
			st.tracker.Reopen(d.ID)
			return err
		}
	}

	info, err := inspect.ParseRequest(ep, body)
	if err != nil {
		// Fail-safe for the request side (04 §5.4): forward — but only
		// once the unparsed record is durable. A failed append fails
		// closed rather than letting an unrecorded request cross.
		return s.appendRecord(sess, "intent.unparsed", IntentUnparsedBody{
			ViaEffect: effectID, Provider: ep.Provider(),
			Detail: "request: " + err.Error(),
		})
	}

	for _, tr := range info.Results {
		if _, ok := st.tracker.CloseForResult(tr.IntentID); !ok {
			if st.tracker.Declared(tr.IntentID) == nil {
				s.Logf("tool result for unknown intent %s (session %s, effect %s)", tr.IntentID, sess.ID, effectID)
			}
			continue
		}
		rb := IntentResultBody{IntentID: tr.IntentID, ViaEffect: effectID, ClosedBy: "tool_result"}
		if tr.HasContent {
			rb.ContentSHA256 = tr.ContentSHA256
			rb.ContentLen = tr.ContentLen
		}
		if tr.HasIsError {
			ie := tr.IsError
			rb.IsError = &ie
		}
		if err := s.appendRecord(sess, "intent.result", rb); err != nil {
			// The result never crossed (the request fails closed): the
			// window stays open so a retry can still close it.
			st.tracker.Reopen(tr.IntentID)
			return err
		}
	}

	// The fold and its append are one atomic step: another request of
	// this session observes only before this fold or after its commit —
	// never between an Observe and its record or rollback.
	st.obsMu.Lock()
	defer st.obsMu.Unlock()
	fresh, count, sha := st.tracker.Observe(info.Blocks)
	nb := make([]ContextBlockBody, len(fresh))
	for i, b := range fresh {
		nb[i] = ContextBlockBody{
			Index: b.Index, Role: b.Role, Kind: b.Kind,
			SHA256: b.SHA256, Len: b.Len, IntentID: b.IntentID,
		}
	}
	if err := s.appendRecord(sess, "context.observed", ContextObservedBody{
		ViaEffect: effectID, Provider: ep.Provider(), Model: info.Model,
		BlockCount: count, ContextSHA256: sha, NewBlocks: nb,
	}); err != nil {
		// No record, no observation: refold these blocks on the retry.
		st.tracker.Unobserve(fresh)
		return err
	}
	return nil
}

// ------------------------------------------------------------------
// response path

// declaredIntent records one intent extracted from a response: the
// append must be durable before the completing bytes are released, so
// inspectPipe calls it at the hold point and aborts the stream on error
// (fail closed — spec/02 §6).
func (s *Server) declaredIntent(sess *Session, st *inspectState, ep inspect.Endpoint, effectID string, it *inspect.Intent) error {
	class := st.classOf(it.Tool)
	if !st.tracker.Declare(it, class, effectID) {
		return nil // same ID again: not a new intent (04 §5.2)
	}
	body := IntentDeclaredBody{
		IntentID: it.ID, Source: "inference", Provider: ep.Provider(),
		Model: it.Model, ViaEffect: effectID, Tool: it.Tool,
		Class: class, Executor: it.Executor,
		InputSHA256: it.InputSHA256, InputLen: len(it.InputRaw),
	}
	if prev, ok := inspect.InputPreview(it.InputRaw, st.previews); ok {
		body.InputPreview = prev
	}
	if class == "exec" {
		if a := anchorSHA(it, st.commandField); a != "" {
			body.AnchorSHA256 = a
		}
	}
	if err := s.appendRecord(sess, "intent.declared", body); err != nil {
		// The completing bytes never cross: the declaration did not
		// happen as far as tracker and client are concerned.
		st.tracker.Undeclare(it.ID)
		return err
	}
	return nil
}

// anchorSHA is the lineage anchor of an exec-class intent (04 §10): the
// SHA-256 of the command-field string in the tool input.
func anchorSHA(it *inspect.Intent, field string) string {
	var m map[string]any
	if err := json.Unmarshal(it.InputRaw, &m); err != nil {
		return ""
	}
	s, _ := m[field].(string)
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// inspectPipe wraps an upstream response body for one inspected request.
// Bytes pass through untouched; when the parser completes a tool-use
// block, the bytes at the block's hold point are released only after the
// intent's append returns — the write-ahead property of 03 §4.5. A parse
// fault switches to raw pass-through after one intent.unparsed record;
// when that record cannot be written the stream aborts instead, since
// fail-safe without the record is fail-open.
type inspectPipe struct {
	src io.Reader
	p   inspect.ResponseParser

	out    []byte // releasable bytes awaiting the client
	fed    []byte // fed bytes not yet released
	relAbs int64  // abs offset of fed[0]

	declare  func(*inspect.Intent) error
	unparsed func(detail string) error

	dead     bool // parser faulted: pass through raw
	finished bool // src drained + parser closed
	err      error
	tailErr  error // upstream read error, delivered after out drains
}

func newInspectPipe(src io.Reader, p inspect.ResponseParser,
	declare func(*inspect.Intent) error, unparsed func(string) error) *inspectPipe {
	return &inspectPipe{
		src: src, p: p,
		out: make([]byte, 0, 64*1024), fed: make([]byte, 0, 64*1024),
		declare: declare, unparsed: unparsed,
	}
}

func (r *inspectPipe) Read(p []byte) (int, error) {
	buf := make([]byte, 32*1024)
	for len(r.out) == 0 && r.err == nil {
		if r.finished {
			if r.tailErr != nil {
				return 0, r.tailErr
			}
			return 0, io.EOF
		}
		n, rerr := r.src.Read(buf)
		if n > 0 {
			r.feed(buf[:n])
		}
		switch {
		case rerr == io.EOF:
			r.finish("")
		case rerr != nil:
			// Upstream died mid-body: the stream is a cut — finish the
			// parser (records unparsed when truncated); buffered bytes
			// still reach the client before the error surfaces.
			r.finish(rerr.Error())
			r.tailErr = rerr
		}
	}
	if len(r.out) == 0 && r.err != nil {
		return 0, r.err
	}
	m := copy(p, r.out)
	r.out = r.out[m:]
	return m, nil
}

// feed passes one upstream chunk through the parser and releases bytes
// into out, honoring hold points in completion order.
func (r *inspectPipe) feed(chunk []byte) {
	if r.dead {
		r.out = append(r.out, chunk...)
		return
	}
	comps, err := r.p.Feed(chunk)
	r.fed = append(r.fed, chunk...)
	for _, c := range comps {
		rel := int(c.HoldAt - r.relAbs)
		if rel < 0 {
			rel = 0
		}
		if rel > len(r.fed) {
			rel = len(r.fed)
		}
		r.out = append(r.out, r.fed[:rel]...)
		r.fed = r.fed[rel:]
		r.relAbs += int64(rel)
		if derr := r.declare(c.Intent); derr != nil {
			// Fail closed: the completing bytes never leave the broker.
			r.err = derr
			r.out = r.out[:0]
			return
		}
	}
	if err != nil {
		if detail, ok := inspect.ParseError(err); ok {
			r.dead = true
			if uerr := r.unparsed(detail); uerr != nil {
				// Fail closed: pass-through without the durable
				// intent.unparsed record is not permitted.
				r.err = uerr
				r.out = r.out[:0]
				return
			}
		} else {
			// Not a recorded parse fault: release the buffered bytes
			// and surface the error.
			r.out = append(r.out, r.fed...)
			r.relAbs += int64(len(r.fed))
			r.fed = r.fed[:0]
			r.err = err
			return
		}
	}
	// Once the appends above returned, everything fed is releasable
	// except bytes that could still belong to a pending completion —
	// the parser's watermark holds an in-flight completing event whole.
	var rel int64
	if r.dead {
		rel = int64(len(r.fed)) // raw pass-through after the fault
	} else {
		rel = r.p.Pending() - r.relAbs
	}
	if rel < 0 {
		rel = 0
	}
	if rel > int64(len(r.fed)) {
		rel = int64(len(r.fed))
	}
	r.out = append(r.out, r.fed[:rel]...)
	r.fed = r.fed[int(rel):]
	r.relAbs += rel
}

// finish drains the parser at upstream end (clean or cut alike) and
// releases any remaining bytes.
func (r *inspectPipe) finish(cause string) {
	if r.finished {
		return
	}
	r.finished = true
	if r.err != nil {
		// The last fed bytes may have failed closed (declare or
		// unparsed append): the held bytes are never released.
		return
	}
	if !r.dead {
		detail, clean := r.p.Finish()
		if !clean {
			if cause != "" {
				detail = detail + " (" + cause + ")"
			}
			if uerr := r.unparsed(detail); uerr != nil {
				// Fail closed: the buffered bytes never leave when the
				// unparsed record cannot be made durable.
				r.err = uerr
				r.out = r.out[:0]
				return
			}
		}
	}
	r.out = append(r.out, r.fed...)
	r.fed = r.fed[:0]
}
