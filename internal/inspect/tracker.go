// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"strings"
	"sync"
	"time"
)

// Tracker is one session's intent-window and context state (spec/04 §5.2–5.3,
// M8.3). It is pure state: every method only reports what record the caller
// must write, so ordering and durability stay with the broker's sink.
//
// Intents are keyed by provider ID — a session may hold several
// conversations and providers reuse no IDs within one. Executor
// "provider" intents register (so results naming them are not
// "unknown") but never open a window. A repeated intent.declared for an
// ID already declared is not a new intent (04 §5.2).
type Tracker struct {
	mu sync.Mutex
	// MaxOpenSeconds is spec.maxIntentOpenSeconds (default 3600).
	MaxOpenSeconds int
	// Now is the clock (tests may substitute).
	Now func() time.Time

	declared map[string]*Declared
	order    []*Declared
	ctxSeen  map[string]bool
	ctxOrder []string
}

// Declared is one intent the session has recorded.
type Declared struct {
	ID         string
	Tool       string
	Class      string
	Executor   string
	Open       bool // a window is open (sandbox executor, not yet closed)
	DeclaredAt time.Time
	ViaEffect  string // the effect whose response carried the declaration
}

// NewTracker creates an empty session tracker.
func NewTracker(maxOpenSeconds int) *Tracker {
	if maxOpenSeconds <= 0 {
		maxOpenSeconds = 3600
	}
	return &Tracker{
		MaxOpenSeconds: maxOpenSeconds,
		Now:            time.Now,
		declared:       map[string]*Declared{},
		ctxSeen:        map[string]bool{},
	}
}

// Declare registers a freshly-recorded intent. Returns false when the ID
// was already declared (spec/04 §5.2: not a new intent) — the caller must
// not write a second intent.declared.
func (t *Tracker) Declare(it *Intent, class, viaEffect string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.declared[it.ID]; ok {
		return false
	}
	d := &Declared{
		ID: it.ID, Tool: it.Tool, Class: class, Executor: it.Executor,
		Open:       it.Executor == ExecutorSandbox,
		DeclaredAt: t.Now(),
		ViaEffect:  viaEffect,
	}
	t.declared[it.ID] = d
	t.order = append(t.order, d)
	return true
}

// CloseForResult closes the window of the intent a tool result
// references. Returns the intent and true when a window was actually
// open, nil/false when the ID is unknown or already closed — the caller
// writes a record only on true.
func (t *Tracker) CloseForResult(intentID string) (*Declared, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	d, ok := t.declared[intentID]
	if !ok || !d.Open {
		return nil, false
	}
	d.Open = false
	return d, true
}

// NextTimeout closes the oldest expired open window and returns it for
// its intent.result append — one window per call, in declaration order.
// A failed append reopens that window and leaves the rest unmarked, so
// the next request's sweep records each expired window exactly once.
func (t *Tracker) NextTimeout() *Declared {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, d := range t.order {
		if !d.Open {
			continue
		}
		if t.Now().Sub(d.DeclaredAt).Seconds() >= float64(t.MaxOpenSeconds) {
			d.Open = false
			return d
		}
	}
	return nil
}

// Seal closes every still-open window (session.seal semantics) and
// returns the intents to record as closed_by:seal.
func (t *Tracker) Seal() []*Declared {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []*Declared
	for _, d := range t.order {
		if d.Open {
			d.Open = false
			out = append(out, d)
		}
	}
	return out
}

// Declared reports the tracker entry for an ID (nil if undeclared).
func (t *Tracker) Declared(intentID string) *Declared {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.declared[intentID]
}

// Undeclare forgets a declaration whose record failed to land: the
// completing bytes were never released, so the intent did not happen and
// a redelivery must declare it again.
func (t *Tracker) Undeclare(intentID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.declared[intentID]; !ok {
		return
	}
	delete(t.declared, intentID)
	for i, d := range t.order {
		if d.ID == intentID {
			t.order = append(t.order[:i], t.order[i+1:]...)
			break
		}
	}
}

// Reopen restores an open window after the closing record's append
// failed: nothing crossed, so the intent stays open.
func (t *Tracker) Reopen(intentID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if d, ok := t.declared[intentID]; ok {
		d.Open = true
	}
}

// Observe folds one request's context blocks into the session's
// first-seen set and returns the blocks not seen before (in request
// order), the running block count and the running context digest:
// SHA-256 of the canonical JSON array of unique block digests in
// first-observed order (docs/intent-capture.md).
func (t *Tracker) Observe(blocks []RequestBlock) (fresh []RequestBlock, count int, sha string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, b := range blocks {
		if t.ctxSeen[b.digest] {
			continue
		}
		t.ctxSeen[b.digest] = true
		t.ctxOrder = append(t.ctxOrder, b.digest)
		fresh = append(fresh, b)
	}
	return fresh, len(t.ctxOrder), t.contextSHA()
}

// Unobserve rolls back the fresh blocks of an Observe whose record's
// append failed — they were never observed upstream, so the next
// request reports them as new again. fresh must be the Observe result;
// exactly its own digests are removed, wherever they sit in the order —
// never another request's blocks.
func (t *Tracker) Unobserve(fresh []RequestBlock) {
	t.mu.Lock()
	defer t.mu.Unlock()
	drop := make(map[string]bool, len(fresh))
	for _, b := range fresh {
		drop[b.digest] = true
		delete(t.ctxSeen, b.digest)
	}
	keep := t.ctxOrder[:0]
	for _, d := range t.ctxOrder {
		if !drop[d] {
			keep = append(keep, d)
		}
	}
	t.ctxOrder = keep
}

// contextSHA is the running context digest: SHA-256 of the canonical
// JSON array of every unique block digest in first-observed order.
func (t *Tracker) contextSHA() string {
	if len(t.ctxOrder) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteByte('[')
	for i, d := range t.ctxOrder {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`"` + d + `"`)
	}
	sb.WriteByte(']')
	return sha256Hex([]byte(sb.String()))
}
