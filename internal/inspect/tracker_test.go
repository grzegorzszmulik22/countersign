// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"fmt"
	"testing"
	"time"
)

func intent(id, tool, exec string) *Intent {
	return &Intent{ID: id, Tool: tool, Executor: exec, InputSHA256: "x"}
}

// TestTrackerWindowLifecycle: declare → close once → resend ignored;
// unknown IDs never close; provider intents never open.
func TestTrackerWindowLifecycle(t *testing.T) {
	tr := NewTracker(3600)
	tr.Now = func() time.Time { return time.Unix(1700000000, 0) }

	if !tr.Declare(intent("a1", "Bash", ExecutorSandbox), "exec", "e1") {
		t.Fatal("first declare rejected")
	}
	if tr.Declare(intent("a1", "Bash", ExecutorSandbox), "exec", "e2") {
		t.Fatal("re-declare of same ID must not be a new intent")
	}
	if !tr.Declare(intent("p1", "web_search", ExecutorProvider), "other", "e1") {
		t.Fatal("provider intent should register")
	}
	if _, ok := tr.CloseForResult("p1"); ok {
		t.Fatal("provider intent must not open a window")
	}
	if _, ok := tr.CloseForResult("ghost"); ok {
		t.Fatal("unknown ID closed")
	}
	d, ok := tr.CloseForResult("a1")
	if !ok || d.ID != "a1" {
		t.Fatal("a1 window should close")
	}
	if _, ok := tr.CloseForResult("a1"); ok {
		t.Fatal("resend must not close twice")
	}
	if n := len(tr.Seal()); n != 0 {
		t.Fatalf("seal after all closed: %d", n)
	}
}

// TestTrackerInterleaved: two conversations' windows are independent.
func TestTrackerInterleaved(t *testing.T) {
	tr := NewTracker(3600)
	base := time.Unix(1700000000, 0)
	tr.Now = func() time.Time { return base }
	tr.Declare(intent("A", "Bash", ExecutorSandbox), "exec", "e1")
	tr.Declare(intent("B", "Read", ExecutorSandbox), "exec", "e2")
	if _, ok := tr.CloseForResult("B"); !ok {
		t.Fatal("B should close")
	}
	if tr.Declared("A").Open != true {
		t.Fatal("A still open")
	}
	sealed := tr.Seal()
	if len(sealed) != 1 || sealed[0].ID != "A" {
		t.Fatalf("seal = %v, want only A", sealed)
	}
}

// TestTrackerTimeout: only windows past the budget close.
func TestTrackerTimeout(t *testing.T) {
	tr := NewTracker(60)
	now := time.Unix(1700000000, 0)
	tr.Now = func() time.Time { return now }
	tr.Declare(intent("old", "Bash", ExecutorSandbox), "exec", "e1")
	now = now.Add(30 * time.Second)
	tr.Declare(intent("new", "Bash", ExecutorSandbox), "exec", "e2")
	now = now.Add(31 * time.Second) // old is 61s, new is 31s
	out := tr.NextTimeout()
	if out == nil || out.ID != "old" {
		t.Fatalf("timeout = %v", out)
	}
	if tr.NextTimeout() != nil {
		t.Fatal("only the expired window may drain")
	}
	now = now.Add(60 * time.Second)
	out = tr.NextTimeout()
	if out == nil || out.ID != "new" {
		t.Fatalf("second timeout sweep = %v", out)
	}
	if tr.Declared("new").Open {
		t.Fatal("new should be closed")
	}
}

// TestTrackerContextDigest: new_blocks are unique per session and the
// running digest matches the documented construction.
func TestTrackerContextDigest(t *testing.T) {
	tr := NewTracker(0)
	mk := func(i int) RequestBlock {
		return RequestBlock{Index: i, SHA256: fmt.Sprintf("d%02x", i), digest: fmt.Sprintf("d%02x", i)}
	}
	fresh, count, sha := tr.Observe([]RequestBlock{mk(0), mk(1)})
	if len(fresh) != 2 || count != 2 {
		t.Fatalf("first observe: %d %d", len(fresh), count)
	}
	want := sha256Hex([]byte(`["d00","d01"]`))
	if sha != want {
		t.Fatalf("context sha = %s, want %s", sha, want)
	}
	fresh, count, sha = tr.Observe([]RequestBlock{mk(1), mk(2), mk(0)})
	if len(fresh) != 1 || fresh[0].SHA256 != "d02" || count != 3 {
		t.Fatalf("second observe: %v count=%d", fresh, count)
	}
	want = sha256Hex([]byte(`["d00","d01","d02"]`))
	if sha != want {
		t.Fatalf("context sha = %s, want %s", sha, want)
	}
}

// TestTrackerRollback: the ledger-failure rollbacks restore the exact
// pre-append state — Undeclare lets a redelivery declare again, Reopen
// restores the window for a retry, Unobserve refolds the blocks so the
// next request reports them fresh.
func TestTrackerRollback(t *testing.T) {
	tr := NewTracker(3600)
	tr.Now = func() time.Time { return time.Unix(1700000000, 0) }

	// Failed intent.declared: the intent is forgotten entirely.
	tr.Declare(intent("a1", "Bash", ExecutorSandbox), "exec", "e1")
	tr.Undeclare("a1")
	if tr.Declared("a1") != nil {
		t.Fatal("undeclared intent still tracked")
	}
	if !tr.Declare(intent("a1", "Bash", ExecutorSandbox), "exec", "e9") {
		t.Fatal("redelivery after undeclare must declare anew")
	}
	if d := tr.Declared("a1"); d == nil || d.ViaEffect != "e9" {
		t.Fatal("redelivered intent carries the new effect")
	}
	tr.Undeclare("ghost") // no-op, must not panic

	// Failed intent.result: the window reopens; a retry closes it.
	if _, ok := tr.CloseForResult("a1"); !ok {
		t.Fatal("a1 window should close")
	}
	tr.Reopen("a1")
	if !tr.Declared("a1").Open {
		t.Fatal("reopen did not restore the window")
	}
	if _, ok := tr.CloseForResult("a1"); !ok {
		t.Fatal("retry after reopen must close the window")
	}

	// Failed context.observed: blocks fold back as unseen.
	mk := func(i int) RequestBlock {
		return RequestBlock{Index: i, SHA256: fmt.Sprintf("d%02x", i), digest: fmt.Sprintf("d%02x", i)}
	}
	fresh, count, _ := tr.Observe([]RequestBlock{mk(0), mk(1)})
	if len(fresh) != 2 || count != 2 {
		t.Fatalf("observe: %d %d", len(fresh), count)
	}
	tr.Unobserve(fresh)
	fresh2, count2, sha2 := tr.Observe([]RequestBlock{mk(0)})
	if len(fresh2) != 1 || count2 != 1 {
		t.Fatalf("unobserved blocks not reported fresh: %d %d", len(fresh2), count2)
	}
	if sha2 != sha256Hex([]byte(`["d00"]`)) {
		t.Fatalf("rolled-back context sha = %s", sha2)
	}
}

// TestTrackerContextInterleaveRollback: when request A's context.observed
// append fails after request B folded its own blocks, A's rollback removes
// exactly A's digests — B's blocks stay observed and in order, and A's
// blocks report fresh on the retry.
func TestTrackerContextInterleaveRollback(t *testing.T) {
	tr := NewTracker(0)
	mk := func(i int) RequestBlock {
		return RequestBlock{Index: i, SHA256: fmt.Sprintf("d%02x", i), digest: fmt.Sprintf("d%02x", i)}
	}
	freshA, _, _ := tr.Observe([]RequestBlock{mk(0), mk(1)})
	if len(freshA) != 2 {
		t.Fatalf("A fresh = %d", len(freshA))
	}
	freshB, countB, shaB := tr.Observe([]RequestBlock{mk(2)})
	if len(freshB) != 1 || countB != 3 {
		t.Fatalf("B fresh = %d count = %d", len(freshB), countB)
	}
	if shaB != sha256Hex([]byte(`["d00","d01","d02"]`)) {
		t.Fatalf("B sha = %s", shaB)
	}

	// A's append fails mid-interleave: exactly [d00 d01] leave, B's d02
	// stays — never a positional truncation over another request's blocks.
	tr.Unobserve(freshA)
	freshC, countC, shaC := tr.Observe([]RequestBlock{mk(3)})
	if len(freshC) != 1 || countC != 2 {
		t.Fatalf("post-rollback state: fresh=%d count=%d — B's block was lost", len(freshC), countC)
	}
	if shaC != sha256Hex([]byte(`["d02","d03"]`)) {
		t.Fatalf("post-rollback sha = %s, want d02,d03", shaC)
	}

	// A's retry observes its own blocks again as new.
	freshA2, countA2, _ := tr.Observe([]RequestBlock{mk(0), mk(1)})
	if len(freshA2) != 2 || countA2 != 4 {
		t.Fatalf("A retry: fresh=%d count=%d", len(freshA2), countA2)
	}
}
