// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Package ledger is the append-only evidence store of 03 §5:
//
//	ledger/
//	  log/entries.jsonl          every envelope, in append order
//	  log/hashes.bin             32-byte leaf hashes, index-aligned
//	  log/checkpoints/<size>.txt signed checkpoints
//	  sessions/<session>.idx     log indices of the session, ascending
//
// Single writer; group commit with an fsync at most every 2 ms; an append
// returns only once durable. No rewriting, compaction, or deletion API
// exists (denied list; C1.4.6).
package ledger

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/mlog"
)

const (
	entriesFile = "log/entries.jsonl"
	hashesFile  = "log/hashes.bin"
	cpDir       = "log/checkpoints"
	sessionsDir = "sessions"

	// fsyncInterval is the group-commit cadence of 03 §5.
	fsyncInterval = 2 * time.Millisecond
	// cpInterval checkpoints at least this often while entries are pending.
	cpInterval = 10 * time.Second
)

// Ledger is the single-writer append-only store.
type Ledger struct {
	dir    string
	origin string
	signer keys.Signer

	entries *os.File
	hashes  *os.File

	mu      sync.Mutex
	cond    *sync.Cond
	tree    *mlog.Log
	seq     uint64 // lines written
	durable uint64 // lines covered by the last fsync
	syncErr error  // sticky fsync failure
	closed  bool
	flushCh chan struct{}

	sessMu  sync.Mutex
	sess    map[string]*os.File
	lastCP  time.Time
	pending bool
}

// Open opens (creating) the ledger at dir, recovering any torn tail.
// origin is the checkpoint origin; signer is the `log` key (may be nil only
// for a read-only use that never checkpoints).
func Open(dir, origin string, signer keys.Signer) (*Ledger, error) {
	for _, d := range []string{dir, filepath.Join(dir, "log"), filepath.Join(dir, cpDir), filepath.Join(dir, sessionsDir)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	l := &Ledger{
		dir: dir, origin: origin, signer: signer,
		tree: mlog.NewLog(origin, signer),
		sess: map[string]*os.File{},
	}
	l.cond = sync.NewCond(&l.mu)
	if err := l.recover(); err != nil {
		return nil, err
	}
	var err error
	l.entries, err = os.OpenFile(filepath.Join(dir, entriesFile), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	l.hashes, err = os.OpenFile(filepath.Join(dir, hashesFile), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		_ = l.entries.Close()
		return nil, err
	}
	l.flushCh = make(chan struct{}, 1)
	l.lastCP = time.Now()
	go l.flusher()
	return l, nil
}

// flusher performs the group commit: fsync at most every 2 ms.
func (l *Ledger) flusher() {
	var lastSync time.Time
	for range l.flushCh {
		l.mu.Lock()
		if l.durable >= l.seq || l.closed {
			l.mu.Unlock()
			continue
		}
		l.mu.Unlock()
		// Rate cap: never fsync more often than once per interval.
		if wait := fsyncInterval - time.Since(lastSync); wait > 0 {
			time.Sleep(wait)
		}
		l.syncFiles()
		lastSync = time.Now()
	}
}

// syncFiles fsyncs every open ledger file, then advances durable.
func (l *Ledger) syncFiles() {
	l.sessMu.Lock()
	files := []*os.File{l.entries, l.hashes}
	for _, f := range l.sess {
		files = append(files, f)
	}
	l.sessMu.Unlock()
	var syncErr error
	for _, f := range files {
		if err := f.Sync(); err != nil {
			syncErr = err
		}
	}
	l.mu.Lock()
	l.syncErr = syncErr
	l.durable = l.seq
	l.cond.Broadcast()
	l.mu.Unlock()
}

// waitDurable blocks until seq is covered by an fsync.
func (l *Ledger) waitDurable(seq uint64) error {
	l.mu.Lock()
	for l.durable < seq && !l.closed {
		l.cond.Wait()
	}
	err := l.syncErr
	l.mu.Unlock()
	return err
}

// Append writes one canonical record line and blocks until it is durable.
// Returns the record's log index.
func (l *Ledger) Append(line []byte) (uint64, error) {
	_, _, r, err := evidence.DecodeRecordLine(line)
	if err != nil {
		return 0, fmt.Errorf("append of undecodable record: %w", err)
	}
	leaf := mlog.HashLeaf(line)

	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return 0, errors.New("ledger closed")
	}
	idx := l.tree.AppendLeaf(line)
	if _, err := l.entries.Write(line); err != nil {
		l.mu.Unlock()
		return 0, err
	}
	if _, err := l.entries.WriteString("\n"); err != nil {
		l.mu.Unlock()
		return 0, err
	}
	if _, err := l.hashes.Write(leaf[:]); err != nil {
		l.mu.Unlock()
		return 0, err
	}
	l.seq++
	seq := l.seq
	l.mu.Unlock()

	l.sessMu.Lock()
	sf, err := l.sessionFile(r.Session)
	if err == nil {
		_, err = fmt.Fprintf(sf, "%d\n", idx)
	}
	l.sessMu.Unlock()
	if err != nil {
		return 0, err
	}

	select {
	case l.flushCh <- struct{}{}:
	default:
	}
	if err := l.waitDurable(seq); err != nil {
		return idx, err
	}

	l.mu.Lock()
	l.pending = true
	trigger := r.Type == "session.seal" || r.Type == "commit.closed"
	due := trigger || (l.pending && time.Since(l.lastCP) >= cpInterval)
	l.mu.Unlock()
	if due {
		if err := l.Checkpoint(); err != nil {
			return idx, fmt.Errorf("checkpoint at %d: %w", idx, err)
		}
	}
	return idx, nil
}

// sessionFile opens (append-only) the session index for a session ID.
func (l *Ledger) sessionFile(session string) (*os.File, error) {
	if f, ok := l.sess[session]; ok {
		return f, nil
	}
	f, err := os.OpenFile(filepath.Join(l.dir, sessionsDir, session+".idx"),
		os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	l.sess[session] = f
	return f, nil
}

// Checkpoint signs and stores a checkpoint for the current tree size.
func (l *Ledger) Checkpoint() error {
	if l.signer == nil {
		return errors.New("ledger has no log signer")
	}
	cp, err := l.tree.Checkpoint()
	if err != nil {
		return err
	}
	data, err := mlog.SignCheckpoint(cp, l.signer)
	if err != nil {
		return err
	}
	p := filepath.Join(l.dir, cpDir, fmt.Sprintf("%d.txt", cp.Size))
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	l.mu.Lock()
	l.pending = false
	l.lastCP = time.Now()
	l.mu.Unlock()
	return nil
}

// Size is the number of log entries.
func (l *Ledger) Size() uint64 { return l.tree.Size() }

// Root is the current tree root.
func (l *Ledger) Root() [32]byte { return l.tree.Root() }

// Tree exposes proof generation (read-only).
func (l *Ledger) Tree() *mlog.Log { return l.tree }

// SessionIndices returns the stored log indices of a session.
func (l *Ledger) SessionIndices(session string) ([]uint64, error) {
	data, err := os.ReadFile(filepath.Join(l.dir, sessionsDir, session+".idx"))
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		v, err := strconv.ParseUint(line, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("corrupt session index for %s: %q", session, line)
		}
		out = append(out, v)
	}
	return out, nil
}

// Line returns the stored line at log index i (no trailing newline).
func (l *Ledger) Line(i uint64) ([]byte, error) {
	f, err := os.Open(filepath.Join(l.dir, entriesFile))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var cur uint64
	buf := make([]byte, 0, 4096)
	one := make([]byte, 1)
	for {
		n, err := f.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				if cur == i {
					return append([]byte(nil), buf...), nil
				}
				cur++
				buf = buf[:0]
				continue
			}
			buf = append(buf, one[0])
		}
		if err != nil {
			return nil, fmt.Errorf("log index %d not found", i)
		}
	}
}

// Close syncs and closes all files.
func (l *Ledger) Close() error {
	l.mu.Lock()
	l.closed = true
	l.cond.Broadcast()
	l.mu.Unlock()
	l.syncFiles()
	l.sessMu.Lock()
	for _, f := range l.sess {
		_ = f.Close()
	}
	l.sessMu.Unlock()
	err1 := l.entries.Close()
	err2 := l.hashes.Close()
	return errors.Join(err1, err2)
}
