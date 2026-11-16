// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/mlog"
)

// recover opens the store, verifies hashes.bin against the stored lines,
// and truncates ONLY the torn tail: the largest prefix of complete,
// hash-verified lines is kept; everything after is removed on open.
func (l *Ledger) recover() error {
	ep := filepath.Join(l.dir, entriesFile)
	hp := filepath.Join(l.dir, hashesFile)
	raw, err := os.ReadFile(ep)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	hashes, err := os.ReadFile(hp)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	// Complete lines only: bytes after the last newline are the torn tail.
	lastNL := bytes.LastIndexByte(raw, '\n')
	good := raw
	if lastNL >= 0 {
		good = raw[:lastNL+1]
	} else if len(raw) > 0 {
		good = nil
	}
	lines := bytes.Split(bytes.TrimSuffix(good, []byte("\n")), []byte("\n"))
	if len(good) == 0 {
		lines = nil
	}

	// A line may be torn mid-hash: keep at most len(hashes)/32 entries, and
	// stop at the first leaf-hash mismatch (the rest is an unacknowledged
	// tail that can only exist past a crash boundary).
	n := uint64(len(lines))
	if nh := uint64(len(hashes)) / 32; nh < n {
		n = nh
	}
	var kept uint64
	for kept = 0; kept < n; kept++ {
		leaf := mlog.HashLeaf(lines[kept])
		stored := hashes[kept*32 : kept*32+32]
		if !bytes.Equal(leaf[:], stored) {
			break
		}
		l.tree.AppendLeaf(lines[kept])
	}

	// Truncate the torn tail: entries past the kept prefix, hash bytes past
	// kept*32. Nothing else is ever rewritten.
	if lastNL < len(raw)-1 || kept < uint64(len(lines)) {
		end := uint64(0)
		for i := uint64(0); i < kept; i++ {
			end += uint64(len(lines[i])) + 1
		}
		if err := os.Truncate(ep, int64(end)); err != nil {
			return err
		}
	}
	if kept*32 < uint64(len(hashes)) {
		if err := os.Truncate(hp, int64(kept*32)); err != nil {
			return err
		}
	}

	// Session indices are derived data: rewrite them from the kept prefix so
	// a torn .idx line can never claim an index the log does not have.
	return l.rebuildSessionIndices(lines[:kept])
}

// rebuildSessionIndices replays the kept lines and rewrites every
// sessions/*.idx deterministically.
func (l *Ledger) rebuildSessionIndices(lines [][]byte) error {
	sessLines := map[string][]byte{}
	for i, line := range lines {
		_, _, r, err := evidence.DecodeRecordLine(line)
		if err != nil {
			continue // undecodable kept line: chain verifier will report it
		}
		sessLines[r.Session] = append(sessLines[r.Session], []byte(strconv.Itoa(i))...)
		sessLines[r.Session] = append(sessLines[r.Session], '\n')
	}
	dir := filepath.Join(l.dir, sessionsDir)
	ents, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, e := range ents {
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	names := make([]string, 0, len(sessLines))
	for s := range sessLines {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, s := range names {
		if err := os.WriteFile(filepath.Join(dir, s+".idx"), sessLines[s], 0o644); err != nil {
			return fmt.Errorf("rebuild session index %s: %w", s, err)
		}
	}
	return nil
}
