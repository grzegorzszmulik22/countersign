// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"os"
	"reflect"
	"testing"

	"github.com/countersign/countersign/internal/names"
	"golang.org/x/sys/unix"
)

// C1.4.6 Ledger files are opened append-only. The package exports no
// rewriting API — the only mutator is Append — and the open files carry
// O_APPEND so a write can never land anywhere but the tail.
func TestC146_AppendOnly(t *testing.T) {
	l, err := Open(t.TempDir(), names.APIGroup+"/log/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	for name, f := range map[string]*os.File{"entries": l.entries, "hashes": l.hashes} {
		fl, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
		if err != nil {
			t.Fatal(err)
		}
		if fl&unix.O_APPEND == 0 {
			t.Fatalf("%s opened without O_APPEND", name)
		}
	}
	// The public surface exposes no rewrite/compaction primitive: anything
	// other than Append/Checkpoint/Close/ExportBundle/readers cannot exist.
	for _, name := range []string{"Rewrite", "Truncate", "Overwrite", "Delete", "Set", "Update"} {
		if method, ok := reflect.TypeOf(l).MethodByName(name); ok && method.IsExported() {
			t.Fatalf("ledger exports mutation-like method %s", name)
		}
	}
}
