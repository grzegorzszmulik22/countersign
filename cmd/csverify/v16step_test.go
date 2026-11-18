// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// C9.2.5-adjacent properties of the V16 step itself (spec/03 §10):
//   - `csverify --reconcile` must never return a CLEAN-class verdict
//     without having reconciled — a bundle re-read failure or an engine
//     error is reported in errors and forces a non-CLEAN verdict;
//   - a failed output write must make the command exit non-zero — no
//     stdout write anywhere in the command may be discarded.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/countersign/countersign/internal/ledger"
	"github.com/countersign/countersign/internal/reconcile"
)

// failingWriter rejects every write — a closed pipe, a full disk, a dead
// consumer; any of them must move the command off exit 0.
type failingWriter struct{ calls int }

func (w *failingWriter) Write(p []byte) (int, error) {
	w.calls++
	return 0, fmt.Errorf("injected write failure")
}

// TestC925_ReconcileReadFailsClosed injects a bundle re-read failure
// after VerifyBundle has passed: the merged result must leave the
// CLEAN class and record the reason.
func TestC925_ReconcileReadFailsClosed(t *testing.T) {
	b, m := reconBundle(t, "enforce", honestEffects, true, nil)
	base := ledger.VerifyBundle(b, m)
	if base.Verdict != "CLEAN" {
		t.Fatalf("baseline verdict %s, want CLEAN", base.Verdict)
	}
	defer func() { reconcileReadBundle = ledger.ReadBundle }()
	reconcileReadBundle = func([]byte) (map[string][]byte, error) {
		return nil, fmt.Errorf("injected re-read failure")
	}
	applyReconcile(base, b)
	if base.Verdict == "CLEAN" || base.Verdict == "CLEAN_WITH_DENIALS" {
		t.Fatalf("verdict %s: CLEAN-class without reconciling", base.Verdict)
	}
	if !hasErr(base.Errors, "E_BUNDLE") {
		t.Fatalf("reason not recorded in errors: %v", base.Errors)
	}
	found := false
	for _, e := range base.Errors {
		if strings.Contains(e.Detail, "injected re-read failure") {
			found = true
		}
	}
	if !found {
		t.Fatalf("re-read failure reason not printed in errors: %v", base.Errors)
	}
}

// TestC925_ReconcileErrorFailsClosed injects an engine error: same rule —
// no CLEAN-class verdict, the reason is in errors.
func TestC925_ReconcileErrorFailsClosed(t *testing.T) {
	b, m := reconBundle(t, "enforce", honestEffects, true, nil)
	base := ledger.VerifyBundle(b, m)
	if base.Verdict != "CLEAN" {
		t.Fatalf("baseline verdict %s, want CLEAN", base.Verdict)
	}
	defer func() { reconcileRun = reconcile.ReconcileBundle }()
	reconcileRun = func(map[string][]byte, []map[string]any) (*reconcile.Result, error) {
		return nil, fmt.Errorf("injected reconcile failure")
	}
	applyReconcile(base, b)
	if base.Verdict == "CLEAN" || base.Verdict == "CLEAN_WITH_DENIALS" {
		t.Fatalf("verdict %s: CLEAN-class without reconciling", base.Verdict)
	}
	if !hasErr(base.Errors, "E_POLICY") {
		t.Fatalf("reason not recorded in errors: %v", base.Errors)
	}
}

// TestC925_ReconcileRan proves V16 actually ran on the honest path: the
// reconcile stats land in the result and no errors are appended.
func TestC925_ReconcileRan(t *testing.T) {
	b, m := reconBundle(t, "enforce", honestEffects, true, nil)
	base := ledger.VerifyBundle(b, m)
	applyReconcile(base, b)
	if base.Verdict != "CLEAN" {
		t.Fatalf("verdict %s, want CLEAN", base.Verdict)
	}
	if _, ok := base.Stats["reconcile_effects"]; !ok {
		t.Fatalf("reconcile stats missing — V16 did not record its run")
	}
	if len(base.Errors) != 0 {
		t.Fatalf("errors on honest bundle: %v", base.Errors)
	}
}

// TestC925_VerifyWriteErrorFails runs the full verify command path with
// an output writer that rejects every write: the run must exit non-zero
// even though the bundle itself is CLEAN.
func TestC925_VerifyWriteErrorFails(t *testing.T) {
	b, m := reconBundle(t, "enforce", honestEffects, true, nil)
	dir := t.TempDir()
	bp := filepath.Join(dir, "bundle.tar")
	if err := os.WriteFile(bp, b, 0o644); err != nil {
		t.Fatal(err)
	}
	kb, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	kp := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(kp, kb, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{bp, "--keys", kp},
		{bp, "--keys", kp, "--reconcile"},
	} {
		rc := runVerify(args, &failingWriter{})
		if rc == 0 {
			t.Fatalf("runVerify %v exited 0 with a failing stdout", args)
		}
		var good bytes.Buffer
		rc = runVerify(args, &good)
		if rc != 0 {
			t.Fatalf("runVerify %v exited %d on a clean bundle", args, rc)
		}
		var res ledger.VerifyResult
		if err := json.Unmarshal(good.Bytes(), &res); err != nil {
			t.Fatalf("unreadable command output: %v", err)
		}
		if res.Verdict != "CLEAN" {
			t.Fatalf("verdict %s, want CLEAN", res.Verdict)
		}
	}
}

// TestC925_BatchWriteErrorFails drives reconcile-batch over a one-line
// input: any write failure — inline or at flush — must exit non-zero.
func TestC925_BatchWriteErrorFails(t *testing.T) {
	dir := t.TempDir()
	// A minimal well-formed trace: open + seal, no effects → CLEAN.
	line := `{"meta":{"policy":{"mode":"enforce","grants":[]}},"records":[` +
		`{"type":"session.open","kind":"agent","mode":"enforce"},` +
		`{"type":"session.seal"}]}` + "\n"
	small := filepath.Join(dir, "small.jsonl")
	if err := os.WriteFile(small, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	// A line large enough to overflow the 4 MiB bufio buffer forces the
	// Fprintln itself (not only the final Flush) to hit the dead writer.
	big := filepath.Join(dir, "big.jsonl")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("x", 5<<20)
	if _, err := fmt.Fprintf(f, `{"meta":{"policy":{"mode":"enforce","grants":[],"pad":"%s"}},"records":[{"type":"session.open","kind":"agent","mode":"enforce"},{"type":"session.seal"}]}`+"\n", pad); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{small, big} {
		fw := &failingWriter{}
		if rc := runReconcileBatch(path, "", fw); rc == 0 {
			t.Fatalf("%s: exited 0 with a failing stdout", path)
		}
		if fw.calls == 0 {
			t.Fatalf("%s: writer never used", path)
		}
	}
	// Control: a good writer exits 0 and emits exactly one result line.
	var buf bytes.Buffer
	if rc := runReconcileBatch(small, "", &buf); rc != 0 {
		t.Fatalf("clean batch exited %d", rc)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want 1 result line, got %d", len(lines))
	}
	var res reconcile.Result
	if err := json.Unmarshal([]byte(lines[0]), &res); err != nil {
		t.Fatalf("unreadable batch output: %v", err)
	}
}

// TestC925_BatchErrorLineFails covers the error-line path: a malformed
// trace line produces an {"error": …} row and exit 1 — never exit 0.
func TestC925_BatchErrorLineFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.jsonl")
	if err := os.WriteFile(path, []byte("{not a trace line}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	rc := runReconcileBatch(path, "", &buf)
	if rc == 0 {
		t.Fatalf("exited 0 on a bad trace line")
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &row); err != nil {
		t.Fatalf("error row not readable JSON: %v", err)
	}
	if row["error"] == nil {
		t.Fatalf("error row carries no error: %v", row)
	}
}
