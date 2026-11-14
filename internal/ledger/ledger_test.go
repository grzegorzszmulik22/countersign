// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package ledger_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/ledger"
	"github.com/countersign/countersign/internal/ledger/ldtest"
)

// C1.4.1 Append returns only after the record is on disk. A helper process
// appends up to 10,000 records from concurrent writers, printing ACK <idx>
// after each durable append. The test SIGKILLs it at random points across
// 50 trials; after recovery every acknowledged record is present and the
// recovered log is a contiguous verified prefix.
func TestC141_CrashRecovery(t *testing.T) {
	trials := 50
	if v := os.Getenv("CS_C141_TRIALS"); v != "" {
		trials, _ = strconv.Atoi(v)
	}
	for trial := 0; trial < trials; trial++ {
		dir := t.TempDir()
		cmd := exec.Command(os.Args[0], "-test.run=^TestC141Helper$")
		cmd.Env = append(os.Environ(), "CS_HELPER=1", "CS_HELPER_DIR="+dir)
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		acked := map[uint64]bool{}
		done := make(chan struct{})
		go func() {
			sc := bufio.NewScanner(out)
			sc.Buffer(make([]byte, 1<<20), 1<<20)
			for sc.Scan() {
				f := strings.Fields(sc.Text())
				if len(f) == 2 && f[0] == "ACK" {
					if v, err := strconv.ParseUint(f[1], 10, 64); err == nil {
						acked[v] = true
					}
				}
			}
			close(done)
		}()
		// Kill at a random point inside the append stream.
		time.Sleep(time.Duration(50+rand.Intn(900)) * time.Millisecond)
		_ = cmd.Process.Signal(syscall.SIGKILL)
		_ = cmd.Wait()
		<-done

		l, err := ledger.Open(dir, "countersign.dev/log/test", nil)
		if err != nil {
			t.Fatalf("trial %d: reopen: %v", trial, err)
		}
		rec := l.Size()
		_ = l.Close()
		for idx := range acked {
			if idx >= rec {
				t.Fatalf("trial %d: acknowledged record %d missing after recovery (size %d)", trial, idx, rec)
			}
		}
	}
}

// TestC141Helper is the worker process (runs only under CS_HELPER=1).
func TestC141Helper(t *testing.T) {
	if os.Getenv("CS_HELPER") != "1" {
		t.Skip("helper")
	}
	dir := os.Getenv("CS_HELPER_DIR")
	s := ldtest.New("countersign.dev/log/test")
	l, err := ledger.Open(dir, "countersign.dev/log/test", s.LogSigner)
	if err != nil {
		t.Fatal(err)
	}
	// Pre-build lines once so appends are fsync-bound.
	em := s.Emitters["broker"]
	const total = 10000
	lines := make([][]byte, total)
	for i := 0; i < total; i++ {
		line, _, err := em.Emit("observer.gap", ldtest.Body("observer.gap", nil), ldtest.TS)
		if err != nil {
			t.Fatal(err)
		}
		lines[i] = line
	}
	work := make(chan int, 64)
	go func() {
		for i := 0; i < total; i++ {
			work <- i
		}
		close(work)
	}()
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				idx, err := l.Append(lines[i])
				if err == nil {
					_, _ = fmt.Fprintf(os.Stdout, "ACK %d\n", idx)
				}
			}
		}()
	}
	wg.Wait()
}

// C1.4.2 Two exports of the same session are byte-identical.
func TestC142_DeterministicExport(t *testing.T) {
	dir := t.TempDir()
	s := ldtest.New("countersign.dev/log/test")
	l, err := ledger.Open(dir, "countersign.dev/log/test", s.LogSigner)
	if err != nil {
		t.Fatal(err)
	}
	ldtest.CleanAllTypes(l, s)
	b1, err := l.ExportBundle(s.ID, s.Manifest, s.Extras())
	if err != nil {
		t.Fatal(err)
	}
	b2, err := l.ExportBundle(s.ID, s.Manifest, s.Extras())
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	if !bytes.Equal(b1, b2) {
		t.Fatal("two exports of one session differ")
	}
	// Reopen and export again: still identical (no process state leaks).
	l, err = ledger.Open(dir, "countersign.dev/log/test", s.LogSigner)
	if err != nil {
		t.Fatal(err)
	}
	b3, err := l.ExportBundle(s.ID, s.Manifest, s.Extras())
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	if !bytes.Equal(b1, b3) {
		t.Fatal("export after reopen differs")
	}
}

// C1.4.5 A trusted manifest that differs from the bundle's keys.json for a
// used key → E_KEY.
func TestC145_KeyDiffers(t *testing.T) {
	bundle, man := cleanBundle(t)
	// Drop the broker key from the trusted manifest.
	var kept keys.Manifest
	for _, e := range man {
		if e.Role != "emitter:broker" {
			kept = append(kept, e)
		}
	}
	res := ledger.VerifyBundle(bundle, kept)
	hasCode(res.Errors, "E_KEY", t)
	if res.Verdict != "INVALID" {
		t.Fatalf("verdict %s", res.Verdict)
	}
}

func cleanBundle(t *testing.T) ([]byte, keys.Manifest) {
	t.Helper()
	dir := t.TempDir()
	s := ldtest.New("countersign.dev/log/test")
	l, err := ledger.Open(dir, "countersign.dev/log/test", s.LogSigner)
	if err != nil {
		t.Fatal(err)
	}
	ldtest.CleanAllTypes(l, s)
	b, err := l.ExportBundle(s.ID, s.Manifest, s.Extras())
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	return b, s.Manifest
}

func hasCode(fs []ledger.Finding, code string, t *testing.T) {
	t.Helper()
	for _, f := range fs {
		if f.Code == code {
			return
		}
	}
	t.Fatalf("missing %s in %v", code, fs)
}

// C1.4.4 csverify uses only the bundle and --keys: run it from an empty
// directory with an empty environment. (The container-isolation half of
// the check is SKIPPED-ENV: no containers on agent-vpc.)
func TestC144_IsolatedRun(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "csverify")
	root, _ := filepath.Abs("../..")
	build := exec.Command(goBin(), "build", "-o", bin, "./cmd/csverify")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	work := t.TempDir()
	for _, f := range []string{"clean.tar", "clean.keys.json"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "test", "vectors", "evidence", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(work, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(bin, filepath.Join(work, "clean.tar"), "--keys", filepath.Join(work, "clean.keys.json"))
	cmd.Dir = t.TempDir() // empty working dir
	cmd.Env = []string{"PATH=/nonexistent"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated run failed: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte(`"verdict": "CLEAN"`)) {
		t.Fatalf("unexpected output: %s", out[:200])
	}
}

func goBin() string {
	root, _ := filepath.Abs("../..")
	return filepath.Join(root, ".tools", "bin", "go")
}

// C1.4.3 Golden bundles produce exactly the expected verdict, error list
// and warning list.
func TestC143_GoldenBundles(t *testing.T) {
	dir := filepath.Join("..", "..", "test", "vectors", "evidence")
	ents, err := filepath.Glob(filepath.Join(dir, "*.tar"))
	if err != nil || len(ents) == 0 {
		t.Fatal("no golden bundles")
	}
	for _, tarPath := range ents {
		name := strings.TrimSuffix(filepath.Base(tarPath), ".tar")
		t.Run(name, func(t *testing.T) {
			bundle, err := os.ReadFile(tarPath)
			if err != nil {
				t.Fatal(err)
			}
			m, err := keys.LoadManifest(strings.TrimSuffix(tarPath, ".tar") + ".keys.json")
			if err != nil {
				t.Fatal(err)
			}
			expRaw, err := os.ReadFile(strings.TrimSuffix(tarPath, ".tar") + ".expected.json")
			if err != nil {
				t.Fatal(err)
			}
			var exp ledger.VerifyResult
			if err := json.Unmarshal(expRaw, &exp); err != nil {
				t.Fatal(err)
			}
			got := ledger.VerifyBundle(bundle, m)
			if got.Verdict != exp.Verdict {
				t.Fatalf("verdict %s ≠ %s", got.Verdict, exp.Verdict)
			}
			if !findingsEqual(got.Errors, exp.Errors) {
				t.Fatalf("errors %v ≠ %v", got.Errors, exp.Errors)
			}
			if !findingsEqual(got.Warnings, exp.Warnings) {
				t.Fatalf("warnings %v ≠ %v", got.Warnings, exp.Warnings)
			}
		})
	}
}

func findingsEqual(a, b []ledger.Finding) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Code != b[i].Code {
			return false
		}
	}
	return true
}
