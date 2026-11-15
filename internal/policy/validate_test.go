// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/countersign/countersign/internal/policy"
)

// TestInvalidPolicies is C3.1.2: each file under test/vectors/policy/invalid/
// must be rejected with a message naming the field declared in its
// `# field:` comment.
func TestInvalidPolicies(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "test/vectors/policy/invalid")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read invalid dir: %v", err)
	}
	var files []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			files = append(files, e.Name())
		}
	}
	if len(files) != 20 {
		t.Fatalf("want exactly 20 invalid policies, got %d", len(files))
	}
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		field := ""
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "# field:") {
				field = strings.TrimSpace(strings.TrimPrefix(line, "# field:"))
			}
		}
		if field == "" {
			t.Fatalf("%s: no '# field:' comment", name)
		}
		_, err = policy.Load(data)
		if err == nil {
			t.Errorf("%s: invalid policy accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), field) {
			t.Errorf("%s: error %q does not name field %q", name, err.Error(), field)
		}
	}
}

// TestPolicyDigest is C3.1.3: the digest is SHA-256 over the exact file bytes,
// so a whitespace-only change must alter it.
func TestPolicyDigest(t *testing.T) {
	vf := loadVectors(t)
	for name, src := range vf.Policies {
		data := []byte(src)
		sum := sha256.Sum256(data)
		want := hex.EncodeToString(sum[:])
		if got := policy.Digest(data); got != want {
			t.Fatalf("policy %s: Digest() = %q, want sha256 %q", name, got, want)
		}
		p, err := policy.Load(data)
		if err != nil {
			t.Fatalf("policy %s: load: %v", name, err)
		}
		if p.DigestHex() != want {
			t.Fatalf("policy %s: DigestHex() = %q, want %q", name, p.DigestHex(), want)
		}
		mutated := append(bytes.Clone(data), ' ', '\n')
		if policy.Digest(mutated) == want {
			t.Fatalf("policy %s: whitespace-only change did not alter digest", name)
		}
	}
}
