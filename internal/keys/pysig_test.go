// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package keys_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/evidence/evtest"
	"github.com/countersign/countersign/internal/keys"
)

// C1.2.3 Signature verifies with an independent Ed25519 implementation (the
// Python cryptography library) over the PAE bytes.
func TestC123_PythonVerifiesPAESig(t *testing.T) {
	python := "../../.tools/bin/python3"
	if _, err := os.Stat(python); err != nil {
		p, err := exec.LookPath("python3")
		if err != nil {
			t.Skip("no pinned python3")
		}
		python = p
	}
	s := keys.NewSigner(seedBytes(t))
	em := keys.NewEmitter("broker", testULID, s)
	body, _ := evtest.Sample("observer.gap")
	line, _, err := em.Emit("observer.gap", body, testTS)
	if err != nil {
		t.Fatal(err)
	}
	env, _, _, err := evidence.DecodeRecordLine(line)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "v.py")
	code := `import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sys.argv[1]))
pae = bytes.fromhex(sys.argv[2])
sig = bytes.fromhex(sys.argv[3])
try:
    pub.verify(sig, pae)
except InvalidSignature:
    sys.exit(1)
`
	if err := os.WriteFile(script, []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	sig := env.Signatures[0]
	cmd := exec.Command(python, script,
		hex.EncodeToString(s.Public()),
		hex.EncodeToString(env.PAE()),
		hex.EncodeToString(sig.Sig))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("python rejected valid signature: %v\n%s", err, out)
	}
	// A flipped bit in the signature must be rejected by the same oracle.
	bad := bytes.Clone(sig.Sig)
	bad[0] ^= 1
	cmd = exec.Command(python, script,
		hex.EncodeToString(s.Public()),
		hex.EncodeToString(env.PAE()),
		hex.EncodeToString(bad))
	if err := cmd.Run(); err == nil {
		t.Fatal("python accepted a corrupted signature")
	}
}
