// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package keys_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/evidence/evtest"
	"github.com/countersign/countersign/internal/keys"
)

const (
	testSeed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	testPub  = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
	testKID  = "56475aa75463474c0285df5dbf2bcab7"
	testULID = "01K7D7JQ9Y8T4X2Z6B4H4F4F4F"
	testTS   = "2026-11-14T00:00:00.000000000Z"
)

func seedBytes(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(testSeed)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// C1.2.1 Key ID equals the first 16 bytes of SHA-256 of the public key,
// checked against a hand-computed vector (python: see plan evidence).
func TestC121_KeyIDVector(t *testing.T) {
	s := keys.NewSigner(seedBytes(t))
	pub, err := hex.DecodeString(testPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.Public(), pub) {
		t.Fatalf("public key mismatch: got %x want %x", s.Public(), pub)
	}
	if got := keys.KeyID(s.Public()); got != testKID {
		t.Fatalf("key id mismatch: got %s want %s", got, testKID)
	}
	if s.KeyID() != testKID {
		t.Fatalf("signer key id: got %s want %s", s.KeyID(), testKID)
	}
}

// Round-trip: file-backed save/load preserves the key.
func TestSignerFileRoundTrip(t *testing.T) {
	s := keys.NewSigner(seedBytes(t))
	p := t.TempDir() + "/k.pem"
	if err := keys.SaveSigner(s, p); err != nil {
		t.Fatal(err)
	}
	s2, err := keys.LoadSigner(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.Public(), s2.Public()) || s.KeyID() != s2.KeyID() {
		t.Fatal("key not preserved by save/load")
	}
	if !ed25519.Verify(s2.Public(), []byte("m"), s2.Sign([]byte("m"))) {
		t.Fatal("loaded signer cannot sign")
	}
}

func manifestWith(t *testing.T, role string) keys.Manifest {
	t.Helper()
	s := keys.NewSigner(seedBytes(t))
	m, err := keys.NewManifest([]keys.ManifestEntry{{
		Role:      role,
		Signer:    s,
		NotBefore: "2020-01-01T00:00:00Z",
	}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func mkRecord(t *testing.T, em *keys.Emitter) (*evidence.Envelope, *evidence.Record) {
	t.Helper()
	body, err := evtest.Sample("observer.gap")
	if err != nil {
		t.Fatal(err)
	}
	line, rec, err := em.Emit("observer.gap", body, testTS)
	if err != nil {
		t.Fatal(err)
	}
	env, _, _, err := evidence.DecodeRecordLine(line)
	if err != nil {
		t.Fatal(err)
	}
	return env, rec
}

// C1.2.4 A signer whose role in the manifest does not match the record's
// emitter role is rejected at verification.
func TestC124_RoleMismatch(t *testing.T) {
	s := keys.NewSigner(seedBytes(t))
	em := keys.NewEmitter("broker", testULID, s)
	env, rec := mkRecord(t, em)

	// Correct role verifies.
	if err := keys.VerifyRecord(env, rec, manifestWith(t, "emitter:broker")); err != nil {
		t.Fatalf("correct role rejected: %v", err)
	}
	// Wrong manifest role is rejected.
	err := keys.VerifyRecord(env, rec, manifestWith(t, "emitter:world"))
	if !errors.Is(err, keys.ErrKey) {
		t.Fatalf("wrong role: got %v, want ErrKey", err)
	}
	// Non-emitter role is rejected.
	err = keys.VerifyRecord(env, rec, manifestWith(t, "log"))
	if !errors.Is(err, keys.ErrKey) {
		t.Fatalf("log role on emitter record: got %v, want ErrKey", err)
	}
}

// Validity window: not_before/not_after bound the record's ts.
func TestC124_ValidityWindow(t *testing.T) {
	s := keys.NewSigner(seedBytes(t))
	em := keys.NewEmitter("broker", testULID, s)
	env, rec := mkRecord(t, em)

	after, err := keys.NewManifest([]keys.ManifestEntry{{
		Role: "emitter:broker", Signer: s,
		NotBefore: "2030-01-01T00:00:00Z",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.VerifyRecord(env, rec, after); !errors.Is(err, keys.ErrKey) {
		t.Fatalf("not-yet-valid key accepted: %v", err)
	}

	expired, err := keys.NewManifest([]keys.ManifestEntry{{
		Role: "emitter:broker", Signer: s,
		NotBefore: "2020-01-01T00:00:00Z",
		NotAfter:  strp("2021-01-01T00:00:00Z"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.VerifyRecord(env, rec, expired); !errors.Is(err, keys.ErrKey) {
		t.Fatalf("expired key accepted: %v", err)
	}
}

// Unknown keyid is rejected as a key error.
func TestC124_UnknownKey(t *testing.T) {
	s := keys.NewSigner(seedBytes(t))
	other := keys.NewSigner(bytes.Repeat([]byte{9}, 32))
	em := keys.NewEmitter("broker", testULID, s)
	env, rec := mkRecord(t, em)
	if err := keys.VerifyRecord(env, rec, manifestWith(t, "emitter:broker")); err != nil {
		t.Fatal(err)
	}
	_ = other
	err := keys.VerifyRecord(env, rec, keys.Manifest(nil))
	if !errors.Is(err, keys.ErrKey) {
		t.Fatalf("unknown keyid: got %v, want ErrKey", err)
	}
}

func strp(s string) *string { return &s }

// ts ordering helper used by manifest tests.
func TestManifestTSOrder(t *testing.T) {
	a, _ := time.Parse(time.RFC3339Nano, "2026-11-14T00:00:00.000000000Z")
	b, _ := time.Parse(time.RFC3339Nano, "2021-01-01T00:00:00Z")
	if !a.After(b) {
		t.Fatal("time sanity")
	}
}
