// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Package keys holds signing keys, the key manifest, and the emitter that
// signs evidence records (M1.2, 02 §4). Ed25519 only — no other algorithms,
// no certificates, no threshold signing.
package keys

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Signer is the one interface for private-key use (02 §4).
type Signer interface {
	KeyID() string
	Public() ed25519.PublicKey
	Sign(msg []byte) []byte
}

type fileSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	kid  string
}

// NewSigner returns a signer from a 32-byte seed.
func NewSigner(seed []byte) Signer {
	priv := ed25519.NewKeyFromSeed(seed)
	return &fileSigner{priv: priv, pub: priv.Public().(ed25519.PublicKey), kid: KeyID(priv.Public().(ed25519.PublicKey))}
}

// KeyID is the first 16 bytes of SHA-256 of the raw public key, lowercase hex.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

func (s *fileSigner) KeyID() string             { return s.kid }
func (s *fileSigner) Public() ed25519.PublicKey { return s.pub }
func (s *fileSigner) Sign(msg []byte) []byte    { return ed25519.Sign(s.priv, msg) }

const pemType = "PRIVATE KEY"

// SaveSigner writes the signer as PKCS8 PEM, mode 0600.
func SaveSigner(s Signer, path string) error {
	fs, ok := s.(*fileSigner)
	if !ok {
		return errors.New("only fileSigner can be saved")
	}
	der, err := x509.MarshalPKCS8PrivateKey(fs.priv)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}), 0o600)
}

// LoadSigner reads a PKCS8 PEM Ed25519 key.
func LoadSigner(path string) (Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != pemType {
		return nil, fmt.Errorf("%s: not a %s PEM", path, pemType)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", path)
	}
	return NewSigner(priv.Seed()), nil
}
