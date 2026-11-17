// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"sync"
)

// SessionKeyStore is the session-key store interface of M2.2/C2.2.5: the
// ONLY place a session CA private key may be serialized. Everything else in
// the broker handles the *ecdsa.PrivateKey object (session) or DER bytes
// (this file); the key never reaches a client, the records or the logs.
//
// A static check greps internal/proxy for x509.Marshal*/pem encoders and
// requires every call site to live in this file.
type SessionKeyStore interface {
	// Put stores the session's CA key under id.
	Put(id string, key *ecdsa.PrivateKey) error
	// Get returns the stored key for id.
	Get(id string) (*ecdsa.PrivateKey, bool)
}

// MemoryKeyStore keeps session CA keys as DER in memory (local mode). The
// serialization round trip is deliberate: the store boundary is where key
// material is allowed to cross into bytes.
type MemoryKeyStore struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

// NewMemoryKeyStore returns an empty in-memory store.
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{keys: map[string][]byte{}}
}

// Put implements SessionKeyStore.
func (s *MemoryKeyStore) Put(id string, key *ecdsa.PrivateKey) error {
	der, err := marshalSessionKey(key)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[id] = der
	return nil
}

// Get implements SessionKeyStore.
func (s *MemoryKeyStore) Get(id string) (*ecdsa.PrivateKey, bool) {
	s.mu.RLock()
	der, ok := s.keys[id]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, false
	}
	return key, true
}

// marshalSessionKey is the single serialization call site for session CA
// private keys (C2.2.5).
func marshalSessionKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("session key marshal: %w", err)
	}
	return der, nil
}
