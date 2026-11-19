// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Package creds holds the credential machinery of spec/04 §4: the secret
// store interface, the file-backed store used in local mode, placeholder
// generation, injection into outbound requests, the credential-shape
// detector, and the streaming response scrubber.
//
// Real secret values exist only in broker memory (and, in cluster mode from
// M4, in Kubernetes Secrets). Records, logs and evidence carry the
// credential ID ("<secret>:<key>") or the placeholder, never a value.
package creds

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// Store resolves credential refs to secret values. Implementations must
// treat values as opaque and never log or record them.
type Store interface {
	// Get returns the value named by ref ("<secret>/<key>").
	Get(ref Ref) (string, error)
	// Close releases the store's resources.
	Close() error
}

// Ref is one addressable secret: a store entry name plus a key within it
// (04 §4: credential.ref {secret, key}). Its string form "<secret>:<key>"
// is the credential ID recorded on effects — never the value.
type Ref struct {
	Secret string
	Key    string
}

// ID renders the ref as recorded in effect.http.decision.credentials.
func (r Ref) ID() string { return r.Secret + ":" + r.Key }

// ErrNoSecret is returned by Get when the ref names nothing in the store.
var ErrNoSecret = errors.New("creds: no such secret")

// secretsDoc is the on-disk form of the local-mode store: a YAML mapping
// of secret name to key -> value entries. Values are fixture canaries in
// tests (CANARY_[A-Z0-9]{32}); real deployments keep this file inside the
// broker's private data directory.
type secretsDoc struct {
	Secrets map[string]map[string]string `yaml:"secrets"`
}

// FileStore is the local-mode credential store (M3.2): a YAML file read
// once at session open; values then live only in memory.
type FileStore struct {
	secrets map[string]map[string]string
}

// LoadFile parses a secrets file (strict: unknown keys rejected).
func LoadFile(path string) (*FileStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("credentials file: %w", err)
	}
	return ParseFile(data)
}

// ParseFile parses secrets YAML bytes.
func ParseFile(data []byte) (*FileStore, error) {
	var doc secretsDoc
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("credentials file: %w", err)
	}
	for name, keys := range doc.Secrets {
		if name == "" {
			return nil, errors.New("credentials file: empty secret name")
		}
		for k, v := range keys {
			if k == "" {
				return nil, fmt.Errorf("credentials file: secret %q: empty key", name)
			}
			if v == "" {
				return nil, fmt.Errorf("credentials file: secret %q key %q: empty value", name, k)
			}
		}
	}
	return &FileStore{secrets: doc.Secrets}, nil
}

// Get implements Store.
func (s *FileStore) Get(ref Ref) (string, error) {
	if keys, ok := s.secrets[ref.Secret]; ok {
		if v, ok := keys[ref.Key]; ok {
			return v, nil
		}
	}
	return "", fmt.Errorf("%w: %s", ErrNoSecret, ref.ID())
}

// Close implements Store.
func (s *FileStore) Close() error { return nil }

// Has reports whether the ref resolves — used at session open to fail
// closed on misconfigured policies (04 §4: a credentialed grant whose
// secret is absent must never reach request time).
func (s *FileStore) Has(ref Ref) bool {
	_, err := s.Get(ref)
	return err == nil
}

// SecretSource is the Kubernetes-side dependency of KubeStore: fetch one
// Secret's data map by namespace/name. The real implementation is the
// controller client (M4); tests use an in-memory one. It is an interface
// boundary, not a running feature: no cluster exists until M4.
type SecretSource interface {
	GetSecret(ctx context.Context, namespace, name string) (map[string][]byte, error)
}

// KubeStore resolves refs as Kubernetes Secret data entries
// (04 §4: ref.secret = Secret name, ref.key = data key). It is interface
// only until M4 wires the client; the resolution logic is complete and
// unit-tested against an in-memory SecretSource.
type KubeStore struct {
	namespace string
	src       SecretSource
	mu        sync.Mutex
	cache     map[string]map[string][]byte
}

// NewKubeStore returns a store reading Secrets from namespace via src.
func NewKubeStore(namespace string, src SecretSource) *KubeStore {
	return &KubeStore{namespace: namespace, src: src, cache: map[string]map[string][]byte{}}
}

// Get implements Store.
func (s *KubeStore) Get(ref Ref) (string, error) {
	s.mu.Lock()
	data, ok := s.cache[ref.Secret]
	s.mu.Unlock()
	if !ok {
		var err error
		data, err = s.src.GetSecret(context.Background(), s.namespace, ref.Secret)
		if err != nil {
			return "", fmt.Errorf("creds: secret %s: %w", ref.Secret, err)
		}
		s.mu.Lock()
		s.cache[ref.Secret] = data
		s.mu.Unlock()
	}
	if v, ok := data[ref.Key]; ok && len(v) > 0 {
		return string(v), nil
	}
	return "", fmt.Errorf("%w: %s", ErrNoSecret, ref.ID())
}

// Close implements Store.
func (s *KubeStore) Close() error { return nil }
