// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/countersign/countersign/internal/creds"
	"github.com/countersign/countersign/internal/policy"
)

// SessionFile is the local-mode session table (M2.1): a YAML document
// listing sessions with their proxy token, client address and policy file.
type SessionFile struct {
	Sessions []SessionEntry `yaml:"sessions"`
}

// SessionEntry is one row of the session table.
type SessionEntry struct {
	ID          string `yaml:"id"`
	Token       string `yaml:"token"`
	ClientIP    string `yaml:"client_ip"`
	Policy      string `yaml:"policy"`
	Credentials string `yaml:"credentials"` // local-mode secrets file (04 §4)
}

// Session is an open session: its policy, its key store entry, the CA minted
// at session open and its per-session record chain.
type Session struct {
	ID       string
	Token    string
	ClientIP netip.Prefix // single-address prefix when the table gives an IP
	Policy   *policy.SessionPolicy

	// placeholders maps credentialed grant ID -> the session's csph_ value
	// (04 §4.1). It is the only client-side form of a credential; the real
	// value stays inside credStore until the broker injects it.
	placeholders map[string]string
	credStore    creds.Store
	rate         *rateTable

	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey

	// appendMu serializes record appends for this session: the sink's
	// chain assignment and the durable write run under it (B2-02).
	appendMu sync.Mutex

	// connSem bounds concurrent client connections (M2.5: 256/session);
	// dialSem bounds in-flight upstream dials (64/session).
	connSem chan struct{}
	dialSem chan struct{}

	leafMu    sync.Mutex
	leafCache map[string]*tls.Certificate
	leafOrder []string // oldest first; bounded by leafCacheMax
}

const leafCacheMax = 4096 // spec M2.2: per-session leaf cache bounded LRU

// loadSessions reads the session table; each entry opens a session: policy
// loaded, session CA minted in memory (M2.2). Paths in the table are
// resolved relative to the table's directory.
func loadSessions(path string, keys SessionKeyStore) (map[string]*Session, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("session table: %w", err)
	}
	var f SessionFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("session table: %w", err)
	}
	if len(f.Sessions) == 0 {
		return nil, fmt.Errorf("session table %s: no sessions", path)
	}
	dir := filepath.Dir(path)
	out := map[string]*Session{}
	ids := map[string]bool{}
	for i, e := range f.Sessions {
		if e.ID == "" || e.Token == "" || e.ClientIP == "" || e.Policy == "" {
			return nil, fmt.Errorf("session table: sessions[%d] requires id, token, client_ip, policy", i)
		}
		if ids[e.ID] {
			return nil, fmt.Errorf("session table: duplicate session id %q", e.ID)
		}
		ids[e.ID] = true
		pfx, err := parseClientIP(e.ClientIP)
		if err != nil {
			return nil, fmt.Errorf("session table: session %q: %w", e.ID, err)
		}
		polPath := e.Policy
		if !filepath.IsAbs(polPath) {
			polPath = filepath.Join(dir, polPath)
		}
		polData, err := os.ReadFile(polPath)
		if err != nil {
			return nil, fmt.Errorf("session table: session %q policy: %w", e.ID, err)
		}
		pol, err := policy.Load(polData)
		if err != nil {
			return nil, fmt.Errorf("session table: session %q policy: %w", e.ID, err)
		}
		s := &Session{
			ID:           e.ID,
			Token:        e.Token,
			ClientIP:     pfx,
			Policy:       pol,
			placeholders: map[string]string{},
			rate:         newRateTable(),
			connSem:      make(chan struct{}, maxSessionConns),
			dialSem:      make(chan struct{}, maxSessionDials),
			leafCache:    map[string]*tls.Certificate{},
		}
		// Credential store + placeholders (04 §4, M3.2): a credentialed
		// grant demands a resolvable store at session open — fail closed.
		credentialed := false
		for i := range pol.Spec.Grants {
			if pol.Spec.Grants[i].Credential != nil {
				credentialed = true
			}
		}
		if credentialed || e.Credentials != "" {
			if e.Credentials == "" {
				return nil, fmt.Errorf("session table: session %q: credentialed grants require credentials", e.ID)
			}
			credPath := e.Credentials
			if !filepath.IsAbs(credPath) {
				credPath = filepath.Join(dir, credPath)
			}
			store, err := creds.LoadFile(credPath)
			if err != nil {
				return nil, fmt.Errorf("session table: session %q credentials: %w", e.ID, err)
			}
			s.credStore = store
			for i := range pol.Spec.Grants {
				g := &pol.Spec.Grants[i]
				if g.Credential == nil {
					continue
				}
				ref := creds.Ref{Secret: g.Credential.Ref.Secret, Key: g.Credential.Ref.Key}
				if !store.Has(ref) {
					return nil, fmt.Errorf("session table: session %q grant %q: credential ref %s not in store", e.ID, g.ID, ref.ID())
				}
				s.placeholders[g.ID] = creds.NewPlaceholder(e.ID, g.ID)
			}
		}
		if err := s.mintCA(); err != nil {
			return nil, fmt.Errorf("session table: session %q CA: %w", e.ID, err)
		}
		if keys != nil {
			if err := keys.Put(e.ID, s.caKey); err != nil {
				return nil, fmt.Errorf("session table: session %q key store: %w", e.ID, err)
			}
		}
		out[e.Token] = s
	}
	if len(out) != len(f.Sessions) {
		return nil, fmt.Errorf("session table: duplicate tokens")
	}
	return out, nil
}

// parseClientIP accepts an IP literal (single host prefix) or a CIDR prefix.
func parseClientIP(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("client_ip %q is not an IP or CIDR", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// admits reports whether the connection's remote IP belongs to this session
// (02 §3: token and source address must agree).
func (s *Session) admits(ip netip.Addr) bool {
	return s.ClientIP.Contains(ip)
}

// mintCA creates the per-session ECDSA P-256 CA in memory (M2.2). The
// private key object lives only in the session and the key store.
func (s *Session) mintCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "countersign session " + s.ID, Organization: []string{"Countersign"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	s.caKey, s.caCert = key, cert
	return nil
}

// CACert returns the session's CA certificate (safe to hand to clients).
func (s *Session) CACert() *x509.Certificate { return s.caCert }

// LeafCacheLen reports the number of cached leaf certificates (tests).
func (s *Session) LeafCacheLen() int {
	s.leafMu.Lock()
	defer s.leafMu.Unlock()
	return len(s.leafCache)
}
