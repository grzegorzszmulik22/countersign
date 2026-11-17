// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"time"
)

// mintLeaf issues (or returns from the bounded LRU) a leaf certificate for
// host, signed by the session CA: SAN = the requested name, validity 24 h
// (M2.2). host is the client-requested name; callers cross-check it against
// CONNECT authority and SNI before minting. Leaf private keys live only as
// *ecdsa.PrivateKey objects inside tls.Certificate; they are never
// serialized (C2.2.5: only the session-key store serializes key material).
func (s *Session) mintLeaf(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	s.leafMu.Lock()
	defer s.leafMu.Unlock()
	if cert, ok := s.leafCache[host]; ok {
		return cert, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.caCert, &key.PublicKey, s.caKey)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	s.leafCache[host] = cert
	s.leafOrder = append(s.leafOrder, host)
	for len(s.leafOrder) > leafCacheMax {
		delete(s.leafCache, s.leafOrder[0])
		s.leafOrder = s.leafOrder[1:]
	}
	return cert, nil
}
