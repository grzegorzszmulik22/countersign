// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package fxlib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA is the test root certificate authority all fixture servers use
// (M0.3: "each serving TLS from a test root CA"). It is created once per run
// directory by EnsureCA; leaf certificates are minted per fixture by Issue.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	serial  int64
	mu      sync.Mutex
	certPEM []byte
	keyPEM  []byte
}

// EnsureCA loads the CA from dir/ca.crt and dir/ca.key, or creates a new root
// CA there if the files do not exist.
func EnsureCA(dir string) (*CA, error) {
	crtPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	crtPEM, crtErr := os.ReadFile(crtPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if crtErr == nil && keyErr == nil {
		return parseCA(crtPEM, keyPEM)
	}
	if crtErr != nil && !os.IsNotExist(crtErr) {
		return nil, crtErr
	}
	if keyErr != nil && !os.IsNotExist(keyErr) {
		return nil, keyErr
	}
	return generateCA(dir, crtPath, keyPath)
}

func parseCA(crtPEM, keyPEM []byte) (*CA, error) {
	blk, _ := pem.Decode(crtPEM)
	if blk == nil {
		return nil, fmt.Errorf("ca.crt: no PEM block")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca.crt: %w", err)
	}
	kblk, _ := pem.Decode(keyPEM)
	if kblk == nil {
		return nil, fmt.Errorf("ca.key: no PEM block")
	}
	key, err := x509.ParseECPrivateKey(kblk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca.key: %w", err)
	}
	return &CA{cert: cert, key: key, serial: 1, certPEM: crtPEM, keyPEM: keyPEM}, nil
}

func generateCA(dir, crtPath, keyPath string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Countersign Test Root CA", Organization: []string{"Countersign test fixtures"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(crtPath, crtPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, serial: 1, certPEM: crtPEM, keyPEM: keyPEM}, nil
}

// CertPEM returns the PEM encoding of the root certificate, for client trust
// stores (SSL_CERT_FILE, GIT_SSL_CAINFO, NODE_EXTRA_CA_CERTS, PIP_CERT).
func (c *CA) CertPEM() []byte { return c.certPEM }

// Pool returns a cert pool containing only this CA.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(c.certPEM)
	return p
}

// Issue mints a leaf server certificate for the given DNS/IP SANs.
func (c *CA) Issue(hosts []string) (tls.Certificate, error) {
	c.mu.Lock()
	c.serial++
	serial := c.serial
	c.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"Countersign test fixtures"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
}

// WriteCertPair issues a leaf and writes it as <dir>/<name>.crt and
// <dir>/<name>.key for external consumers.
func (c *CA) WriteCertPair(dir, name string, hosts []string) (crtPath, keyPath string, err error) {
	cert, err := c.Issue(hosts)
	if err != nil {
		return "", "", err
	}
	crtPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	crtOut, err := os.Create(crtPath)
	if err != nil {
		return "", "", err
	}
	for _, c := range cert.Certificate {
		if err := pem.Encode(crtOut, &pem.Block{Type: "CERTIFICATE", Bytes: c}); err != nil {
			_ = crtOut.Close()
			return "", "", err
		}
	}
	if err := crtOut.Close(); err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return "", "", err
	}
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", "", err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		_ = keyOut.Close()
		return "", "", err
	}
	_ = keyOut.Close()
	return crtPath, keyPath, nil
}
