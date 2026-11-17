// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// requestDigest computes the 04 §3 digest: SHA-256 over
//
//	"countersign-request-v1\n" ‖ METHOD "\n" ‖ scheme "\n" ‖ authority "\n"
//	‖ raw-path "\n" ‖ hex(SHA-256(raw-query)) "\n" ‖ hex(SHA-256(body)) "\n"
//	‖ optional "content-type:" trimmed-value "\n"
//
// where authority is the lowercase host with ":port" only when non-default.
// Credential-bearing headers are excluded by construction (only
// content-type is read).
func requestDigest(method, scheme, authority, rawPath, rawQuery string, bodySHA [32]byte, hdr http.Header) string {
	h := sha256.New()
	h.Write([]byte("countersign-request-v1\n"))
	h.Write([]byte(method))
	h.Write([]byte("\n"))
	h.Write([]byte(scheme))
	h.Write([]byte("\n"))
	h.Write([]byte(authority))
	h.Write([]byte("\n"))
	h.Write([]byte(rawPath))
	h.Write([]byte("\n"))
	q := sha256.Sum256([]byte(rawQuery))
	h.Write([]byte(hex.EncodeToString(q[:])))
	h.Write([]byte("\n"))
	h.Write([]byte(hex.EncodeToString(bodySHA[:])))
	h.Write([]byte("\n"))
	if ct, ok := hdr[http.CanonicalHeaderKey("Content-Type")]; ok && len(ct) > 0 {
		h.Write([]byte("content-type:"))
		h.Write([]byte(strings.TrimSpace(ct[0])))
		h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// digestAuthority renders the authority field of 04 §3: lowercase host,
// ":port" only when non-default for the scheme.
func digestAuthority(host string, port int, scheme string) string {
	def := 443
	if scheme == "http" {
		def = 80
	}
	if port != 0 && port != def {
		return strings.ToLower(host) + ":" + itoa(port)
	}
	return strings.ToLower(host)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
