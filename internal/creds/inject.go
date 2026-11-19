// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package creds

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"
)

// InjectSpec is the grant's credential material resolved for one request:
// where the secret goes and the two client-visible forms (placeholder and
// real). The real value exists only inside this struct and the mutated
// header — it is never returned to callers.
type InjectSpec struct {
	// Loc is the injection location for records and the pinning rule:
	// "header:<name>" for a header-format credential or "basic" for HTTP
	// Basic (whose location is the Authorization header).
	Loc string

	// header is the outbound header name for both forms.
	header string
	// expect is the exact header value that authorizes replacement
	// (format with the placeholder, or the Basic placeholder form).
	expect string
	// real is the exact header value to write (format with the secret,
	// or the Basic real form).
	real string
	// basicUser, when non-empty, marks a Basic credential and is the
	// configured username; Eval then decodes candidate values so a
	// placeholder hidden inside base64 (in either position) is seen.
	basicUser string
}

// HeaderSpec builds the spec for inject.header + inject.format (04 §4.1–4.2).
func HeaderSpec(name, format, placeholder, secret string) InjectSpec {
	f := func(v string) string {
		return strings.ReplaceAll(format, "{secret}", v)
	}
	return InjectSpec{Loc: "header:" + http.CanonicalHeaderKey(name),
		header: http.CanonicalHeaderKey(name), expect: f(placeholder), real: f(secret)}
}

// BasicSpec builds the spec for inject.basic (04 §4.1–4.2): Authorization:
// Basic base64(username ":" secret).
func BasicSpec(username, placeholder, secret string) InjectSpec {
	b := func(v string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+v))
	}
	return InjectSpec{Loc: "basic", header: "Authorization", basicUser: username,
		expect: b(placeholder), real: b(secret)}
}

// Header returns the header this spec writes to.
func (s InjectSpec) Header() string { return s.header }

// Verdict classifies what the client's inject-location header contained.
type Verdict int

const (
	// InjectAbsent — location held no value; the broker added the credential.
	InjectAbsent Verdict = iota
	// InjectReplaced — location held exactly the expected placeholder form;
	// the broker replaced it with the real credential.
	InjectReplaced
)

// Apply writes the real credential into h per the spec. Call only after
// every 04 §2 check has passed and the write-ahead record is durable —
// it is the moment a real secret first touches wire-bound bytes.
func (s InjectSpec) Apply(h http.Header) {
	h.Del(s.header)
	h.Set(s.header, s.real)
}

// Eval inspects the client's inject-location values: exact placeholder
// form (or absence) authorizes injection; anything else is a denial the
// caller classifies (placeholder material → PLACEHOLDER_MISUSE, other
// non-empty credential material → FOREIGN_CREDENTIAL).
//
// Returns (verdict, ok, hasPlaceholderMaterial):
//   - ok=true: proceed to Apply. verdict is InjectAbsent/InjectReplaced.
//   - ok=false, hasPlaceholderMaterial=true: some value carried a csph_
//     token (any session's, well-formed or not) → PLACEHOLDER_MISUSE.
//   - ok=false, hasPlaceholderMaterial=false: non-empty foreign material
//     → FOREIGN_CREDENTIAL.
func (s InjectSpec) Eval(h http.Header) (Verdict, bool, bool) {
	vals := h.Values(s.header)
	if len(vals) == 0 {
		return InjectAbsent, true, false
	}
	sawPH := false
	allExpected := true
	for _, v := range vals {
		if v == "" {
			continue
		}
		if v != s.expect {
			allExpected = false
		}
		if s.valueHasPH(v) {
			sawPH = true
		}
	}
	if allExpected {
		return InjectReplaced, true, false
	}
	return 0, false, sawPH
}

// valueHasPH reports whether v carries placeholder material — directly,
// or inside the decoded payload of a Basic value for basic credentials.
func (s InjectSpec) valueHasPH(v string) bool {
	if HasPlaceholderToken(v) {
		return true
	}
	if s.basicUser != "" && strings.HasPrefix(v, "Basic ") {
		dec, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v, "Basic "))
		if err == nil && HasPlaceholderToken(string(dec)) {
			return true
		}
	}
	return false
}

// HasPlaceholderToken reports whether s contains a csph_ token marker.
// Deliberately marker-wide: any csph_ substring — this session's, another
// session's, or a half-formed one — is placeholder material outside the
// exact inject slot and means PLACEHOLDER_MISUSE (04 §4.3).
func HasPlaceholderToken(s string) bool {
	return strings.Contains(s, placeholderPrefix)
}

// HasPlaceholderTokenB is HasPlaceholderToken for byte slices.
func HasPlaceholderTokenB(b []byte) bool {
	return bytes.Contains(b, []byte(placeholderPrefix))
}
