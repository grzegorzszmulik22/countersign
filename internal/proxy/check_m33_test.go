// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/countersign/countersign/internal/creds"
)

// M3.3 checks: pinning, placeholder misuse and the credential-shape
// detector (04 §4.3, §4.4). All share the M3 rig of check_m32_test.go.

// denyReason extracts the broker's deny reason off a response.
func denyReason(res *http.Response) string {
	return res.Header.Get("X-Countersign-Reason")
}

// --- C3.3.1 -------------------------------------------------------------
// A credentialed-grant request carrying somebody else's credential in
// x-api-key, Authorization or Cookie is refused FOREIGN_CREDENTIAL; the
// upstream never sees it (scenario A6 in miniature — the upload does not
// reach the service).
func TestC331ForeignCredential(t *testing.T) {
	ce := startCredEnv(t, m3Grants, nil)
	e := ce.env

	cases := []struct {
		name string
		hdr  map[string]string
	}{
		{"x-api-key", map[string]string{"X-Api-Key": "sk-ant-someone-elses-key-0000000000000000"}},
		{"authorization", map[string]string{"Authorization": "Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"}},
		{"cookie", map[string]string{"Cookie": "session=ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"}},
		{"basic", map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass123456"))}},
	}
	before := ce.anthro.count()
	for _, c := range cases {
		res, body := doCred(t, e, "tok-one", "POST", "https://api.anthropic.com/v1/messages",
			c.hdr, []byte(`{"upload":true}`))
		if res.StatusCode != http.StatusForbidden || denyReason(res) != "FOREIGN_CREDENTIAL" {
			t.Fatalf("%s: status=%d reason=%q body=%s", c.name, res.StatusCode, denyReason(res), body)
		}
	}
	if got := ce.anthro.count(); got != before {
		t.Fatalf("foreign-credential requests reached upstream: %d new", got-before)
	}
	// Deny records exist and carry no secret material.
	raw, _ := os.ReadFile(filepath.Join(e.records, "s1.jsonl"))
	canaryFree(t, "record file", raw)
	if !bytes.Contains(raw, []byte("FOREIGN_CREDENTIAL")) {
		t.Fatal("no FOREIGN_CREDENTIAL deny record")
	}
}

// --- C3.3.2 -------------------------------------------------------------
// The session's own placeholder outside the exact inject slot — in the
// query string, a JSON body, another header, or sent to another host —
// is PLACEHOLDER_MISUSE.
func TestC332PlaceholderMisuse(t *testing.T) {
	ce := startCredEnv(t, m3Grants, nil)
	e := ce.env
	p := ph(t, e, "s1", "anthropic")

	cases := []struct {
		name   string
		method string
		url    string
		hdr    map[string]string
		body   []byte
	}{
		{"query", "POST", "https://api.anthropic.com/v1/messages?key=" + url.QueryEscape(p), nil, []byte("{}")},
		{"json-body", "POST", "https://api.anthropic.com/v1/messages", nil,
			[]byte(`{"api_key":"` + p + `"}`)},
		{"other-header", "POST", "https://api.anthropic.com/v1/messages",
			map[string]string{"X-Other": "value " + p}, []byte("{}")},
		{"other-host", "GET", "https://pypi.org/simple/",
			map[string]string{"Authorization": "Bearer " + p}, nil},
		{"cookie", "POST", "https://api.anthropic.com/v1/messages",
			map[string]string{"Cookie": "k=" + p}, []byte("{}")},
		{"slot-junk", "POST", "https://api.anthropic.com/v1/messages",
			map[string]string{"X-Api-Key": p + "extra"}, []byte("{}")},
	}
	for _, c := range cases {
		res, body := doCred(t, e, "tok-one", c.method, c.url, c.hdr, c.body)
		if res.StatusCode != http.StatusForbidden || denyReason(res) != "PLACEHOLDER_MISUSE" {
			t.Fatalf("%s: status=%d reason=%q body=%s", c.name, res.StatusCode, denyReason(res), body)
		}
	}
	if got := ce.anthro.count() + ce.pypi.count(); got != 0 {
		t.Fatalf("misuse requests reached upstream (%d)", got)
	}

	// Basic grant: the placeholder in the Basic *username* (the password
	// slot is the pin) is also misuse.
	pG := ph(t, e, "s1", "github")
	bad := "Basic " + base64.StdEncoding.EncodeToString([]byte(pG+":x"))
	res, _ := doCred(t, e, "tok-one", "GET", "https://github.com/acme/widgets.git/info/refs?service=git-upload-pack",
		map[string]string{"Authorization": bad}, nil)
	if res.StatusCode != http.StatusForbidden || denyReason(res) != "PLACEHOLDER_MISUSE" {
		t.Fatalf("basic-username placeholder: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
	// And the exact pinned form (placeholder as the Basic password) is
	// the one form that authorizes replacement — smoke-checked here;
	// C3.2.4 asserts the full clone.
	good := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+pG))
	res, _ = doCred(t, e, "tok-one", "GET", "https://github.com/acme/widgets.git/info/refs?service=git-upload-pack",
		map[string]string{"Authorization": good}, nil)
	if res.StatusCode != 200 && res.StatusCode != 401 {
		t.Fatalf("pinned basic placeholder: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
}

// --- C3.3.3 -------------------------------------------------------------
// A placeholder belonging to another session — or to another grant of
// the same session — is misuse too.
func TestC333CrossSessionPlaceholder(t *testing.T) {
	ce := startCredEnv(t, m3Grants, nil)
	e := ce.env
	pS2 := ph(t, e, "s2", "anthropic")
	pOtherGrant := ph(t, e, "s1", "hub-api")

	for i, p := range []string{pS2, pOtherGrant} {
		res, body := doCred(t, e, "tok-one", "POST", "https://api.anthropic.com/v1/messages",
			map[string]string{"X-Api-Key": p}, []byte("{}"))
		if res.StatusCode != http.StatusForbidden || denyReason(res) != "PLACEHOLDER_MISUSE" {
			t.Fatalf("case %d: status=%d reason=%q body=%s", i, res.StatusCode, denyReason(res), body)
		}
	}
	if got := ce.anthro.count(); got != 0 {
		t.Fatalf("cross-session requests reached upstream (%d)", got)
	}
}

// --- C3.3.4 -------------------------------------------------------------
// A §4.4 credential-shaped string in the URL or the buffered body of a
// credentialed-grant request is FOREIGN_CREDENTIAL; the identical string
// to a non-credentialed grant is allowed (the detector only guards
// credentialed grants — D14).
func TestC334CredentialShape(t *testing.T) {
	ce := startCredEnv(t, m3Grants, nil)
	e := ce.env
	shape := "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"

	res, body := doCred(t, e, "tok-one", "POST",
		"https://api.anthropic.com/v1/messages?ref="+shape, nil, []byte("{}"))
	if res.StatusCode != http.StatusForbidden || denyReason(res) != "FOREIGN_CREDENTIAL" {
		t.Fatalf("shape in URL: status=%d reason=%q body=%s", res.StatusCode, denyReason(res), body)
	}
	res, _ = doCred(t, e, "tok-one", "POST", "https://api.anthropic.com/v1/messages",
		nil, []byte(`{"note":"`+shape+`"}`))
	if res.StatusCode != http.StatusForbidden || denyReason(res) != "FOREIGN_CREDENTIAL" {
		t.Fatalf("shape in body: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
	// Percent-encoded shape still detected (raw + decoded forms scanned).
	enc := strings.ReplaceAll(shape, "_", "%5f")
	res, _ = doCred(t, e, "tok-one", "POST",
		"https://api.anthropic.com/v1/messages?ref="+enc, nil, []byte("{}"))
	if res.StatusCode != http.StatusForbidden || denyReason(res) != "FOREIGN_CREDENTIAL" {
		t.Fatalf("encoded shape in URL: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
	// Same shape to a non-credentialed grant: allowed (and only redacted
	// in any preview — the detector's other §4.4 use). Once on another
	// host, once on the SAME host under a different grant: credentialed
	// status attaches to the grant, not the host.
	res, _ = doCred(t, e, "tok-one", "GET",
		"https://pypi.org/simple/?q="+shape, nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("non-credentialed shape request: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
	res, _ = doCred(t, e, "tok-one", "POST", "https://api.anthropic.com/v1/files",
		nil, []byte(`{"note":"`+shape+`"}`))
	if res.StatusCode != 200 {
		t.Fatalf("non-credentialed grant on credentialed host: status=%d reason=%q", res.StatusCode, denyReason(res))
	}
}

// --- C3.3.5 -------------------------------------------------------------
// The detector itself: every positive vector in credshapes.json is
// detected, no negative is flagged (the file is the conformance oracle;
// internal/creds re-runs the same table).
func TestC335ShapeVectorsEndToEnd(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "vectors", "credshapes.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vec struct {
		Positive []string `json:"positive"`
		Negative []string `json:"negative"`
	}
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vec.Positive) < 20 || len(vec.Negative) < 20 {
		t.Fatalf("want ≥20 vectors per side (≥5 per shape), got %d/%d",
			len(vec.Positive), len(vec.Negative))
	}
	for _, s := range vec.Positive {
		if !creds.Match([]byte(s)) {
			t.Errorf("positive not detected: %q", s)
		}
	}
	for _, s := range vec.Negative {
		if creds.Match([]byte(s)) {
			t.Errorf("negative flagged: %q", s)
		}
	}
}

// --- C3.3.6 -------------------------------------------------------------
// Ordinary bearer-less requests to non-credentialed grants are
// unaffected: no credential material is attached or required, and
// arbitrary non-credential headers pass through.
func TestC336NonCredentialedUnaffected(t *testing.T) {
	ce := startCredEnv(t, m3Grants, nil)
	e := ce.env

	res, body := doCred(t, e, "tok-one", "GET", "https://pypi.org/simple/",
		map[string]string{"X-Custom": "anything", "Accept": "text/html"}, nil)
	if res.StatusCode != 200 {
		t.Fatalf("status=%d reason=%q body=%s", res.StatusCode, denyReason(res), body)
	}
	got := ce.pypi.last()
	if got.Get("X-Custom") != "anything" {
		t.Fatalf("custom header lost: %v", got)
	}
	if got.Get("Authorization") != "" || got.Get("X-Api-Key") != "" {
		t.Fatalf("credential material appeared on non-credentialed grant")
	}
	// Body POST to the non-credentialed files grant on the same host —
	// allowed, untouched.
	res, _ = doCred(t, e, "tok-one", "POST", "https://api.anthropic.com/v1/files",
		map[string]string{"Content-Type": "application/octet-stream"}, []byte("arbitrary bytes \x00\x01"))
	if res.StatusCode != 200 {
		t.Fatalf("files POST status=%d reason=%q", res.StatusCode, denyReason(res))
	}
}
