// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package creds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// --- store ------------------------------------------------------------

func TestFileStoreGet(t *testing.T) {
	s, err := ParseFile([]byte(`secrets:
  anthropic:
    api-key: CANARY_ANTHROPIC0123456789ABCDEFGHI
  github-token:
    value: CANARY_GITHUB0123456789ABCDEFGHIJKL
`))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	got, err := s.Get(Ref{Secret: "anthropic", Key: "api-key"})
	if err != nil || got != "CANARY_ANTHROPIC0123456789ABCDEFGHI" {
		t.Fatalf("Get: %q %v", got, err)
	}
	if _, err := s.Get(Ref{Secret: "anthropic", Key: "other"}); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("missing key: %v", err)
	}
	if _, err := s.Get(Ref{Secret: "nope", Key: "k"}); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("missing secret: %v", err)
	}
	if s.Has(Ref{Secret: "anthropic", Key: "other"}) {
		t.Fatal("Has true for absent ref")
	}
}

func TestFileStoreStrict(t *testing.T) {
	for _, bad := range []string{
		"secrets: {a: {k: \"\"}}\n",          // empty value
		"secrets: {\"\": {k: v}}\n",          // empty name
		"other: {a: 1}\n",                    // unknown top-level key
		"secrets: [1,2]\n",                   // wrong shape
	} {
		if _, err := ParseFile([]byte(bad)); err == nil {
			t.Fatalf("ParseFile accepted %q", bad)
		}
	}
}

// memSecrets is the in-memory SecretSource KubeStore tests run against —
// the interface is complete; the real client wires in M4.
type memSecrets map[string]map[string][]byte

func (m memSecrets) GetSecret(_ context.Context, namespace, name string) (map[string][]byte, error) {
	if namespace != "cs" {
		return nil, fmt.Errorf("wrong namespace %q", namespace)
	}
	if d, ok := m[name]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("secret %q not found", name)
}

func TestKubeStoreIface(t *testing.T) {
	src := memSecrets{
		"anthropic": {"api-key": []byte("CANARY_KUBE0123456789ABCDEFGHIJK")},
	}
	s := NewKubeStore("cs", src)
	got, err := s.Get(Ref{Secret: "anthropic", Key: "api-key"})
	if err != nil || got != "CANARY_KUBE0123456789ABCDEFGHIJK" {
		t.Fatalf("kube Get: %q %v", got, err)
	}
	if _, err := s.Get(Ref{Secret: "anthropic", Key: "nope"}); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("kube missing key: %v", err)
	}
	if _, err := s.Get(Ref{Secret: "ghost", Key: "k"}); err == nil || errors.Is(err, ErrNoSecret) {
		t.Fatalf("kube missing secret must surface the fetch error, got %v", err)
	}
}

// --- placeholders -----------------------------------------------------

func TestPlaceholderShape(t *testing.T) {
	for _, tc := range []struct{ sess, grant string }{
		{"s1", "anthropic"},
		{"s1", "github-token_v2"},
		{"session-2", "pypi"},
	} {
		p := NewPlaceholder(tc.sess, tc.grant)
		want := "csph_" + SessionTag(tc.sess) + "_" + tc.grant + "_"
		if !strings.HasPrefix(p, want) {
			t.Fatalf("placeholder %q missing %q", p, want)
		}
		if len(p) != len(want)+22 {
			t.Fatalf("placeholder %q length %d", p, len(p))
		}
		if !IsPlaceholder(p) {
			t.Fatalf("IsPlaceholder rejected %q", p)
		}
	}
	// Two placeholders for the same (session, grant) differ; different
	// sessions share only the prefix shape.
	a, b := NewPlaceholder("s1", "g"), NewPlaceholder("s1", "g")
	if a == b {
		t.Fatal("identical placeholders")
	}
	if NewPlaceholder("s1", "g") == NewPlaceholder("s2", "g") {
		t.Fatal("identical placeholders across sessions")
	}
	// Rejects: other prefixes, short random parts, no tag.
	for _, bad := range []string{
		"", "csph_", "csph_zzzzzzzz_grant_0123456789abcdefghijklmnopqrstuv",
		"csph_0123abcd_short_0123456789abcdefghijklmnopqrstuv",
		"csph_0123abcd_grant_0123456789abcdefghij",       // 20 < 22
		"csph_0123abcd_grant_0123456789abcdefghijklmnop", // 26 > 22
		"csph_0123abcd_grant_0123456789abcdefghij!m",     // bad char
	} {
		if IsPlaceholder(bad) {
			t.Fatalf("IsPlaceholder accepted %q", bad)
		}
	}
	// The value never contains the secret: placeholders are generated
	// without any secret input — assert against a canary shape anyway.
	if strings.Contains(NewPlaceholder("s1", "g"), "CANARY_") {
		t.Fatal("placeholder carries secret material")
	}
}

// --- inject -----------------------------------------------------------

func TestInjectHeader(t *testing.T) {
	spec := HeaderSpec("x-api-key", "{secret}", "csph_0123abcd_g_0123456789abcdefghij", "REALSECRET")
	h := http.Header{}
	// Absent -> add.
	v, ok, _ := spec.Eval(h)
	if !ok || v != InjectAbsent {
		t.Fatal("absent not InjectAbsent")
	}
	spec.Apply(h)
	if h.Get("X-Api-Key") != "REALSECRET" {
		t.Fatalf("apply wrote %q", h.Get("X-Api-Key"))
	}
	// Exact placeholder -> replace.
	h2 := http.Header{}
	h2.Set("X-Api-Key", "csph_0123abcd_g_0123456789abcdefghij")
	v, ok, _ = spec.Eval(h2)
	if !ok || v != InjectReplaced {
		t.Fatal("placeholder not InjectReplaced")
	}
	spec.Apply(h2)
	if h2.Get("x-api-key") != "REALSECRET" {
		t.Fatal("apply did not replace")
	}
	// Format with a prefix.
	spec2 := HeaderSpec("authorization", "Bearer {secret}", "PH", "REAL")
	h3 := http.Header{}
	spec2.Apply(h3)
	if h3.Get("Authorization") != "Bearer REAL" {
		t.Fatalf("format apply wrote %q", h3.Get("Authorization"))
	}
	h3.Set("Authorization", "Bearer PH")
	if _, ok, _ := spec2.Eval(h3); !ok {
		t.Fatal("formatted placeholder rejected")
	}
	// Foreign material -> not ok, no placeholder marker.
	h4 := http.Header{}
	h4.Set("x-api-key", "someone-else")
	if _, ok, ph := spec.Eval(h4); ok || ph {
		t.Fatal("foreign value not classified FOREIGN")
	}
	// Wrong placeholder -> misuse.
	h5 := http.Header{}
	h5.Set("x-api-key", "csph_deadbeef_other_0123456789abcdefghij")
	if _, ok, ph := spec.Eval(h5); ok || !ph {
		t.Fatal("foreign placeholder not classified MISUSE")
	}
}

func TestInjectBasic(t *testing.T) {
	ph := "csph_0123abcd_gh_0123456789abcdefghij"
	spec := BasicSpec("x-access-token", ph, "REALSECRET")
	h := http.Header{}
	spec.Apply(h)
	want := "Basic " + b64std("x-access-token:REALSECRET")
	if h.Get("Authorization") != want {
		t.Fatalf("basic apply wrote %q", h.Get("Authorization"))
	}
	h.Set("Authorization", "Basic "+b64std("x-access-token:"+ph))
	if v, ok, _ := spec.Eval(h); !ok || v != InjectReplaced {
		t.Fatal("basic placeholder not InjectReplaced")
	}
	// Placeholder in the USERNAME position -> misuse even though decoded.
	h.Set("Authorization", "Basic "+b64std(ph+":anything"))
	if _, ok, sawPH := spec.Eval(h); ok || !sawPH {
		t.Fatal("placeholder-in-username not classified MISUSE")
	}
	// Wrong password that is not a placeholder -> foreign.
	h.Set("Authorization", "Basic "+b64std("x-access-token:wrong"))
	if _, ok, sawPH := spec.Eval(h); ok || sawPH {
		t.Fatal("wrong basic password not classified FOREIGN")
	}
	// A Bearer value where a Basic credential is expected -> foreign.
	h.Set("Authorization", "Bearer "+ph)
	if _, ok, sawPH := spec.Eval(h); ok || !sawPH {
		t.Fatal("placeholder-shaped bearer in basic slot not MISUSE")
	}
}

func b64std(s string) string {
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	for i := 0; i < len(s); i += 3 {
		var b [3]byte
		n := copy(b[:], s[i:])
		v := uint(b[0])<<16 | uint(b[1])<<8 | uint(b[2])
		out.WriteByte(table[(v>>18)&63])
		out.WriteByte(table[(v>>12)&63])
		if n > 1 {
			out.WriteByte(table[(v>>6)&63])
		} else {
			out.WriteByte('=')
		}
		if n > 2 {
			out.WriteByte(table[v&63])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}

// --- detector ---------------------------------------------------------

func vectorPath() string {
	_, src, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(src), "..", "..", "test", "vectors", "credshapes.json")
}

func TestCredshapesVectors(t *testing.T) {
	data, err := os.ReadFile(vectorPath())
	if err != nil {
		t.Fatalf("vectors: %v", err)
	}
	var set struct {
		Positive []string `json:"positive"`
		Negative []string `json:"negative"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		t.Fatalf("vectors decode: %v", err)
	}
	if len(set.Positive) < 20 || len(set.Negative) < 20 {
		t.Fatalf("vector counts %d/%d", len(set.Positive), len(set.Negative))
	}
	miss := 0
	for _, s := range set.Positive {
		if got := Detect([]byte(s)); len(got) == 0 {
			miss++
			t.Errorf("positive not detected: %q", s)
		}
	}
	for _, s := range set.Negative {
		if got := Detect([]byte(s)); len(got) != 0 {
			t.Errorf("negative detected %v: %q", got, s)
		}
	}
	if miss != 0 {
		t.Fatalf("%d/%d positives undetected", miss, len(set.Positive))
	}
}

func TestDetectRedact(t *testing.T) {
	in := []byte("note: ghp_abcdefghijklmnopqrstuvwxyz0123456789AB and sk-ant-0123456789abcdefghijklmnopqrstuvwxyz")
	if names := Detect(in); len(names) == 0 {
		t.Fatal("Detect found nothing")
	}
	out := Redact(in)
	if strings.Contains(string(out), "ghp_") || strings.Contains(string(out), "sk-ant-") {
		t.Fatalf("Redact left material: %s", out)
	}
	if Detect(out) != nil {
		t.Fatal("Redact output still detects")
	}
	if !strings.Contains(string(out), "[credential-redacted]") {
		t.Fatalf("Redact output missing marker: %s", out)
	}
}
