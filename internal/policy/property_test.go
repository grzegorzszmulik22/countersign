// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"os/exec"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/countersign/countersign/internal/names"
	"github.com/countersign/countersign/internal/policy"
)

// TestPropertyVsPython is C3.1.4: for random policies and requests the Go
// matcher must agree with the reference matcher in
// ref/python/refreconcile/match.py.
func TestPropertyVsPython(t *testing.T) {
	const n = 8000
	rng := rand.New(rand.NewSource(0xC505EED))
	type oneCase struct {
		Policy  any `json:"policy"`
		Request any `json:"request"`
	}
	var cases []oneCase
	var loaded []*policy.SessionPolicy
	var reqs []*policy.Request
	for i := 0; i < n; i++ {
		doc := genDoc(rng)
		raw, err := yaml.Marshal(doc)
		if err != nil {
			t.Fatalf("marshal generated policy: %v", err)
		}
		p, err := policy.Load(raw)
		if err != nil {
			t.Fatalf("generated policy rejected (generator bug): %v\n%s", err, raw)
		}
		req := genRequest(rng, doc)
		var specJSON any
		if err := json.Unmarshal(mustJSON(t, doc.Spec), &specJSON); err != nil {
			t.Fatalf("spec json: %v", err)
		}
		var reqJSON any
		if err := json.Unmarshal(mustJSON(t, req), &reqJSON); err != nil {
			t.Fatalf("request json: %v", err)
		}
		cases = append(cases, oneCase{Policy: specJSON, Request: reqJSON})
		loaded = append(loaded, p)
		reqs = append(reqs, req)
	}
	payload, err := json.Marshal(map[string]any{"cases": cases})
	if err != nil {
		t.Fatal(err)
	}
	python := filepath.Join(repoRoot(t), ".tools/bin/python3")
	if _, err := exec.LookPath(python); err != nil {
		python = "python3"
	}
	cmd := exec.Command(python, filepath.Join(repoRoot(t), "ref/python/refreconcile/match.py"))
	cmd.Stdin = bytes.NewReader(payload)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("reference matcher failed: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("run reference matcher: %v", err)
	}
	var results []struct {
		Grant  *string `json:"grant"`
		Reason *string `json:"reason"`
	}
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("reference output not JSON: %v\n%s", err, out)
	}
	if len(results) != n {
		t.Fatalf("reference returned %d results for %d cases", len(results), n)
	}
	for i := 0; i < n; i++ {
		got := loaded[i].Match(reqs[i])
		g, r := "", ""
		if results[i].Grant != nil {
			g = *results[i].Grant
		}
		if results[i].Reason != nil {
			r = *results[i].Reason
		}
		if got.Grant != g || got.Reason != r {
			t.Fatalf("case %d: go={%q %q} python={%q %q}\nrequest %+v", i, got.Grant, got.Reason, g, r, reqs[i])
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal %T: %v", v, err)
	}
	return b
}

// FuzzLoadPolicy is C3.1.5: the loader must never panic.
func FuzzLoadPolicy(f *testing.F) {
	seeds := []string{
		"apiVersion: " + names.APIGroup + "/v1alpha1\nkind: SessionPolicy\nmetadata: {name: x}\nspec: {mode: enforce, scenario: agent, grants: [{id: g, match: {hosts: [a.com]}}]}\n",
		"not yaml at all\x00\x01",
		"{{{",
		"apiVersion: " + names.APIGroup + "/v1alpha1\nkind: SessionPolicy\nmetadata: {name: x}\nspec:\n  grants:\n    - {id: a, action: deny, match: {hosts: ['*.x.com'], methods: [GET], paths: ['/**']}}\n",
		"\xff\xfe random \x00 bytes \xf0\x9f",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := policy.Load(data)
		if err != nil {
			return
		}
		// A policy that loads must also match without panicking.
		r := rand.New(rand.NewSource(int64(len(data))))
		for i := 0; i < 4; i++ {
			_ = p.Match(genRequest(r, nil))
		}
	})
}

var (
	hostPool = []string{
		"api.example.com", "example.com", "a.example.com", "a.b.example.com",
		"cdn.test", "sub.cdn.test", "deep.sub.cdn.test", "other.net",
		"203.0.113.7", "10.1.2.3", "xn--nxasmq6b.example",
	}
	pathPool = []string{
		"/", "/v1", "/v1/messages", "/v2/messages", "/repos/a/b",
		"/repos/acme/widgets", "/repos/acme/widgets-evil", "/admin/x",
		"/admin", "/data", "/data/file.txt", "/deep/a/b/c/d",
	}
	globPool = []string{
		"/**", "/", "/v1/**", "/v*/messages", "/repos/*/*",
		"/repos/acme/*", "/admin/**", "/data/*.txt", "/deep/**/d",
	}
	methodPool = []string{"GET", "POST", "PUT", "HEAD", "DELETE", "get", "post"}
)

func pick(r *rand.Rand, xs []string) string { return xs[r.Intn(len(xs))] }

func genDoc(r *rand.Rand) *policy.SessionPolicy {
	ng := 1 + r.Intn(5)
	doc := &policy.SessionPolicy{
		APIVersion: names.APIGroup + "/v1alpha1",
		Kind:       "SessionPolicy",
		Metadata:   policy.Metadata{Name: "gen"},
		Spec: policy.Spec{
			Mode:     "enforce",
			Scenario: "agent",
		},
	}
	for i := 0; i < ng; i++ {
		g := policy.Grant{ID: string(rune('a' + i))}
		if r.Intn(4) == 0 {
			g.Action = "deny"
		}
		m := &policy.Match{}
		switch r.Intn(10) {
		case 0:
			m.Hosts = []string{"*"}
		case 1, 2:
			m.Hosts = []string{"*." + pick(r, hostPool[:8])}
		default:
			m.Hosts = []string{pick(r, hostPool)}
			if r.Intn(4) == 0 {
				m.Hosts = append(m.Hosts, pick(r, hostPool))
			}
		}
		if r.Intn(5) == 0 {
			m.Scheme = "http"
		}
		if r.Intn(4) == 0 {
			m.Ports = []int{443, 8443}
		} else if r.Intn(8) == 0 {
			m.Ports = []int{8080}
		}
		if r.Intn(2) == 0 {
			ms := append([]string{}, methodPool[:3+r.Intn(3)]...)
			m.Methods = ms[:1+r.Intn(len(ms))]
		}
		if r.Intn(12) == 0 {
			m.Matcher = &policy.Matcher{GitSmartHTTP: &policy.GitSmartHTTP{
				Repos:  []string{"acme/widgets", "acme/gadgets"}[:1+r.Intn(2)],
				Access: []string{"read", "write"}[r.Intn(2)]}}
			m.Methods = nil
			m.Paths = nil
		} else if r.Intn(2) == 0 {
			n := 1 + r.Intn(2)
			for j := 0; j < n; j++ {
				m.Paths = append(m.Paths, pick(r, globPool))
			}
		}
		g.Match = m
		doc.Spec.Grants = append(doc.Spec.Grants, g)
	}
	return doc
}

func genRequest(r *rand.Rand, doc *policy.SessionPolicy) *policy.Request {
	req := &policy.Request{Scheme: "https"}
	if r.Intn(4) == 0 {
		req.Scheme = "http"
	}
	req.Method = pick(r, methodPool)
	// Half the time derive the host from a grant of the document so matches
	// actually happen; the rest comes from the pool with mutations.
	if doc != nil && len(doc.Spec.Grants) > 0 && r.Intn(2) == 0 {
		g := doc.Spec.Grants[r.Intn(len(doc.Spec.Grants))]
		if len(g.Match.Hosts) > 0 {
			h := g.Match.Hosts[r.Intn(len(g.Match.Hosts))]
			switch {
			case h == "*":
				req.Host = pick(r, hostPool)
			case len(h) > 2 && h[:2] == "*.":
				switch r.Intn(3) {
				case 0:
					req.Host = h[2:]
				case 1:
					req.Host = "x." + h[2:]
				default:
					req.Host = "a.b." + h[2:]
				}
			default:
				req.Host = h
				switch r.Intn(5) {
				case 0:
					req.Host = h + "."
				case 1:
					req.Host = "www." + h
				}
			}
		}
		if r.Intn(3) == 0 && len(g.Match.Paths) > 0 {
			glob := g.Match.Paths[r.Intn(len(g.Match.Paths))]
			req.Path = pathFromGlob(r, glob)
		}
		if g.Match.Matcher != nil && g.Match.Matcher.GitSmartHTTP != nil && r.Intn(3) > 0 {
			gitRequest(r, req, g.Match.Matcher.GitSmartHTTP)
		}
		if r.Intn(4) == 0 && len(g.Match.Ports) > 0 {
			req.Port = g.Match.Ports[r.Intn(len(g.Match.Ports))]
		}
		if r.Intn(4) == 0 && len(g.Match.Methods) > 0 {
			req.Method = g.Match.Methods[r.Intn(len(g.Match.Methods))]
		}
	}
	if req.Host == "" {
		req.Host = pick(r, hostPool)
		switch r.Intn(6) {
		case 0:
			req.Host = req.Host + "."
		case 1:
			req.Host = "x." + req.Host
		}
	}
	if r.Intn(12) == 0 {
		req.Host = "API.EXAMPLE.COM"
	}
	if req.Path == "" {
		req.Path = pick(r, pathPool)
	}
	switch r.Intn(14) {
	case 0:
		req.Path = ""
	case 1:
		req.Path += "/"
	case 2:
		req.Path = "/v1/mess%61ges"
	case 3:
		req.Path = "/a/../b"
	case 4:
		req.Path = "/a%2fb"
	case 5:
		req.Path = `/x\y`
	case 6:
		req.Path = "/x%2ey"
	}
	if r.Intn(8) == 0 {
		req.Query = "q=1&r=%2f"
	}
	if r.Intn(10) == 0 {
		req.Port = []int{80, 443, 8443, 8080}[r.Intn(4)]
	}
	if r.Intn(12) == 0 {
		req.SNI = pick(r, hostPool)
	}
	if r.Intn(14) == 0 {
		req.Connect = req.Host
	}
	if r.Intn(20) == 0 {
		req.Connect = "other.example.com"
	}
	return req
}

// gitRequest shapes req into something a git smart-HTTP client or an
// attacker imitating one might send: usually one of the four endpoint forms
// for a listed repo (maybe mutated out of scope).
func gitRequest(r *rand.Rand, req *policy.Request, git *policy.GitSmartHTTP) {
	repo := git.Repos[r.Intn(len(git.Repos))]
	switch r.Intn(9) {
	case 0:
		repo += "-evil"
	case 1:
		repo = "ACME/widgets"
	case 2:
		repo = "x/" + repo
	}
	dot := []string{"", ".git", ".gitx"}[r.Intn(3)]
	svc := []string{"git-upload-pack", "git-receive-pack", "git-dumb", "GIT-UPLOAD-PACK"}[r.Intn(4)]
	switch r.Intn(6) {
	case 0, 1, 2:
		req.Method = "GET"
		req.Path = "/" + repo + dot + "/info/refs"
		req.Query = "service=" + svc
	case 3:
		req.Method = "POST"
		req.Path = "/" + repo + dot + "/" + svc
	case 4:
		req.Method = []string{"GET", "PUT", "HEAD"}[r.Intn(3)]
		req.Path = "/" + repo + dot + "/info/refs"
		req.Query = "service=" + svc
	case 5:
		req.Method = "POST"
		req.Path = "/" + repo + dot + "/" + svc
		req.Query = []string{"", "service=" + svc, "x=1"}[r.Intn(3)]
	}
	if r.Intn(6) == 0 {
		req.Query = ""
	}
	if r.Intn(8) == 0 {
		req.Path += "/extra"
	}
}

// pathFromGlob instantiates a glob into a concrete path (sometimes mutated so
// it stops matching).
func pathFromGlob(r *rand.Rand, glob string) string {
	out := ""
	star := 0
	for _, c := range glob {
		if c == '*' {
			star++
			continue
		}
		out += string(c)
	}
	segs := []string{"", "x", "y/z", "deep/nest/x"}
	for ; star > 0; star-- {
		out += segs[r.Intn(len(segs))]
	}
	if out == "" {
		out = "/"
	}
	if r.Intn(6) == 0 {
		out += "/extra"
	}
	return out
}
