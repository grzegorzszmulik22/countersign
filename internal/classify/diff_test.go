// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package classify_test

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	yaml "gopkg.in/yaml.v3"

	"github.com/countersign/countersign/internal/classify"
	"github.com/countersign/countersign/internal/names"
	"github.com/countersign/countersign/internal/policy"
)

// genDoc builds a random SessionPolicy valid under the M5.2 rules (05 §2:
// no intent; staged needs a stager; tools/calls need inspect:mcp; no stager
// on passthrough).
func genDoc(r *rand.Rand) *policy.SessionPolicy {
	doc := &policy.SessionPolicy{
		APIVersion: names.APIGroup + "/v1alpha1",
		Kind:       "SessionPolicy",
		Metadata:   policy.Metadata{Name: "gen"},
		Spec:       policy.Spec{Mode: "enforce", Scenario: "agent"},
	}
	conds := []string{"allow", "review", "deny"}
	if r.Intn(3) > 0 {
		doc.Spec.Autonomy = map[string]string{}
		for _, c := range []string{"control", "safe", "staged", "compensable", "irreversible"} {
			if r.Intn(2) == 0 {
				doc.Spec.Autonomy[c] = conds[r.Intn(3)]
			}
		}
	}
	ng := 1 + r.Intn(6)
	for i := 0; i < ng; i++ {
		g := policy.Grant{ID: "g" + strconv.Itoa(i)}
		m := &policy.Match{}
		m.Hosts = []string{[]string{
			"api.test", "code.test", "chat.test", "countersign.internal",
			"mcp.test", "x.test", "*.wild.test",
		}[r.Intn(7)]}
		git := false
		passthrough := r.Intn(8) == 0
		if !passthrough && r.Intn(4) == 0 {
			m.Matcher = &policy.Matcher{GitSmartHTTP: &policy.GitSmartHTTP{
				Repos:  []string{"acme/widgets"},
				Access: []string{"read", "write"}[r.Intn(2)],
			}}
			git = true
		}
		if !git && !passthrough && r.Intn(2) == 0 {
			m.Methods = [][]string{
				{"GET", "HEAD"}, {"GET"}, {"POST", "PUT"},
				{"GET", "POST", "DELETE", "PATCH"},
			}[r.Intn(4)]
		}
		if !git && !passthrough && r.Intn(3) == 0 {
			m.Paths = []string{"/a/**"}
		}
		g.Match = m
		if passthrough {
			g.Mode = "passthrough"
		} else {
			switch r.Intn(5) {
			case 0:
				g.Inspect = "inference"
			case 1:
				g.Inspect = "mcp"
			}
			if r.Intn(3) == 0 {
				switch r.Intn(2) {
				case 0:
					g.Stager = &policy.Stager{Git: &policy.GitStager{Refs: []string{"refs/heads/a/*"}}}
				case 1:
					g.Stager = &policy.Stager{Outbox: &policy.OutboxStager{
						Respond: &policy.OutboxRespond{
							Status: 200, ContentType: "application/json", Body: "{}"},
						IDMap: &policy.OutboxIDMap{Provisional: "/id", Real: "/id"},
					}}
				}
			}
			if r.Intn(4) == 0 {
				c := &policy.Compensate{}
				if r.Intn(2) == 0 {
					c.Restore = &policy.CompensateRule{Methods: []string{"PUT", "PATCH"}}
				} else {
					c.DeleteCreated = &policy.DeleteCreated{
						Methods: []string{"POST"}, From: "location"}
				}
				g.Compensate = c
			}
			if g.Inspect == "mcp" {
				if r.Intn(3) == 0 {
					g.Calls = "serialized"
				}
				if r.Intn(2) == 0 {
					g.Tools = map[string]string{
						"a": []string{"safe", "compensable", "irreversible", "control"}[r.Intn(4)],
						"b": []string{"safe", "compensable", "irreversible", "control"}[r.Intn(4)],
					}
				}
			}
		}
		if r.Intn(4) == 0 {
			cls := []string{"safe", "compensable", "irreversible", "control"}[r.Intn(4)]
			if g.Stager != nil && r.Intn(3) == 0 {
				cls = "staged"
			}
			g.Class = cls
		}
		if r.Intn(3) == 0 {
			g.Requires = conds[r.Intn(3)]
		}
		if r.Intn(4) == 0 {
			w := &policy.WhenTainted{Labels: map[string]string{}}
			if r.Intn(2) == 0 {
				w.Default = conds[r.Intn(3)]
			}
			for _, l := range []string{"web", "packages", "other"} {
				if r.Intn(2) == 0 {
					w.Labels[l] = conds[r.Intn(3)]
				}
			}
			g.WhenTainted = w
		}
		doc.Spec.Grants = append(doc.Spec.Grants, g)
	}
	return doc
}

// genReq builds a random request leaning on git, MCP, tunnel and websocket
// shapes plus ordinary API traffic.
func genReq(r *rand.Rand, doc *policy.SessionPolicy) *classify.Request {
	paths := []string{
		"/", "/v1/x", "/a/b", "/api/search", "/acme/widgets/info/refs",
		"/acme/widgets/git-upload-pack", "/acme/widgets/git-receive-pack",
		"/acme/widgets.git/git-upload-pack", "/acme/other/git-receive-pack",
		"/x/info/refs", "/o/r/git-receive-pack",
	}
	queries := []string{"", "service=git-upload-pack", "service=git-receive-pack", "x=1"}
	methods := []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH", "TRACE", "FOO"}
	hosts := []string{
		"api.test", "code.test", "chat.test", "countersign.internal",
		"countersign.internal:8443", "mcp.test", "x.test", "sub.wild.test", "other.test",
	}
	req := &classify.Request{
		Method:    methods[r.Intn(len(methods))],
		Host:      hosts[r.Intn(len(hosts))],
		Path:      paths[r.Intn(len(paths))],
		Query:     queries[r.Intn(len(queries))],
		WebSocket: r.Intn(6) == 0,
		Tunnel:    r.Intn(6) == 0,
	}
	switch r.Intn(5) {
	case 0, 1:
		req.MCP = &classify.MCP{Method: "tools/call",
			Tool: []string{"a", "b", "c", "search", ""}[r.Intn(5)]}
	case 2:
		req.MCP = &classify.MCP{Method: []string{"tools/list", "notifications/x", "initialize", "ping"}[r.Intn(4)]}
	}
	return req
}

func genTaint(r *rand.Rand) []string {
	labels := []string{"web", "packages", "other", "x"}
	var out []string
	for _, l := range labels {
		if r.Intn(3) == 0 {
			out = append(out, l)
		}
	}
	return out
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal %T: %v", v, err)
	}
	return b
}

// TestDifferentialVsRefclassify is the 10,000-input half of MM5.1/C5.2.1:
// the Go classifier and ref/python/refclassify must agree on class,
// requires and declared_safe for every random case.
func TestDifferentialVsRefclassify(t *testing.T) {
	const n = 10000
	rng := rand.New(rand.NewSource(0xC1A551F1))
	type oneCase struct {
		Policy  any               `json:"policy"`
		Grant   string            `json:"grant"`
		Request *classify.Request `json:"request"`
		Taint   []string          `json:"taint"`
	}
	cases := make([]oneCase, 0, n)
	type bound struct {
		p     *policy.SessionPolicy
		g     *policy.Grant
		req   *classify.Request
		taint []string
	}
	bounds := make([]bound, 0, n)
	for len(bounds) < n {
		doc := genDoc(rng)
		raw, err := yaml.Marshal(doc)
		if err != nil {
			t.Fatalf("marshal doc: %v", err)
		}
		p, err := policy.Load(raw)
		if err != nil {
			t.Fatalf("generated policy rejected (generator bug): %v\n%s", err, raw)
		}
		gi := rng.Intn(len(p.Spec.Grants))
		var specJSON any
		if err := json.Unmarshal(mustJSON(t, doc.Spec), &specJSON); err != nil {
			t.Fatalf("spec json: %v", err)
		}
		req := genReq(rng, doc)
		taint := genTaint(rng)
		g := &p.Spec.Grants[gi]
		cases = append(cases, oneCase{
			Policy: specJSON, Grant: g.ID, Request: req, Taint: taint})
		bounds = append(bounds, bound{p, g, req, taint})
	}
	payload, err := json.Marshal(map[string]any{"cases": cases})
	if err != nil {
		t.Fatal(err)
	}
	// Pinned toolchain only (06 §11): never the host's python.
	python := filepath.Join(repoRoot(t), ".tools/bin/python3")
	if _, err := exec.LookPath(python); err != nil {
		t.Fatalf("missing pinned python at .tools/bin/python3: run make tools")
	}
	cmd := exec.Command(python, filepath.Join(repoRoot(t), "ref/python/refclassify/classify.py"))
	cmd.Stdin = bytes.NewReader(payload)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("refclassify failed: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("run refclassify: %v", err)
	}
	var results []struct {
		Class        string `json:"class"`
		Requires     string `json:"requires"`
		DeclaredSafe bool   `json:"declared_safe"`
	}
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("refclassify output not JSON: %v\n%s", err, out)
	}
	if len(results) != n {
		t.Fatalf("refclassify returned %d results for %d cases", len(results), n)
	}
	for i, b := range bounds {
		want := results[i]
		got := classify.Classify(b.p, b.g, b.req, b.taint)
		if got.Class != want.Class || got.Requires != want.Requires ||
			got.DeclaredSafe != want.DeclaredSafe {
			specJSON, _ := json.Marshal(b.p.Spec)
			reqJSON, _ := json.Marshal(b.req)
			t.Fatalf("case %d: go={%q %q %v} python={%q %q %v}\ngrant %s\nspec %s\nreq %s",
				i, got.Class, got.Requires, got.DeclaredSafe,
				want.Class, want.Requires, want.DeclaredSafe,
				b.g.ID, specJSON, reqJSON)
		}
	}
}
