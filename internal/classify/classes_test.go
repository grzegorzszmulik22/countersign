// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package classify_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	yaml "gopkg.in/yaml.v3"

	"github.com/countersign/countersign/internal/classify"
	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/evidence/evtest"
	"github.com/countersign/countersign/internal/names"
	"github.com/countersign/countersign/internal/policy"
)

// vectorFile mirrors test/vectors/policy/classes.yaml.
type vectorFile struct {
	Policies map[string]string `yaml:"policies"`
	Rows     []struct {
		Name    string `yaml:"name"`
		Policy  string `yaml:"policy"`
		Grant   string `yaml:"grant"`
		Request struct {
			Method    string `yaml:"method"`
			Host      string `yaml:"host"`
			Port      int    `yaml:"port"`
			Path      string `yaml:"path"`
			Query     string `yaml:"query"`
			WebSocket bool   `yaml:"websocket"`
			Tunnel    bool   `yaml:"tunnel"`
			MCP       *struct {
				Method string `yaml:"method"`
				Tool   string `yaml:"tool"`
			} `yaml:"mcp"`
		} `yaml:"request"`
		Taint    []string `yaml:"taint"`
		C523     bool     `yaml:"c523"`
		Expected struct {
			Class        string `yaml:"class"`
			Requires     string `yaml:"requires"`
			DeclaredSafe bool   `yaml:"declared_safe"`
		} `yaml:"expected"`
	} `yaml:"rows"`
	Invalid []struct {
		Name   string `yaml:"name"`
		Field  string `yaml:"field"`
		Policy string `yaml:"policy"`
	} `yaml:"invalid"`
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	return root
}

func loadVectors(t *testing.T) *vectorFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "test/vectors/policy/classes.yaml"))
	if err != nil {
		t.Fatalf("read classes.yaml: %v", err)
	}
	var vf vectorFile
	if err := yaml.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse classes.yaml: %v", err)
	}
	return &vf
}

func findGrant(t *testing.T, p *policy.SessionPolicy, id string) *policy.Grant {
	t.Helper()
	for i := range p.Spec.Grants {
		if p.Spec.Grants[i].ID == id {
			return &p.Spec.Grants[i]
		}
	}
	t.Fatalf("grant %q not in policy", id)
	return nil
}

// TestClassesTable is the decision-table half of MM5.1/C5.2.1: every row of
// classes.yaml selects its grant and produces the expected class, condition
// and declared_safe flag.
func TestClassesTable(t *testing.T) {
	vf := loadVectors(t)
	if len(vf.Rows) < 250 {
		t.Fatalf("decision table has %d rows, need >= 250", len(vf.Rows))
	}
	policies := make(map[string]*policy.SessionPolicy)
	seen := make(map[string]bool)
	c523 := 0
	for _, row := range vf.Rows {
		if row.Name == "" {
			t.Fatal("row without name")
		}
		if seen[row.Name] {
			t.Fatalf("duplicate row name %q", row.Name)
		}
		seen[row.Name] = true
		p, ok := policies[row.Policy]
		if !ok {
			src, ok := vf.Policies[row.Policy]
			if !ok {
				t.Fatalf("row %s: unknown policy %q", row.Name, row.Policy)
			}
			var err error
			p, err = policy.Load([]byte(src))
			if err != nil {
				t.Fatalf("row %s: policy %q rejected: %v", row.Name, row.Policy, err)
			}
			policies[row.Policy] = p
		}
		// Grant selection (04 §2) must pick the named grant.
		mreq := &policy.Request{
			Method: row.Request.Method,
			Host:   row.Request.Host,
			Port:   row.Request.Port,
			Path:   row.Request.Path,
			Query:  row.Request.Query,
		}
		if res := p.Match(mreq); res.Grant != row.Grant || res.Reason != "" {
			t.Fatalf("row %s: grant selection = grant %q reason %q, want grant %q",
				row.Name, res.Grant, res.Reason, row.Grant)
		}
		g := findGrant(t, p, row.Grant)
		host := row.Request.Host
		if row.Request.Port != 0 {
			host += ":" + strconv.Itoa(row.Request.Port)
		}
		creq := &classify.Request{
			Method:    row.Request.Method,
			Host:      host,
			Path:      row.Request.Path,
			Query:     row.Request.Query,
			WebSocket: row.Request.WebSocket,
			Tunnel:    row.Request.Tunnel,
		}
		if row.Request.MCP != nil {
			creq.MCP = &classify.MCP{
				Method: row.Request.MCP.Method,
				Tool:   row.Request.MCP.Tool,
			}
		}
		got := classify.Classify(p, g, creq, row.Taint)
		if got.Class != row.Expected.Class {
			t.Errorf("row %s: class = %q, want %q", row.Name, got.Class, row.Expected.Class)
		}
		if got.Requires != row.Expected.Requires {
			t.Errorf("row %s: requires = %q, want %q", row.Name, got.Requires, row.Expected.Requires)
		}
		if got.DeclaredSafe != row.Expected.DeclaredSafe {
			t.Errorf("row %s: declared_safe = %v, want %v", row.Name, got.DeclaredSafe, row.Expected.DeclaredSafe)
		}
		if row.C523 {
			c523++
			// C5.2.3: the grant's requires is strictly looser than (or
			// absent under) a review/deny autonomy condition, and the
			// autonomy value must be the imposed condition.
			if got.Requires != row.Expected.Requires {
				continue
			}
			auto := p.Spec.Autonomy[got.Class]
			if auto == "" {
				auto = "allow"
			}
			if got.Requires != auto {
				t.Errorf("c523 row %s: requires %q != autonomy[%s] %q",
					row.Name, got.Requires, got.Class, auto)
			}
			strict := map[string]int{"allow": 0, "intent": 1, "review": 2, "deny": 3}
			if strict[g.Requires] >= strict[auto] {
				t.Errorf("c523 row %s: grant requires %q is not looser than autonomy %q",
					row.Name, g.Requires, auto)
			}
		}
	}
	if c523 < 20 {
		t.Fatalf("only %d rows assert C5.2.3 (requires looser than autonomy); need >= 20", c523)
	}
}

// TestInvalidClassPolicies asserts every invalid entry fails Load naming
// its declared field (C5.2.2).
func TestInvalidClassPolicies(t *testing.T) {
	vf := loadVectors(t)
	for _, ent := range vf.Invalid {
		_, err := policy.Load([]byte(ent.Policy))
		if err == nil {
			t.Errorf("%s: invalid policy accepted", ent.Name)
			continue
		}
		if !strings.Contains(err.Error(), ent.Field) {
			t.Errorf("%s: error %q does not name field %q", ent.Name, err.Error(), ent.Field)
		}
	}
}

// TestClassesSchemaConformance validates every classes.yaml policy against
// the published SessionPolicy JSON Schema.
func TestClassesSchemaConformance(t *testing.T) {
	vf := loadVectors(t)
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "api/schema/sessionpolicy.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	c := jsonschema.NewCompiler()
	const schemaURL = "https://" + names.APIGroup + "/schema/sessionpolicy.v1alpha1.schema.json"
	if err := c.AddResource(schemaURL, doc); err != nil {
		t.Fatalf("add schema: %v", err)
	}
	sch, err := c.Compile(schemaURL)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	for name, src := range vf.Policies {
		var ydoc any
		if err := yaml.Unmarshal([]byte(src), &ydoc); err != nil {
			t.Fatalf("policy %s: yaml: %v", name, err)
		}
		if err := sch.Validate(ydoc); err != nil {
			t.Errorf("policy %s fails api/schema/sessionpolicy.schema.json: %v", name, err)
		}
	}
}

// recordSchema compiles api/schema/records/<type>.json with _common.json.
func recordSchema(t *testing.T, typeName string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	base := "https://" + names.APIGroup + "/schema/records/"
	common, err := os.ReadFile(filepath.Join(repoRoot(t), "api/schema/records/_common.json"))
	if err != nil {
		t.Fatalf("read _common.json: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(common))
	if err != nil {
		t.Fatalf("parse _common.json: %v", err)
	}
	if err := c.AddResource(base+"_common.json", doc); err != nil {
		t.Fatalf("add _common.json: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "api/schema/records", typeName+".json"))
	if err != nil {
		t.Fatalf("read %s schema: %v", typeName, err)
	}
	rdoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse %s schema: %v", typeName, err)
	}
	if err := c.AddResource(base+typeName+".json", rdoc); err != nil {
		t.Fatalf("add %s: %v", typeName, err)
	}
	sch, err := c.Compile(base + typeName + ".json")
	if err != nil {
		t.Fatalf("compile %s: %v", typeName, err)
	}
	return sch
}

// TestDeclaredSafeRecordSurvival is C5.2.4 at the classifier level: the
// declared_safe flag and the imposed condition have a committed place on the
// shared decision block of every effect record, survive the strict record
// codec, and validate against the published record schemas.
func TestDeclaredSafeRecordSurvival(t *testing.T) {
	vf := loadVectors(t)
	p, err := policy.Load([]byte(vf.Policies["base"]))
	if err != nil {
		t.Fatal(err)
	}
	// decl-safe is the explicit class:safe grant; a POST through it is a
	// flagged declared_safe.
	g := findGrant(t, p, "decl-safe")
	got := classify.Classify(p, g, &classify.Request{
		Method: "POST", Host: "d.test", Path: "/s/x",
	}, nil)
	if got.Class != "safe" || !got.DeclaredSafe {
		t.Fatalf("classifier gave %+v, want safe+declared_safe", got)
	}

	for _, typeName := range []string{"effect.http", "effect.tunnel"} {
		sch := recordSchema(t, typeName)
		body, err := evtest.Sample(typeName)
		if err != nil {
			t.Fatalf("sample %s: %v", typeName, err)
		}
		var dec *evidence.Decision
		switch b := body.(type) {
		case *evidence.EffectHTTPBody:
			b.Class = got.Class
			dec = &b.Decision
		case *evidence.EffectTunnelBody:
			dec = &b.Decision
		default:
			t.Fatalf("unexpected body type %T", body)
		}
		dec.Action = "allow"
		dec.Requires = got.Requires
		dec.DeclaredSafe = got.DeclaredSafe

		rec := &evidence.Record{
			V:       1,
			Type:    typeName,
			ID:      "01K7D7JQ9Y8T4X2Z6B4H4F4F4F",
			Session: "01K7D7JQ9Y8T4X2Z6B4H4F4F4G",
			Emitter: "broker/01K7D7JQ9Y8T4X2Z6B4H4F4F4H",
			Eseq:    0,
			Eprev:   "0000000000000000000000000000000000000000000000000000000000000000",
			TS:      "2026-11-14T00:00:00.000000000Z",
			Body:    body,
		}
		pred, err := evidence.MarshalPredicate(rec)
		if err != nil {
			t.Fatalf("%s: marshal: %v", typeName, err)
		}
		var v any
		if err := json.Unmarshal(pred, &v); err != nil {
			t.Fatalf("%s: predicate is not JSON: %v", typeName, err)
		}
		if err := sch.Validate(v); err != nil {
			t.Fatalf("%s: record with declared_safe fails schema: %v", typeName, err)
		}
		back, err := evidence.UnmarshalPredicate(pred)
		if err != nil {
			t.Fatalf("%s: strict decode: %v", typeName, err)
		}
		var dec2 evidence.Decision
		var cls2 string
		switch b := back.Body.(type) {
		case *evidence.EffectHTTPBody:
			dec2, cls2 = b.Decision, b.Class
		case *evidence.EffectTunnelBody:
			dec2 = b.Decision
		}
		if !dec2.DeclaredSafe || dec2.Requires != got.Requires {
			t.Errorf("%s: decision lost declared_safe/requires: %+v", typeName, dec2)
		}
		if typeName == "effect.http" && cls2 != got.Class {
			t.Errorf("class lost: %q", cls2)
		}
		// The field is required on the record: a decision without it must
		// fail the published schema.
		var m map[string]any
		if err := json.Unmarshal(pred, &m); err != nil {
			t.Fatal(err)
		}
		delete(m["body"].(map[string]any)["decision"].(map[string]any), "declared_safe")
		stripped, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var sv any
		if err := json.Unmarshal(stripped, &sv); err != nil {
			t.Fatal(err)
		}
		if err := sch.Validate(sv); err == nil {
			t.Errorf("%s: schema accepts a decision without declared_safe", typeName)
		}
	}
}

// TestNoRuleIrreversible is the classifier-level half of C5.2.2: a request
// matching no classification rule is irreversible.
func TestNoRuleIrreversible(t *testing.T) {
	vf := loadVectors(t)
	p, err := policy.Load([]byte(vf.Policies["base"]))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, host, path string }{
		{"POST", "api.test", "/x"},
		{"DELETE", "api.test", "/x"},
		{"PUT", "api.test", "/a/b/c"},
		{"PATCH", "api.test", "/"},
		{"TRACE", "api.test", "/t"},
	} {
		g := findGrant(t, p, "api")
		got := classify.Classify(p, g, &classify.Request{
			Method: tc.method, Host: tc.host, Path: tc.path,
		}, nil)
		if got.Class != "irreversible" {
			t.Errorf("%s %s: class = %q, want irreversible", tc.method, tc.path, got.Class)
		}
		if got.DeclaredSafe {
			t.Errorf("%s %s: declared_safe set on undeclared grant", tc.method, tc.path)
		}
	}
}
