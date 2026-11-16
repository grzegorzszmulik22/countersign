// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/countersign/countersign/internal/names"
	"github.com/countersign/countersign/internal/policy"
)

// vectorFile is the decision-table format of test/vectors/policy/matching.yaml.
type vectorFile struct {
	Policies map[string]string `yaml:"policies"`
	Rows     []struct {
		Name    string `yaml:"name"`
		Policy  string `yaml:"policy"`
		Request struct {
			Method  string `yaml:"method"`
			Scheme  string `yaml:"scheme"`
			Host    string `yaml:"host"`
			Port    int    `yaml:"port"`
			Path    string `yaml:"path"`
			Query   string `yaml:"query"`
			SNI     string `yaml:"sni"`
			Connect string `yaml:"connect"`
		} `yaml:"request"`
		Expected struct {
			Grant  *string `yaml:"grant"`
			Reason *string `yaml:"reason"`
		} `yaml:"expected"`
	} `yaml:"rows"`
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
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "test/vectors/policy/matching.yaml"))
	if err != nil {
		t.Fatalf("read matching.yaml: %v", err)
	}
	var vf vectorFile
	if err := yaml.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse matching.yaml: %v", err)
	}
	return &vf
}

// TestDecisionTable is C3.1.1 (MM3.1): every row of the decision table must
// produce the expected grant and reason.
func TestDecisionTable(t *testing.T) {
	vf := loadVectors(t)
	if len(vf.Rows) < 200 {
		t.Fatalf("decision table has %d rows, need >= 200", len(vf.Rows))
	}
	policies := make(map[string]*policy.SessionPolicy)
	seen := make(map[string]bool)
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
		req := &policy.Request{
			Method:  row.Request.Method,
			Scheme:  row.Request.Scheme,
			Host:    row.Request.Host,
			Port:    row.Request.Port,
			Path:    row.Request.Path,
			Query:   row.Request.Query,
			SNI:     row.Request.SNI,
			Connect: row.Request.Connect,
		}
		got := p.Match(req)
		wantGrant, wantReason := "", ""
		if row.Expected.Grant != nil {
			wantGrant = *row.Expected.Grant
		}
		if row.Expected.Reason != nil {
			wantReason = *row.Expected.Reason
		}
		if got.Grant != wantGrant || got.Reason != wantReason {
			t.Errorf("row %s: got {grant:%q reason:%q}, want {grant:%q reason:%q}",
				row.Name, got.Grant, got.Reason, wantGrant, wantReason)
		}
	}
}

// TestSchemaConformance checks every policy used by the decision table against
// the published JSON Schema in api/schema/.
func TestSchemaConformance(t *testing.T) {
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
