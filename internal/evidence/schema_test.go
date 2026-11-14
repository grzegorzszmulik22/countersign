// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package evidence_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/evidence/evtest"
	"github.com/countersign/countersign/internal/names"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const schemaDir = "../../api/schema"

// loadSchemas compiles every per-record schema under api/schema/records with
// the shared definitions file, and returns name → compiled schema.
func loadSchemas(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	common, err := os.ReadFile(filepath.Join(schemaDir, "records", "_common.json"))
	if err != nil {
		t.Fatalf("read _common.json: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(common)))
	if err != nil {
		t.Fatalf("parse _common.json: %v", err)
	}
	// Record schemas carry an absolute $id; "_common.json" refs resolve to a
	// sibling of that $id, so the common file is registered under its own $id.
	if err := c.AddResource("https://"+names.APIGroup+"/schema/records/_common.json", doc); err != nil {
		t.Fatalf("add _common.json: %v", err)
	}
	out := map[string]*jsonschema.Schema{}
	entries, err := os.ReadDir(filepath.Join(schemaDir, "records"))
	if err != nil {
		t.Fatalf("read schema dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, "_") || !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(schemaDir, "records", name))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		if err := c.AddResource(name, doc); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
		sch, err := c.Compile(name)
		if err != nil {
			t.Fatalf("compile %s: %v", name, err)
		}
		out[strings.TrimSuffix(name, ".json")] = sch
	}
	return out
}

// C1.1.4 Every Go record type validates against its JSON Schema and every
// schema has a Go type (bijection).
func TestC114_SchemaBijection(t *testing.T) {
	schemas := loadSchemas(t)
	types := evidence.Types()

	var schemaNames []string
	for n := range schemas {
		schemaNames = append(schemaNames, n)
	}
	sort.Strings(schemaNames)
	sort.Strings(types)
	if strings.Join(schemaNames, ",") != strings.Join(types, ",") {
		t.Fatalf("schema/type mismatch:\n schemas: %v\n types:   %v", schemaNames, types)
	}

	for _, tn := range types {
		r := testRecord(t, tn)
		pred, err := evidence.MarshalPredicate(r)
		if err != nil {
			t.Fatalf("%s: marshal predicate: %v", tn, err)
		}
		var v any
		if err := json.Unmarshal(pred, &v); err != nil {
			t.Fatalf("%s: unmarshal: %v", tn, err)
		}
		if err := schemas[tn].Validate(v); err != nil {
			t.Fatalf("%s: valid record rejected by schema: %v", tn, err)
		}
	}
}

// The schemas must also have teeth: removing a required field, adding an
// unknown one, or violating an enum/const must fail validation.
func TestC114_SchemaTeeth(t *testing.T) {
	schemas := loadSchemas(t)

	valid := func(t *testing.T, tn string) map[string]any {
		r := testRecord(t, tn)
		pred, err := evidence.MarshalPredicate(r)
		if err != nil {
			t.Fatal(err)
		}
		var v map[string]any
		if err := json.Unmarshal(pred, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	t.Run("missing required field", func(t *testing.T) {
		v := valid(t, "effect.denied")
		delete(v, "eseq")
		if err := schemas["effect.denied"].Validate(v); err == nil {
			t.Fatal("schema accepted record missing eseq")
		}
	})
	t.Run("unknown predicate field", func(t *testing.T) {
		v := valid(t, "effect.denied")
		v["zzz"] = 1
		if err := schemas["effect.denied"].Validate(v); err == nil {
			t.Fatal("schema accepted unknown predicate field")
		}
	})
	t.Run("unknown body field", func(t *testing.T) {
		v := valid(t, "effect.denied")
		v["body"].(map[string]any)["zzz"] = 1
		if err := schemas["effect.denied"].Validate(v); err == nil {
			t.Fatal("schema accepted unknown body field")
		}
	})
	t.Run("missing required body field", func(t *testing.T) {
		v := valid(t, "effect.denied")
		delete(v["body"].(map[string]any), "reason")
		if err := schemas["effect.denied"].Validate(v); err == nil {
			t.Fatal("schema accepted body missing reason")
		}
	})
	t.Run("enum violation", func(t *testing.T) {
		v := valid(t, "effect.http")
		v["body"].(map[string]any)["actor"] = "nobody"
		if err := schemas["effect.http"].Validate(v); err == nil {
			t.Fatal("schema accepted bad enum value")
		}
	})
	t.Run("const violation", func(t *testing.T) {
		v := valid(t, "effect.denied")
		v["v"] = 2
		if err := schemas["effect.denied"].Validate(v); err == nil {
			t.Fatal("schema accepted v=2")
		}
	})
	t.Run("pattern violation", func(t *testing.T) {
		v := valid(t, "effect.denied")
		v["id"] = "not-a-ulid"
		if err := schemas["effect.denied"].Validate(v); err == nil {
			t.Fatal("schema accepted malformed ULID")
		}
	})
}

// evtest.Sample must produce schema-valid bodies for every type — this is what
// C1.1.4 iterates, and golden bundles in M1.4 build on it.
func TestC114_SampleCoverage(t *testing.T) {
	for _, tn := range evidence.Types() {
		if _, err := evtest.Sample(tn); err != nil {
			t.Fatalf("no sample for %s: %v", tn, err)
		}
	}
}
