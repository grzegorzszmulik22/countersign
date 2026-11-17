// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// schemagen generates api/schema/records/<type>.json for every record type
// registered in internal/evidence, from the Go field tags. Run:
//
//	go run ./tools/schemagen <outdir>
//
// The generated files are committed; check-M1.1 regenerates and diffs them.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/names"
)

// omap is an insertion-ordered JSON object for deterministic output.
type omap struct {
	keys []string
	vals map[string]any
}

func newOmap() *omap { return &omap{vals: map[string]any{}} }

func (o *omap) set(k string, v any) *omap {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
	return o
}

func (o *omap) MarshalJSON() ([]byte, error) {
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, err := json.Marshal(o.vals[k])
		if err != nil {
			return nil, err
		}
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	b.WriteByte('}')
	return []byte(b.String()), nil
}

var rawMessageType = reflect.TypeOf(json.RawMessage{})

func ref(def string) *omap {
	return newOmap().set("$ref", "_common.json#/$defs/"+def)
}

// fieldSchema produces the schema for one Go field. nullable reports whether
// the field may carry JSON null (pointer types and nullable-tagged maps).
func fieldSchema(t reflect.Type, tag string, nullable bool) (*omap, bool) {
	if t == rawMessageType {
		// Free-form but still a single JSON value (strict-scanned on decode).
		return newOmap(), nullable
	}
	if t.Kind() == reflect.Pointer {
		inner, _ := fieldSchema(t.Elem(), tag, false)
		return wrapNullable(inner), true
	}
	var s *omap
	isNullable := nullable
	switch t.Kind() {
	case reflect.String:
		s = stringSchema(tag)
	case reflect.Bool:
		s = newOmap().set("type", "boolean")
	case reflect.Int64, reflect.Int, reflect.Int32:
		s = newOmap().set("type", "integer")
		if tag == "port" {
			s.set("minimum", 0).set("maximum", 65535)
		}
	case reflect.Uint64, reflect.Uint:
		s = newOmap().set("type", "integer").set("minimum", 0)
	case reflect.Float64:
		s = newOmap().set("type", "number")
	case reflect.Slice:
		items, _ := fieldSchema(t.Elem(), tag, false)
		s = newOmap().set("type", "array").set("items", items)
		if strings.Contains(tag, "max64") {
			s.set("maxItems", 64)
		}
	case reflect.Map:
		elt, _ := fieldSchema(t.Elem(), "", false)
		s = newOmap().set("type", "object").set("additionalProperties", elt)
		isNullable = isNullable || strings.Contains(tag, "nullable")
	case reflect.Struct:
		s = objectSchema(t)
	default:
		panic(fmt.Sprintf("unhandled kind %s for %s", t.Kind(), t))
	}
	return s, isNullable
}

func wrapNullable(inner *omap) *omap {
	return newOmap().set("anyOf", []any{newOmap().set("type", "null"), inner})
}

func stringSchema(tag string) *omap {
	for _, opt := range strings.Split(tag, ",") {
		switch {
		case opt == "ulid", opt == "hex64", opt == "hex32",
			opt == "ts", opt == "emitter", opt == "keyid":
			return ref(opt)
		case opt == "ip":
			return newOmap().set("type", "string")
		case opt == "port":
			return newOmap().set("type", "string")
		case strings.HasPrefix(opt, "enum:"):
			vals := strings.Split(strings.TrimPrefix(opt, "enum:"), "|")
			vs := make([]any, len(vals))
			for i, v := range vals {
				vs[i] = v
			}
			return newOmap().set("type", "string").set("enum", vs)
		case opt == "nullable", opt == "raw", opt == "max64":
		}
	}
	return newOmap().set("type", "string")
}

// objectSchema emits the strict object schema for a struct: every field
// required, nothing additional.
func objectSchema(t reflect.Type) *omap {
	required := make([]any, 0, t.NumField())
	props := newOmap()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		required = append(required, name)
		fs, _ := fieldSchema(f.Type, f.Tag.Get("cs"), false)
		props.set(name, fs)
	}
	return newOmap().
		set("type", "object").
		set("additionalProperties", false).
		set("required", required).
		set("properties", props)
}

// recordSchema is the full predicate schema for one record type.
func recordSchema(typeName string, bodyT reflect.Type) *omap {
	props := newOmap().
		set("v", newOmap().set("const", 1)).
		set("type", newOmap().set("const", typeName)).
		set("id", ref("ulid")).
		set("session", ref("ulid")).
		set("emitter", ref("emitter")).
		set("eseq", newOmap().set("type", "integer").set("minimum", 0)).
		set("eprev", ref("hex64")).
		set("ts", ref("ts")).
		set("body", objectSchema(bodyT))
	return newOmap().
		set("$schema", "https://json-schema.org/draft/2020-12/schema").
		set("$id", "https://"+names.APIGroup+"/schema/records/"+typeName+".json").
		set("title", "countersign record "+typeName+" (03 §4)").
		set("type", "object").
		set("additionalProperties", false).
		set("required", []any{"v", "type", "id", "session", "emitter", "eseq", "eprev", "ts", "body"}).
		set("properties", props)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: schemagen <outdir>")
		os.Exit(2)
	}
	out := os.Args[1]
	types := evidence.Types()
	for _, tn := range types {
		body, _ := evidence.NewBody(tn)
		sch := recordSchema(tn, reflect.TypeOf(body).Elem())
		b, err := json.MarshalIndent(sch, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		p := filepath.Join(out, tn+".json")
		if err := os.WriteFile(p, append(b, '\n'), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	sort.Strings(types)
	fmt.Printf("wrote %d record schemas to %s\n", len(types), out)
}
