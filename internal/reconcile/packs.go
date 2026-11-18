// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Expectation rule packs (spec/04 §6.2) live in packs/*.json, shared with
// the Python reference. This validates their shape and loads them, either
// from a directory or from the copy embedded in the binary.
package reconcile

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

//go:embed packs
var packFS embed.FS

var ruleKeys = map[string]bool{"id": true, "when": true, "forbid_tokens": true,
	"forbid_prefixes": true, "bind": true, "expect": true}
var whenKeys = map[string]bool{"tool": true, "tool_class": true, "argv0": true,
	"argv0_prefix": true, "argv1": true, "argv_prefix": true, "argv_eq": true,
	"url_arg_count": true, "input_has": true}
var bindKinds = map[string]bool{"first-arg-url": true, "single-url-arg": true,
	"input-field": true, "literal": true, "curl-method": true}
var shapes = map[string]bool{"git-smart-http": true, "http": true}

// ValidatePack checks one pack object and returns its rules tagged with
// the pack name (a fresh map per rule, like the reference).
func ValidatePack(obj map[string]any, name string) ([]map[string]any, error) {
	if str(mget(obj, "kind")) != "expectation-pack/v1" {
		return nil, fmt.Errorf("%s: bad kind", name)
	}
	pname := strOr(mget(obj, "pack"), name)
	rules, ok := mget(obj, "rules").([]any)
	if !ok {
		return nil, fmt.Errorf("%s: rules not a list", pname)
	}
	var out []map[string]any
	for i, rv := range rules {
		where := fmt.Sprintf("%s rule %d", pname, i)
		r, ok := rv.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: not an object", where)
		}
		for k := range r {
			if !ruleKeys[k] {
				return nil, fmt.Errorf("%s: bad key %q", where, k)
			}
		}
		if _, ok := r["id"].(string); !ok {
			return nil, fmt.Errorf("%s: no id", where)
		}
		for k := range mdict(r, "when") {
			if !whenKeys[k] {
				return nil, fmt.Errorf("%s: bad when key %q", where, k)
			}
		}
		for bname, bv := range mdict(r, "bind") {
			b, _ := bv.(map[string]any)
			if b == nil || !bindKinds[str(mget(b, "kind"))] {
				return nil, fmt.Errorf("%s: bind %s has bad kind", where, bname)
			}
		}
		exps, ok := mget(r, "expect").([]any)
		if !ok || len(exps) == 0 {
			return nil, fmt.Errorf("%s: empty expect", where)
		}
		for _, ev := range exps {
			e, _ := ev.(map[string]any)
			if e == nil || !shapes[str(mget(e, "shape"))] {
				return nil, fmt.Errorf("%s: bad expect shape %v", where, ev)
			}
		}
		cp := map[string]any{}
		for k, v := range r {
			cp[k] = v
		}
		cp["pack"] = pname
		out = append(out, cp)
	}
	return out, nil
}

// LoadPacks reads every *.json in dir into one flat rule list; an empty
// dir loads the packs embedded in the binary (internal/reconcile/packs).
func LoadPacks(dir string) ([]map[string]any, error) {
	if dir == "" {
		return loadPacksEmbed()
	}
	names, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var rules []map[string]any
	for _, name := range names {
		data, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		v, err := DecodeJSON(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: not an object", name)
		}
		rs, err := ValidatePack(obj, filepath.Base(name))
		if err != nil {
			return nil, err
		}
		rules = append(rules, rs...)
	}
	return rules, nil
}

func loadPacksEmbed() ([]map[string]any, error) {
	names, err := fs.Glob(packFS, "packs/*.json")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var rules []map[string]any
	for _, name := range names {
		data, err := packFS.ReadFile(name)
		if err != nil {
			return nil, err
		}
		v, err := DecodeJSON(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: not an object", name)
		}
		rs, err := ValidatePack(obj, name[len("packs/"):])
		if err != nil {
			return nil, err
		}
		rules = append(rules, rs...)
	}
	return rules, nil
}
