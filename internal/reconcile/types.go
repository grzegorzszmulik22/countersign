// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Package reconcile is the Go reconciliation engine of spec/04 §5–§7 and
// §6.5 plus the class/condition rules of spec/05 §1–§2 (M9.2). It operates
// on the abstract trace form of docs/refreconcile.md (JSONL: a trace.meta
// line then record bodies) and, through the bundle adapter, on real
// evidence bundles for step V16 of spec/03 §10.
//
// Ordering is log order only. Timestamps are used exactly once — the §7.1
// startup-grace duration — and never for ordering.
package reconcile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// rec is one abstract record: the body fields plus "type" (and "ts").
type rec = map[string]any

func mget(m map[string]any, k string) any {
	if m == nil {
		return nil
	}
	return m[k]
}

func mdict(m map[string]any, k string) map[string]any {
	if d, ok := mget(m, k).(map[string]any); ok {
		return d
	}
	return nil
}

func mlist(m map[string]any, k string) []any {
	if l, ok := mget(m, k).([]any); ok {
		return l
	}
	return nil
}

func has(m map[string]any, k string) bool {
	if m == nil {
		return false
	}
	_, ok := m[k]
	return ok
}

// str returns v when it is a string, else "".
func str(v any) string {
	s, _ := v.(string)
	return s
}

// strOr returns v as a string or d when v is not a string.
func strOr(v any, d string) string {
	if s, ok := v.(string); ok {
		return s
	}
	return d
}

// truthy mirrors Python truthiness for JSON values.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		return x.String() != "0"
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// orValue returns a if truthy else b (Python `a or b`).
func orValue(a, b any) any {
	if truthy(a) {
		return a
	}
	return b
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// asStrList converts a JSON array to []string (non-strings dropped per
// element, mirroring how the reference treats list fields: membership and
// indexing over whatever is present).
func asStrList(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, e := range l {
		s, _ := e.(string)
		out = append(out, s)
	}
	return out
}

// inStrList is Python `s in list` for a JSON list of strings.
func inStrList(v any, s string) bool {
	for _, e := range asStrList(v) {
		if e == s {
			return true
		}
	}
	return false
}

func inStrSlice(l []string, s string) bool {
	for _, e := range l {
		if e == s {
			return true
		}
	}
	return false
}

// sameValue compares a recorded JSON value with a computed one
// (Python ==).
func sameValue(a, b any) bool {
	return jsonDeepEqual(a, b)
}

func jsonDeepEqual(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, e := range av {
			if !jsonDeepEqual(e, bv[k]) {
				return false
			}
		}
		return true
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i, e := range av {
			if !jsonDeepEqual(e, bv[i]) {
				return false
			}
		}
		return true
	}
	if an, aok := jsonNum(a); aok {
		bn, bok := jsonNum(b)
		return bok && an == bn
	}
	if _, ok := jsonNum(b); ok {
		return false
	}
	return a == b
}

// jsonNum reads a scalar as a float when it is a JSON number type.
func jsonNum(v any) (float64, bool) {
	switch x := v.(type) {
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	}
	return 0, false
}
