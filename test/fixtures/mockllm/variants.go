// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package mockllm

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

// Variant is a planted behavioural change (M12.4): the server applies it to
// the served response at a chosen turn so replay/divergence tooling has
// something to find.
type Variant struct {
	Kind string // extra-call | missing-call | different-arg | reordered-pair | different-host | write-for-read
	Turn int    // -1 → first turn that has calls
}

// ParseVariant parses "kind" or "kind@turn".
func ParseVariant(spec string) (Variant, error) {
	v := Variant{Turn: -1}
	name := spec
	if i := strings.LastIndex(spec, "@"); i >= 0 {
		t, err := strconv.Atoi(spec[i+1:])
		if err != nil {
			return v, fmt.Errorf("variant %q: bad turn", spec)
		}
		v.Turn = t
		name = spec[:i]
	}
	switch name {
	case "extra-call", "missing-call", "different-arg", "reordered-pair", "different-host", "write-for-read":
		v.Kind = name
	default:
		return v, fmt.Errorf("variant %q: unknown kind", name)
	}
	return v, nil
}

// apply mutates the response at the chosen turn (copied; caller keeps the
// transcript pristine).
func (v Variant) apply(t *Transcript) {
	if v.Kind == "" {
		return
	}
	idx := v.Turn
	if idx < 0 {
		for i, tn := range t.Turns {
			if len(tn.Response.Calls) > 0 {
				idx = i
				break
			}
		}
	}
	if idx < 0 || idx >= len(t.Turns) {
		return
	}
	resp := &t.Turns[idx].Response
	switch v.Kind {
	case "extra-call":
		resp.Calls = append(append([]Call{}, resp.Calls...),
			Call{Key: "variant-extra", Tool: "Write", Input: json.RawMessage(`{"file_path":"/tmp/planted.txt","content":"planted"}`)})
	case "missing-call":
		if len(resp.Calls) > 0 {
			resp.Calls = append([]Call{}, resp.Calls[:len(resp.Calls)-1]...)
		}
	case "different-arg":
		if len(resp.Calls) > 0 {
			var m map[string]any
			if json.Unmarshal(resp.Calls[0].Input, &m) == nil {
				for k, val := range m {
					if s, ok := val.(string); ok {
						m[k] = s + "-VARIANT"
						break
					}
				}
				if b, err := json.Marshal(m); err == nil {
					resp.Calls[0].Input = b
				}
			}
		}
	case "reordered-pair":
		if len(resp.Calls) >= 2 {
			resp.Calls[0], resp.Calls[1] = resp.Calls[1], resp.Calls[0]
		}
	case "different-host":
		for i := range resp.Calls {
			var m map[string]any
			if json.Unmarshal(resp.Calls[i].Input, &m) == nil {
				for k, val := range m {
					if s, ok := val.(string); ok && strings.Contains(s, "github.com") {
						m[k] = strings.ReplaceAll(s, "github.com", "attacker.example")
						if b, err := json.Marshal(m); err == nil {
							resp.Calls[i].Input = b
						}
						return
					}
				}
			}
		}
	case "write-for-read":
		if len(resp.Calls) > 0 && resp.Calls[0].Tool == "Read" {
			resp.Calls[0].Tool = "Write"
		}
	}
}

// Flaky applies the variant to a copy of the transcript with probability p per
// request, driven by a seeded RNG (C12.4.6 plants changes with probability p).
type Flaky struct {
	P    float64
	Rand *rand.Rand
}

// decide reports whether this request carries the planted change.
func (f *Flaky) decide() bool {
	if f == nil || f.Rand == nil {
		return true
	}
	return f.Rand.Float64() < f.P
}
