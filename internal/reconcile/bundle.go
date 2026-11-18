// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Bundle adapter (spec/04 §6.5): map an evidence bundle's members onto the
// abstract trace form the engine consumes.
//
// Real records differ from abstract ones in three ways the adapter must
// bridge:
//   - request queries are digested (query_sha256/query_len) — the query
//     abstraction compares digests with digests, never literals;
//   - intent inputs are recorded as input_sha256 + input_len with an
//     optional input_preview — the preview is accepted as the input only
//     when its canonical digest equals input_sha256;
//   - decision.would_deny is a plain reason string — it is normalized to
//     the abstract {action, reason} object before comparison;
//   - effect.tunnel cannot record class/attribution — its claim scope is
//     the decision block only.
package reconcile

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/countersign/countersign/internal/evidence"
	"gopkg.in/yaml.v3"
)

// BundleInput builds (meta, records) for the engine from a bundle's raw
// members (as returned by ledger.ReadBundle). Lines that cannot be decoded
// as evidence records are skipped — step V2 already flags them.
func BundleInput(members map[string][]byte) (map[string]any, []rec, error) {
	rawPolicy, ok := members["policy.yaml"]
	if !ok {
		return nil, nil, fmt.Errorf("policy.yaml missing")
	}
	var doc map[string]any
	if err := yaml.Unmarshal(rawPolicy, &doc); err != nil {
		return nil, nil, fmt.Errorf("policy.yaml: %w", err)
	}
	spec, _ := doc["spec"].(map[string]any)
	if spec == nil {
		return nil, nil, fmt.Errorf("policy.yaml: no spec object")
	}
	meta := map[string]any{"policy": spec}

	var cnames []string
	for name := range members {
		if strings.HasPrefix(name, "contracts/") &&
			(strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")) {
			cnames = append(cnames, name)
		}
	}
	if len(cnames) > 0 {
		sort.Strings(cnames)
		contracts := map[string]any{}
		for _, name := range cnames {
			var cdoc map[string]any
			if err := yaml.Unmarshal(members[name], &cdoc); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
			contracts[strings.TrimPrefix(name, "contracts/")] = cdoc
		}
		meta["contracts"] = contracts
		if len(cnames) == 1 {
			meta["contract"] = contracts[strings.TrimPrefix(cnames[0], "contracts/")]
		}
	}

	raw, ok := members["records.jsonl"]
	if !ok {
		return nil, nil, fmt.Errorf("records.jsonl missing")
	}
	var records []rec
	for _, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		r, err := recordToAbstract(line)
		if err != nil {
			continue // already an E_SCHEMA under V2
		}
		records = append(records, r)
	}
	return meta, records, nil
}

// ReconcileBundle runs the engine on a bundle's members.
func ReconcileBundle(members map[string][]byte, packs []map[string]any) (*Result, error) {
	meta, records, err := BundleInput(members)
	if err != nil {
		return nil, err
	}
	return Reconcile(meta, records, packs)
}

// recordToAbstract decodes one stored DSSE line to the abstract record
// form (body fields plus type/ts). Lines that fail the strict schema
// rules (already E_SCHEMA under V2) are skipped.
func recordToAbstract(line []byte) (rec, error) {
	_, st, _, err := evidence.DecodeRecordLine(line)
	if err != nil {
		return nil, err
	}
	v, err := DecodeJSON(st.Predicate)
	if err != nil {
		return nil, err
	}
	pred, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("predicate not an object")
	}
	body, ok := pred["body"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no body")
	}
	r := rec{}
	for k, val := range body {
		r[k] = val
	}
	if t, ok := pred["type"].(string); ok {
		r["type"] = t
	}
	if ts, ok := pred["ts"]; ok {
		r["ts"] = ts
	}
	switch r["type"] {
	case "effect.http":
		r["x-claim"] = claim{true, true, true}
		if req, ok := r["request"].(map[string]any); ok {
			if sha, ok := req["query_sha256"].(string); ok {
				ln, _ := jsonNum(req["query_len"])
				req["x-query"] = digestQuery(sha, int64(ln))
			} else {
				req["x-query"] = litQuery(str(req["query"]))
			}
		}
		normDecision(r)
	case "effect.tunnel":
		r["x-claim"] = claim{false, true, false}
		normDecision(r)
	case "intent.declared":
		recoverInput(r)
	}
	return r, nil
}

// normDecision rewrites decision.would_deny (a reason string in real
// records) to the abstract {action, reason} object.
func normDecision(r rec) {
	dec, ok := r["decision"].(map[string]any)
	if !ok {
		return
	}
	// On grant-resolution denies (NO_GRANT/DENY_GRANT/SMUGGLING_SUSPECT) no
	// class or condition is ever evaluated — the recomputation yields None
	// for both, so the recorded `class`/`requires` fields (non-nullable
	// placeholders in real records) carry no claim.
	switch dec["reason"] {
	case "NO_GRANT", "DENY_GRANT", "SMUGGLING_SUSPECT":
		dec["requires"] = nil
		r["class"] = nil
	}
	switch wd := dec["would_deny"].(type) {
	case string:
		action := "deny"
		if wd == "REVIEW_REQUIRED" {
			action = "hold"
		}
		dec["would_deny"] = map[string]any{"action": action, "reason": wd}
	}
}

// recoverInput accepts input_preview as the intent input only when its
// canonical digest equals input_sha256 (spec/04 §6.5).
func recoverInput(r rec) {
	if r["input"] != nil {
		return
	}
	preview, ok := r["input_preview"].(string)
	if !ok {
		return
	}
	v, err := DecodeJSON([]byte(preview))
	if err != nil {
		return
	}
	sha, err := CanonSHA256(v)
	if err != nil {
		return
	}
	if sha == str(r["input_sha256"]) {
		if m, ok := v.(map[string]any); ok {
			r["input"] = m
		}
	}
}
