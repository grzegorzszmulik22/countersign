// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// C9.2.4 — every field the broker records inside `decision` (and the
// recorded class/attribution it is compared with) is a claim the verifier
// recomputes and checks (spec/04 §6.4–§6.5, spec/03 §10 V16). Each test
// tampers exactly one recorded field of an otherwise honest re-signed
// bundle and requires the matching F_* finding.
package main

import (
	"testing"

	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/ledger"
	"github.com/countersign/countersign/internal/ledger/ldtest"
	"github.com/countersign/countersign/internal/names"
	"github.com/countersign/countersign/internal/reconcile"
)

// decFieldPolicy extends reconPolicy with an intent-requiring POST grant
// (class irreversible → autonomy review → hold in enforce, would_deny
// hold in audit) and a grant carrying a credential.
var decFieldPolicy = []byte(`apiVersion: ` + names.APIGroup + `/v1alpha1
kind: Policy
metadata: {name: decfield-test}
spec:
  mode: enforce
  toolClasses: {Bash: exec, WebFetch: http, "mcp__*": mcp, "*": other}
  autonomy: {safe: allow, control: allow, staged: intent, compensable: intent, irreversible: review}
  maxIntentOpenSeconds: 3600
  commandField: command
  grants:
    - id: cdn
      match: {hosts: [cdn.example.com], methods: [GET]}
    - id: api
      match: {hosts: [api.example.com], methods: [GET]}
      requires: intent
      intentMatch: exact
    - id: apiw
      match: {hosts: [api.example.com], methods: [POST]}
      requires: intent
      intentMatch: window
    - id: cred
      match: {hosts: [cred.example.com], methods: [GET]}
      credential: AK-test
    - id: ads
      match: {hosts: [ads.example.com]}
      action: deny
`)

// decBundle emits a session under decFieldPolicy: open, `before` effects,
// the cdn via-effect, intent i1 (curl https://api.example.com/x), then the
// caller's effects, then a clean seal. Records are signed at emit time, so
// every body below is exactly what a broker would have recorded.
func decBundle(t *testing.T, mode string, before, effects []map[string]any) ([]byte, keys.Manifest) {
	t.Helper()
	dir := t.TempDir()
	s := ldtest.New(names.APIGroup + "/log/test")
	s.Policy = decFieldPolicy
	s.Contracts = map[string][]byte{}
	l, err := ledger.Open(dir, names.APIGroup+"/log/test", s.LogSigner)
	if err != nil {
		t.Fatal(err)
	}
	s.Open(l, mode)
	for _, e := range before {
		s.Emit(l, "broker", "effect.http", ldtest.Body("effect.http", e))
	}
	s.Emit(l, "broker", "effect.http", ldtest.Body("effect.http",
		httpBody("e0", "GET", "cdn.example.com", "safe", allowDec("cdn"), attr("NONE", []string{}))))
	s.Emit(l, "broker", "intent.declared", ldtest.Body("intent.declared",
		intentBody(t, "i1", "e0", "Bash",
			map[string]any{"command": "curl https://api.example.com/x"})))
	for _, e := range effects {
		s.Emit(l, "broker", "effect.http", ldtest.Body("effect.http", e))
	}
	s.Emit(l, "observer", "observer.gap", ldtest.Body("observer.gap", nil))
	s.Emit(l, "world", "world.closed", ldtest.Body("world.closed", map[string]any{"outcome": "closed"}))
	s.EmitterSeal(l, "broker")
	s.EmitterSeal(l, "world")
	s.EmitterSeal(l, "observer")
	s.Seal(l)
	b, err := l.ExportBundle(s.ID, s.Manifest, s.Extras())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return b, s.Manifest
}

// decBody is httpBody with a free-form decision map.
func decBody(id, method, authority, path, class string, dec, attr map[string]any) map[string]any {
	b := httpBody(id, method, authority, class, dec, attr)
	if path != "/x" {
		b["request"].(map[string]any)["path"] = path
	}
	return b
}

// clone returns a deep copy of a flat JSON-object map (one level of
// nesting for request/decision/attribution).
func clone(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if mm, ok := v.(map[string]any); ok {
			out[k] = clone(mm)
		} else {
			out[k] = v
		}
	}
	return out
}

// decCase is one tamper case: an honest recorded effect plus a mutation
// applied to the decision map before emit.
type decCase struct {
	name   string
	mode   string
	effect map[string]any
	mutate func(dec map[string]any)
	codes  []string
}

func TestC924_DecisionFieldMatrix(t *testing.T) {
	// Honest recorded decisions per recomputed outcome.
	excat := attr("EXACT", []string{"i1"})
	win := attr("WINDOW", []string{"i1"})
	none := attr("NONE", []string{})

	honest := map[string]map[string]any{
		// GET api.example.com/x while i1 open: EXACT, allow.
		"allow": decBody("e1", "GET", "api.example.com", "/x", "safe",
			map[string]any{"action": "allow", "reason": "OK", "requires": "intent",
				"grant": "api", "credentials": []string{}}, excat),
		// GET api.example.com/other while i1 open: WINDOW, exact-match
		// intent condition fails → audit allows with would_deny NO_INTENT.
		"audit_deny": decBody("e2", "GET", "api.example.com", "/other", "safe",
			map[string]any{"action": "allow", "reason": "OK", "requires": "intent",
				"grant": "api", "credentials": []string{}, "would_deny": "NO_INTENT"}, win),
		// POST api.example.com/y while i1 open: irreversible+review →
		// audit allows with would_deny REVIEW_REQUIRED (a hold, not deny).
		"audit_hold": decBody("e3", "POST", "api.example.com", "/y", "irreversible",
			map[string]any{"action": "allow", "reason": "OK", "requires": "review",
				"grant": "apiw", "credentials": []string{}, "would_deny": "REVIEW_REQUIRED"}, win),
		// GET ungranted.example.com: no grant → audit allows with
		// would_deny NO_GRANT; class/requires/grant recomputed empty.
		"audit_nogrant": decBody("e4", "GET", "ungranted.example.com", "/x", "",
			map[string]any{"action": "allow", "reason": "OK",
				"grant": "", "credentials": []string{}, "would_deny": "NO_GRANT"}, none),
		// GET ads.example.com: deny grant → deny DENY_GRANT every mode.
		"denied": decBody("e9", "GET", "ads.example.com", "/x", "",
			map[string]any{"action": "deny", "reason": "DENY_GRANT",
				"grant": "ads", "credentials": []string{}}, none),
		// GET cred.example.com: grant carries credential AK-test.
		"cred": decBody("e5", "GET", "cred.example.com", "/x", "safe",
			map[string]any{"action": "allow", "reason": "OK", "requires": "allow",
				"grant": "cred", "credentials": []string{"AK-test"}}, win),
	}

	// Modes the audit-* records are honest under: audit only (the same
	// records in enforce/learn are decision mismatches on action).
	cases := []decCase{}
	set := func(k string, v any) func(map[string]any) {
		return func(dec map[string]any) { dec[k] = v }
	}
	del := func(k string) func(map[string]any) {
		return func(dec map[string]any) { delete(dec, k) }
	}

	// The same allow-effect in every mode: each recorded decision field,
	// tampered one at a time.
	for _, mode := range []string{"enforce", "audit", "learn"} {
		base := honest["allow"]
		cases = append(cases,
			decCase{mode + "/action-deny", mode, base, set("action", "deny"), []string{"F_DECISION_MISMATCH"}},
			decCase{mode + "/action-hold", mode, base, set("action", "hold"), []string{"F_DECISION_MISMATCH"}},
			decCase{mode + "/reason", mode, base, set("reason", "NO_INTENT"), []string{"F_DECISION_MISMATCH"}},
			decCase{mode + "/grant", mode, base, set("grant", "cdn"), []string{"F_DECISION_MISMATCH"}},
			decCase{mode + "/grant-dropped", mode, base, del("grant"), []string{"F_DECISION_MISMATCH"}},
			decCase{mode + "/requires", mode, base, set("requires", "allow"), []string{"F_CLASS_MISMATCH"}},
			decCase{mode + "/requires-dropped", mode, base, del("requires"), []string{"F_CLASS_MISMATCH"}},
			decCase{mode + "/credentials", mode, base, set("credentials", []string{"AK-other"}), []string{"F_CREDENTIAL_SCOPE"}},
			decCase{mode + "/would_deny-added", mode, base, set("would_deny", "NO_INTENT"), []string{"F_DECISION_MISMATCH"}},
		)
	}

	// Audit mode: the effect recomputes to allow+would_deny{deny,
	// NO_INTENT}. The recorded would_deny is a claim of both fields.
	cases = append(cases,
		decCase{"audit/would_deny-dropped", "audit", honest["audit_deny"], del("would_deny"), []string{"F_DECISION_MISMATCH"}},
		decCase{"audit/would_deny-reason", "audit", honest["audit_deny"], set("would_deny", "NO_GRANT"), []string{"F_DECISION_MISMATCH"}},
		decCase{"audit/would_deny-action", "audit", honest["audit_deny"], set("would_deny", "REVIEW_REQUIRED"), []string{"F_DECISION_MISMATCH"}},
		decCase{"audit/would_deny-empty", "audit", honest["audit_deny"], set("would_deny", ""), []string{"F_DECISION_MISMATCH"}},
		decCase{"audit/would_deny-nonsense", "audit", honest["audit_deny"], set("would_deny", "STAGED"), []string{"F_DECISION_MISMATCH"}},
		decCase{"audit/action", "audit", honest["audit_deny"], set("action", "deny"), []string{"F_DECISION_MISMATCH"}},
		decCase{"audit/reason", "audit", honest["audit_deny"], set("reason", "NO_INTENT"), []string{"F_DECISION_MISMATCH"}},
		decCase{"audit/grant", "audit", honest["audit_deny"], set("grant", "cdn"), []string{"F_DECISION_MISMATCH"}},
		decCase{"audit/requires", "audit", honest["audit_deny"], set("requires", "allow"), []string{"F_CLASS_MISMATCH"}},
		decCase{"audit/credentials", "audit", honest["audit_deny"], set("credentials", []string{"AK-x"}), []string{"F_CREDENTIAL_SCOPE"}},
	)

	// The hold form: recorded would_deny "REVIEW_REQUIRED" normalizes to
	// action hold; any other action or reason must mismatch.
	cases = append(cases,
		decCase{"audit-hold/would_deny-dropped", "audit", honest["audit_hold"], del("would_deny"), []string{"F_DECISION_MISMATCH"}},
		decCase{"audit-hold/would_deny-deny", "audit", honest["audit_hold"], set("would_deny", "NO_INTENT"), []string{"F_DECISION_MISMATCH"}},
		decCase{"audit-hold/action", "audit", honest["audit_hold"], set("action", "hold"), []string{"F_DECISION_MISMATCH"}},
		decCase{"audit-hold/requires", "audit", honest["audit_hold"], set("requires", "intent"), []string{"F_CLASS_MISMATCH"}},
	)

	// NO_GRANT in audit: grant/class/requires recompute empty; the
	// recorded would_deny still claims {deny, NO_GRANT}.
	cases = append(cases,
		decCase{"audit-nogrant/would_deny-dropped", "audit", honest["audit_nogrant"], del("would_deny"), []string{"F_DECISION_MISMATCH"}},
		decCase{"audit-nogrant/would_deny-reason", "audit", honest["audit_nogrant"], set("would_deny", "NO_INTENT"), []string{"F_DECISION_MISMATCH"}},
		decCase{"audit-nogrant/grant", "audit", honest["audit_nogrant"], set("grant", "api"), []string{"F_DECISION_MISMATCH"}},
		decCase{"audit-nogrant/reason", "audit", honest["audit_nogrant"], set("reason", "NO_GRANT"), []string{"F_DECISION_MISMATCH"}},
	)

	// Deny-grant records (deny DENY_GRANT) in every mode.
	for _, mode := range []string{"enforce", "audit", "learn"} {
		base := honest["denied"]
		cases = append(cases,
			decCase{mode + "-denied/action", mode, base, set("action", "allow"), []string{"F_DECISION_MISMATCH"}},
			decCase{mode + "-denied/reason", mode, base, set("reason", "NO_INTENT"), []string{"F_DECISION_MISMATCH"}},
			decCase{mode + "-denied/grant", mode, base, set("grant", "api"), []string{"F_DECISION_MISMATCH"}},
		)
	}

	// Credentials: a recorded credential on a grant carrying none is
	// F_CREDENTIAL_SCOPE (04 §6.5); on a credential grant the schema-free
	// string list is the broker's claim.
	cases = append(cases,
		decCase{"cred/none-on-cred-grant", "enforce", honest["cred"], del("credentials"), []string{}}, // §6.5 checks only recorded-vs-grant
		decCase{"cred/wrong-grant", "enforce", honest["cred"], set("grant", "api"), []string{"F_DECISION_MISMATCH"}},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eff := clone(tc.effect)
			dec := eff["decision"].(map[string]any)
			tc.mutate(dec)
			b, m := decBundle(t, tc.mode, nil, []map[string]any{eff})
			res, rc := reconVerify(t, b, m)
			if len(tc.codes) == 0 {
				// Control cases: the honest record must produce no
				// findings and keep the CLEAN-class verdict.
				if len(rc.Findings) != 0 {
					t.Fatalf("honest record flagged: %v", rc.Findings)
				}
				if res.Verdict == "VIOLATIONS" || res.Verdict == "INVALID" {
					t.Fatalf("verdict %s on honest record", res.Verdict)
				}
				return
			}
			for _, code := range tc.codes {
				if !hasFinding(rc.Findings, code) {
					t.Fatalf("want %s, got %v", code, rc.Findings)
				}
			}
			// The lattice keeps a learn session at LEARN even with
			// findings; every other mode must reach VIOLATIONS.
			want := "VIOLATIONS"
			if tc.mode == "learn" {
				want = "LEARN"
			}
			if res.Verdict != want {
				t.Fatalf("verdict %s, want %s", res.Verdict, want)
			}
		})
	}
}

// The audit-hold honest record: would_deny normalizes "REVIEW_REQUIRED"
// to action hold. Asserted as a control so a normalization change (e.g.
// mapping it to deny) fails loudly instead of only via tamper cases.
func TestC924_DecisionFieldHonest(t *testing.T) {
	excat := attr("EXACT", []string{"i1"})
	for _, tc := range []struct {
		name   string
		mode   string
		effect map[string]any
	}{
		{"enforce-allow", "enforce", decBody("e1", "GET", "api.example.com", "/x", "safe",
			map[string]any{"action": "allow", "reason": "OK", "requires": "intent",
				"grant": "api", "credentials": []string{}}, excat)},
		{"audit-allow", "audit", decBody("e1", "GET", "api.example.com", "/x", "safe",
			map[string]any{"action": "allow", "reason": "OK", "requires": "intent",
				"grant": "api", "credentials": []string{}}, excat)},
		{"audit-would-deny-deny", "audit", decBody("e2", "GET", "api.example.com", "/other", "safe",
			map[string]any{"action": "allow", "reason": "OK", "requires": "intent",
				"grant": "api", "credentials": []string{}, "would_deny": "NO_INTENT"},
			attr("WINDOW", []string{"i1"}))},
		{"audit-would-deny-hold", "audit", decBody("e3", "POST", "api.example.com", "/y", "irreversible",
			map[string]any{"action": "allow", "reason": "OK", "requires": "review",
				"grant": "apiw", "credentials": []string{}, "would_deny": "REVIEW_REQUIRED"},
			attr("WINDOW", []string{"i1"}))},
		{"audit-nogrant", "audit", decBody("e4", "GET", "ungranted.example.com", "/x", "",
			map[string]any{"action": "allow", "reason": "OK",
				"grant": "", "credentials": []string{}, "would_deny": "NO_GRANT"},
			attr("NONE", []string{}))},
		{"learn-allow", "learn", decBody("e1", "GET", "api.example.com", "/x", "safe",
			map[string]any{"action": "allow", "reason": "OK", "requires": "intent",
				"grant": "api", "credentials": []string{}}, excat)},
		{"enforce-denied", "enforce", decBody("e9", "GET", "ads.example.com", "/x", "",
			map[string]any{"action": "deny", "reason": "DENY_GRANT",
				"grant": "ads", "credentials": []string{}}, attr("NONE", []string{}))},
		{"learn-denied", "learn", decBody("e9", "GET", "ads.example.com", "/x", "",
			map[string]any{"action": "deny", "reason": "DENY_GRANT",
				"grant": "ads", "credentials": []string{}}, attr("NONE", []string{}))},
		{"cred-honest", "enforce", decBody("e5", "GET", "cred.example.com", "/x", "safe",
			map[string]any{"action": "allow", "reason": "OK", "requires": "allow",
				"grant": "cred", "credentials": []string{"AK-test"}}, attr("WINDOW", []string{"i1"}))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, m := decBundle(t, tc.mode, nil, []map[string]any{tc.effect})
			res, rc := reconVerify(t, b, m)
			if len(rc.Findings) != 0 {
				t.Fatalf("honest %s flagged: %v", tc.name, rc.Findings)
			}
			wantClean := res.Verdict == "CLEAN" || res.Verdict == "CLEAN_WITH_DENIALS" || res.Verdict == "LEARN"
			if !wantClean {
				t.Fatalf("verdict %s on honest %s", res.Verdict, tc.name)
			}
		})
	}
}

// The abstract trace form (corpus/differential input) records
// would_deny as the {action, reason} object itself; the comparison must
// treat it the same way as the normalized real-record string.
func TestC924_DecisionFieldAbstract(t *testing.T) {
	policy := map[string]any{
		"mode":         "enforce",
		"toolClasses":  map[string]any{"Bash": "exec", "*": "other"},
		"autonomy":     map[string]any{"safe": "allow", "control": "allow", "staged": "intent", "compensable": "intent", "irreversible": "review"},
		"commandField": "command",
		"grants": []any{
			map[string]any{"id": "api", "match": map[string]any{"hosts": []any{"api.example.com"}, "methods": []any{"GET"}}, "requires": "intent", "intentMatch": "exact"},
		},
	}
	meta := map[string]any{"policy": policy}
	open := map[string]any{"type": "session.open", "kind": "agent", "mode": "audit"}
	intent := map[string]any{"type": "intent.declared", "intent_id": "i1", "tool": "Bash",
		"class": "exec", "executor": "sandbox",
		"input": map[string]any{"command": "curl https://api.example.com/x"}}
	effect := func(dec, att map[string]any) map[string]any {
		return map[string]any{
			"type": "effect.http", "effect_id": "e2", "actor": "sandbox",
			"request": map[string]any{"method": "GET", "scheme": "https",
				"authority": "api.example.com", "path": "/other", "query": ""},
			"class": "safe", "decision": dec, "attribution": att,
		}
	}
	seal := map[string]any{"type": "session.seal"}
	att := map[string]any{"level": "WINDOW", "intents": []any{"i1"}}

	for _, tc := range []struct {
		name string
		wd   any  // recorded would_deny (abstract object form)
		want bool // expect F_DECISION_MISMATCH
	}{
		{"honest", map[string]any{"action": "deny", "reason": "NO_INTENT"}, false},
		{"dropped", nil, true},
		{"reason", map[string]any{"action": "deny", "reason": "NO_GRANT"}, true},
		{"action", map[string]any{"action": "hold", "reason": "REVIEW_REQUIRED"}, true},
		{"extra-key", map[string]any{"action": "deny", "reason": "NO_INTENT", "x": 1}, true},
		{"empty-object", map[string]any{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dec := map[string]any{"action": "allow", "reason": "OK", "requires": "intent",
				"grant": "api", "credentials": []any{}}
			if tc.wd != nil {
				dec["would_deny"] = tc.wd
			}
			records := []map[string]any{open, intent, effect(dec, att), seal}
			res, err := reconcile.Reconcile(meta, records, nil)
			if err != nil {
				t.Fatal(err)
			}
			got := hasFinding(res.Findings, "F_DECISION_MISMATCH")
			if got != tc.want {
				t.Fatalf("wd=%v: mismatch=%v want %v (findings %v)", tc.wd, got, tc.want, res.Findings)
			}
		})
	}
}
