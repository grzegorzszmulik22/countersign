// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// C9.2.4 / C9.2.5 — the verifier recomputes attribution and decision from
// the records and bundled policy (spec/04 §6.5) and must not trust
// broker-recorded fields, and the merged verdict respects the lattice of
// spec/03 §10.
package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/ledger"
	"github.com/countersign/countersign/internal/ledger/ldtest"
	"github.com/countersign/countersign/internal/names"
	"github.com/countersign/countersign/internal/reconcile"
)

// reconPolicy is a real-format policy.yaml. grant api requires an intent
// (exact match); cdn is unconditional; ads is a deny grant.
var reconPolicy = []byte(`apiVersion: ` + names.APIGroup + `/v1alpha1
kind: Policy
metadata: {name: recon-test}
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
    - id: ads
      match: {hosts: [ads.example.com]}
      action: deny
`)

// intentBody returns an intent.declared override whose input_preview is the
// canonical JSON of input and whose input_sha256 matches it (04 §6.5).
func intentBody(t *testing.T, id, via, tool string, input map[string]any) map[string]any {
	t.Helper()
	preview, err := reconcile.CanonString(input)
	if err != nil {
		t.Fatalf("canon: %v", err)
	}
	sha, err := reconcile.CanonSHA256(input)
	if err != nil {
		t.Fatalf("sha: %v", err)
	}
	return map[string]any{
		"intent_id": id, "via_effect": via, "tool": tool, "class": "exec",
		"executor":     "sandbox",
		"input_sha256": sha, "input_len": len(preview),
		"input_preview": string(preview),
	}
}

func httpBody(id, method, authority, class string, dec, attr map[string]any) map[string]any {
	return map[string]any{
		"effect_id": id, "actor": "sandbox",
		"request": map[string]any{
			"method": method, "scheme": "https", "authority": authority,
			"path": "/x",
			// sha256("") — an empty digested query, as real records carry.
			"query_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"query_len":    0,
		},
		"class": class, "decision": dec, "attribution": attr,
	}
}

func allowDec(grant string) map[string]any {
	return map[string]any{"action": "allow", "reason": "OK", "requires": "allow",
		"grant": grant, "credentials": []string{}}
}

func intentDec(grant string) map[string]any {
	return map[string]any{"action": "allow", "reason": "OK", "requires": "intent",
		"grant": grant, "credentials": []string{}}
}

func attr(level string, intents []string) map[string]any {
	return map[string]any{"level": level, "intents": intents}
}

// reconBundle emits a session: open, one cdn effect (the intent's
// via_effect), the intent, then the caller's effects, then a clean seal.
// extra may emit additional records before the seal. When seal is false
// the session.seal record is omitted (UNSEALED case).
func reconBundle(t *testing.T, mode string, effects []map[string]any, seal bool, extra func(*ledger.Ledger, *ldtest.Session)) ([]byte, keys.Manifest) {
	return reconBundleBefore(t, mode, nil, effects, seal, extra)
}

// reconBundleBefore additionally emits `before` effect records directly
// after session.open — before the intent is declared.
func reconBundleBefore(t *testing.T, mode string, before, effects []map[string]any, seal bool, extra func(*ledger.Ledger, *ldtest.Session)) ([]byte, keys.Manifest) {
	t.Helper()
	dir := t.TempDir()
	s := ldtest.New(names.APIGroup + "/log/test")
	s.Policy = reconPolicy
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
	if extra != nil {
		extra(l, s)
	}
	s.Emit(l, "observer", "observer.gap", ldtest.Body("observer.gap", nil))
	s.Emit(l, "world", "world.closed", ldtest.Body("world.closed", map[string]any{"outcome": "closed"}))
	s.EmitterSeal(l, "broker")
	s.EmitterSeal(l, "world")
	s.EmitterSeal(l, "observer")
	if seal {
		s.Seal(l)
	}
	b, err := l.ExportBundle(s.ID, s.Manifest, s.Extras())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return b, s.Manifest
}

// reconVerify runs base verify plus V16 reconciliation on a bundle.
func reconVerify(t *testing.T, b []byte, m keys.Manifest) (*ledger.VerifyResult, *reconcile.Result) {
	t.Helper()
	res := ledger.VerifyBundle(b, m)
	members, err := ledger.ReadBundle(b)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	rc, err := reconcile.ReconcileBundle(members, nil)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	mergeReconcile(res, rc)
	return res, rc
}

func hasFinding(fs []reconcile.Finding, code string) bool {
	for _, f := range fs {
		if f.Code == code {
			return true
		}
	}
	return false
}

func hasErr(es []ledger.Finding, code string) bool {
	for _, e := range es {
		if e.Code == code {
			return true
		}
	}
	return false
}

var honestEffects = []map[string]any{
	httpBody("e1", "GET", "api.example.com", "safe", intentDec("api"), attr("EXACT", []string{"i1"})),
}

// C9.2.4 — re-signed bundles whose broker-recorded claims are wrong must
// surface the corresponding recomputation finding.
func TestC924_TamperedRecordedFields(t *testing.T) {
	cases := []struct {
		name    string
		effects []map[string]any
		code    string
	}{
		{"attribution-level", []map[string]any{
			httpBody("e1", "GET", "api.example.com", "safe", intentDec("api"), attr("NONE", []string{})),
		}, "F_ATTRIBUTION_MISMATCH"},
		{"attribution-intents", []map[string]any{
			httpBody("e1", "GET", "api.example.com", "safe", intentDec("api"), attr("EXACT", []string{"i9"})),
		}, "F_ATTRIBUTION_MISMATCH"},
		{"decision-action", []map[string]any{
			httpBody("e1", "GET", "api.example.com", "safe",
				map[string]any{"action": "deny", "reason": "NO_INTENT", "requires": "intent",
					"grant": "api", "credentials": []string{}},
				attr("NONE", []string{})),
		}, "F_DECISION_MISMATCH"},
		{"decision-ungranted", []map[string]any{
			httpBody("e1", "GET", "evil.example.com", "safe", allowDec(""), attr("NONE", []string{})),
		}, "F_DECISION_MISMATCH"},
		{"class", []map[string]any{
			httpBody("e1", "GET", "api.example.com", "compensable", intentDec("api"), attr("EXACT", []string{"i1"})),
		}, "F_CLASS_MISMATCH"},
		{"credential-scope", []map[string]any{
			httpBody("e1", "GET", "api.example.com", "safe",
				map[string]any{"action": "allow", "reason": "OK", "requires": "intent",
					"grant": "api", "credentials": []string{"AK"}},
				attr("EXACT", []string{"i1"})),
		}, "F_CREDENTIAL_SCOPE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, m := reconBundle(t, "enforce", tc.effects, true, nil)
			res, rc := reconVerify(t, b, m)
			if !hasFinding(rc.Findings, tc.code) {
				t.Fatalf("want %s, got %v", tc.code, rc.Findings)
			}
			if res.Verdict != "VIOLATIONS" {
				t.Fatalf("verdict %s, want VIOLATIONS", res.Verdict)
			}
		})
	}
}

// C9.2.4 — an audit-mode effect allowed with would_deny but carrying no
// qualifying intent must be flagged F_UNATTRIBUTED.
func TestC924_AuditUnattributed(t *testing.T) {
	unattr := httpBody("e2", "GET", "api.example.com", "safe",
		map[string]any{"action": "allow", "reason": "OK", "requires": "intent",
			"grant": "api", "credentials": []string{},
			"would_deny": "NO_INTENT"},
		attr("NONE", []string{}))
	unattr["request"].(map[string]any)["path"] = "/other" // intent expects /x
	// Emitted before the intent opens: O(e2) is empty and the grant
	// requires intent, so the level is NONE.
	b, m := reconBundleBefore(t, "audit", []map[string]any{unattr}, honestEffects, true, nil)
	res, rc := reconVerify(t, b, m)
	if !hasFinding(rc.Findings, "F_UNATTRIBUTED") {
		t.Fatalf("want F_UNATTRIBUTED, got %v", rc.Findings)
	}
	if res.Verdict != "VIOLATIONS" {
		t.Fatalf("verdict %s", res.Verdict)
	}
}

// TestDumpBundle writes a bundle + keys.json to $CS_DUMP_DIR for manual
// CLI exercise (`csverify --reconcile`, `csverify explain`).
func TestDumpBundle(t *testing.T) {
	dir := os.Getenv("CS_DUMP_DIR")
	if dir == "" {
		t.Skip("CS_DUMP_DIR unset")
	}
	b, m := reconBundle(t, "enforce", honestEffects, true, nil)
	if err := os.WriteFile(dir+"/bundle.tar", b, 0o644); err != nil {
		t.Fatal(err)
	}
	kb, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/keys.json", kb, 0o644); err != nil {
		t.Fatal(err)
	}
}

// An input_preview whose canonical digest does not match input_sha256
// must not be used as the intent's input: without it the expectation
// list is empty and the effect cannot be EXACT.
func TestC924_InputPreviewDigest(t *testing.T) {
	bad := intentBody(t, "i1", "e0", "Bash",
		map[string]any{"command": "curl https://api.example.com/x"})
	bad["input_preview"] = `{"command":"curl https://api.example.com/different"}`
	dir := t.TempDir()
	s := ldtest.New(names.APIGroup + "/log/test")
	s.Policy = reconPolicy
	s.Contracts = map[string][]byte{}
	l, err := ledger.Open(dir, names.APIGroup+"/log/test", s.LogSigner)
	if err != nil {
		t.Fatal(err)
	}
	s.Open(l, "enforce")
	s.Emit(l, "broker", "effect.http", ldtest.Body("effect.http",
		httpBody("e0", "GET", "cdn.example.com", "safe", allowDec("cdn"), attr("NONE", []string{}))))
	s.Emit(l, "broker", "intent.declared", ldtest.Body("intent.declared", bad))
	s.Emit(l, "broker", "effect.http", ldtest.Body("effect.http",
		httpBody("e1", "GET", "api.example.com", "safe", intentDec("api"), attr("EXACT", []string{"i1"}))))
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
	_ = l.Close()
	res, rc := reconVerify(t, b, s.Manifest)
	if !hasFinding(rc.Findings, "F_ATTRIBUTION_MISMATCH") {
		t.Fatalf("tampered preview must not satisfy the intent, got %v", rc.Findings)
	}
	if res.Verdict != "VIOLATIONS" {
		t.Fatalf("verdict %s", res.Verdict)
	}
}

// C9.2.5 — the verdict lattice of 03 §10 must hold on constructed cases.
func TestC925_VerdictLattice(t *testing.T) {
	t.Run("clean", func(t *testing.T) {
		b, m := reconBundle(t, "enforce", honestEffects, true, nil)
		res, rc := reconVerify(t, b, m)
		if len(rc.Findings) != 0 {
			t.Fatalf("findings %v", rc.Findings)
		}
		if res.Verdict != "CLEAN" {
			t.Fatalf("verdict %s, want CLEAN", res.Verdict)
		}
	})
	t.Run("clean-with-denials", func(t *testing.T) {
		deny := httpBody("e9", "GET", "ads.example.com", "safe",
			map[string]any{"action": "deny", "reason": "DENY_GRANT", "requires": "allow",
				"grant": "ads", "credentials": []string{}},
			attr("NONE", []string{}))
		effs := append(append([]map[string]any{}, honestEffects...), deny)
		b, m := reconBundle(t, "enforce", effs, true, func(l *ledger.Ledger, s *ldtest.Session) {
			s.Emit(l, "broker", "effect.denied", ldtest.Body("effect.denied", nil))
		})
		res, rc := reconVerify(t, b, m)
		if len(rc.Findings) != 0 {
			t.Fatalf("findings %v", rc.Findings)
		}
		if res.Verdict != "CLEAN_WITH_DENIALS" {
			t.Fatalf("verdict %s, want CLEAN_WITH_DENIALS", res.Verdict)
		}
	})
	t.Run("violations", func(t *testing.T) {
		effs := []map[string]any{
			httpBody("e1", "GET", "api.example.com", "safe", intentDec("api"), attr("NONE", []string{})),
		}
		b, m := reconBundle(t, "enforce", effs, true, nil)
		res, _ := reconVerify(t, b, m)
		if res.Verdict != "VIOLATIONS" {
			t.Fatalf("verdict %s, want VIOLATIONS", res.Verdict)
		}
	})
	t.Run("learn", func(t *testing.T) {
		b, m := reconBundle(t, "learn", honestEffects, true, nil)
		res, _ := reconVerify(t, b, m)
		if res.Verdict != "LEARN" {
			t.Fatalf("verdict %s, want LEARN", res.Verdict)
		}
	})
	t.Run("unsealed", func(t *testing.T) {
		b, m := reconBundle(t, "enforce", honestEffects, false, nil)
		res, _ := reconVerify(t, b, m)
		if res.Verdict != "UNSEALED" {
			t.Fatalf("verdict %s, want UNSEALED", res.Verdict)
		}
	})
	// Lattice ordering: findings cannot pull a LEARN or UNSEALED session
	// down to VIOLATIONS.
	t.Run("learn-with-findings", func(t *testing.T) {
		effs := []map[string]any{
			httpBody("e1", "GET", "api.example.com", "safe", intentDec("api"), attr("NONE", []string{})),
		}
		b, m := reconBundle(t, "learn", effs, true, nil)
		res, _ := reconVerify(t, b, m)
		if res.Verdict != "LEARN" {
			t.Fatalf("verdict %s, want LEARN", res.Verdict)
		}
	})
	t.Run("unsealed-with-findings", func(t *testing.T) {
		effs := []map[string]any{
			httpBody("e1", "GET", "api.example.com", "safe", intentDec("api"), attr("NONE", []string{})),
		}
		b, m := reconBundle(t, "enforce", effs, false, nil)
		res, _ := reconVerify(t, b, m)
		if res.Verdict != "UNSEALED" {
			t.Fatalf("verdict %s, want UNSEALED", res.Verdict)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		b, m := reconBundle(t, "enforce", honestEffects, true, nil)
		var kept keys.Manifest
		for _, e := range m {
			if e.Role != "emitter:broker" {
				kept = append(kept, e)
			}
		}
		res, _ := reconVerify(t, b, kept)
		if res.Verdict != "INVALID" {
			t.Fatalf("verdict %s, want INVALID", res.Verdict)
		}
		if !hasErr(res.Errors, "E_KEY") {
			t.Fatalf("want E_KEY, got %v", res.Errors)
		}
	})
}
