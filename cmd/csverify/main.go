// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// csverify <bundle> --keys keys.json — the offline evidence verifier of
// 03 §10. Reads only the bundle and the trusted manifest; no network, no
// ledger access. Exit 0 only for CLEAN and CLEAN_WITH_DENIALS.
//
//	csverify <bundle> --keys keys.json [--reconcile]
//	csverify explain <bundle> --keys keys.json <effect_id>
//	csverify reconcile-trace FILE [--packs DIR]
//	csverify reconcile-batch FILE [--packs DIR]
//	csverify reconcile-corpus DIR [--packs DIR]
//
// --reconcile adds step V16 (spec/04 §6.5): every recorded class,
// condition, attribution and decision field is recomputed from the
// records and the bundled policy; disagreements are F_* findings.
// The reconcile-* subcommands run the same engine on the abstract trace
// form of docs/refreconcile.md (corpus, differential and audit harnesses).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/ledger"
	"github.com/countersign/countersign/internal/reconcile"
)

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}

// writeLine writes one line to w. The command's stdout is its product:
// a failed write must fail the command, never exit 0 with output lost.
func writeLine(w io.Writer, s string) error {
	_, err := fmt.Fprintln(w, s)
	return err
}

// writeJSONTo marshals v indented and writes it to w.
func writeJSONTo(w io.Writer, v any) error {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeLine(w, string(out))
}

func writeJSON(v any) {
	if err := writeJSONTo(os.Stdout, v); err != nil {
		fatal(err)
	}
}

// reconcileReadBundle and reconcileRun are the V16 inputs — package vars
// so tests can inject a failure and prove a CLEAN-class verdict is never
// returned without reconciliation having run.
var reconcileReadBundle = ledger.ReadBundle
var reconcileRun = reconcile.ReconcileBundle

// applyReconcile runs step V16 of 03 §10. Any failure to re-read the
// bundle or to reconcile lands in Errors and forces INVALID: --reconcile
// may never report a CLEAN-class verdict it did not compute.
func applyReconcile(res *ledger.VerifyResult, bundle []byte) {
	members, err := reconcileReadBundle(bundle)
	if err != nil {
		res.Errors = append(res.Errors,
			ledger.Finding{Code: "E_BUNDLE", Detail: fmt.Sprintf("reconcile: %v", err)})
		res.Verdict = "INVALID"
		return
	}
	rc, err := reconcileRun(members, nil)
	if err != nil {
		res.Errors = append(res.Errors,
			ledger.Finding{Code: "E_POLICY", Detail: fmt.Sprintf("reconcile: %v", err)})
		res.Verdict = "INVALID"
		return
	}
	mergeReconcile(res, rc)
}

// verdict merges the reconciliation findings into the base verdict
// (03 §10: findings sit between LEARN and CLEAN_WITH_DENIALS).
func mergeReconcile(res *ledger.VerifyResult, rc *reconcile.Result) {
	res.Findings = make([]ledger.Finding, 0, len(rc.Findings))
	for _, f := range rc.Findings {
		detail := f.Detail
		if f.Effect != nil {
			detail = fmt.Sprintf("effect %v: %s", f.Effect, f.Detail)
		}
		res.Findings = append(res.Findings,
			ledger.Finding{Code: f.Code, Detail: detail})
	}
	errs := 0
	for _, f := range rc.Findings {
		if f.Severity == "error" {
			errs++
		}
	}
	switch res.Verdict {
	case "INVALID", "UNSEALED", "LEARN":
		// The lattice is unchanged at these levels.
	default:
		switch {
		case errs > 0:
			res.Verdict = "VIOLATIONS"
		case rc.Denials > 0:
			res.Verdict = "CLEAN_WITH_DENIALS"
		default:
			// Keep the base verdict (CLEAN or CLEAN_WITH_DENIALS).
		}
	}
	res.Stats["reconcile_effects"] = len(rc.Effects)
	res.Stats["reconcile_findings"] = len(rc.Findings)
}

func cmdVerify(args []string) {
	os.Exit(runVerify(args, os.Stdout))
}

// runVerify is `csverify <bundle> --keys keys.json [--reconcile]` with
// the result writer passed in: 0 for CLEAN/CLEAN_WITH_DENIALS, 1 for
// any other verdict, 2 for usage/read/write failure.
func runVerify(args []string, stdout io.Writer) int {
	// The spec's order has the positional first, so parse flags by hand.
	var keysPath string
	var doReconcile bool
	rest := []string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--keys" && i+1 < len(args):
			keysPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--keys="):
			keysPath = a[len("--keys="):]
		case a == "--reconcile":
			doReconcile = true
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) != 1 || keysPath == "" {
		fmt.Fprintln(os.Stderr, "usage: csverify <bundle> --keys keys.json [--reconcile]")
		return 2
	}
	bundle, err := os.ReadFile(rest[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	m, err := keys.LoadManifest(keysPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	res := ledger.VerifyBundle(bundle, m)
	if doReconcile {
		applyReconcile(res, bundle)
	}
	if err := writeJSONTo(stdout, res); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if res.Verdict == "CLEAN" || res.Verdict == "CLEAN_WITH_DENIALS" {
		return 0
	}
	return 1
}

// cmdExplain prints the recorded vs recomputed attribution of one effect
// (spec/04 §6.5): the recomputed values stand on their own; the findings
// list names every disagreement.
func cmdExplain(args []string) {
	os.Exit(runExplain(args, os.Stdout))
}

func runExplain(args []string, stdout io.Writer) int {
	var keysPath string
	rest := []string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--keys" && i+1 < len(args):
			keysPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--keys="):
			keysPath = a[len("--keys="):]
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) != 2 || keysPath == "" {
		fmt.Fprintln(os.Stderr, "usage: csverify explain <bundle> --keys keys.json <effect_id>")
		return 2
	}
	bundle, err := os.ReadFile(rest[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if _, err := keys.LoadManifest(keysPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	effectID := rest[1]
	members, err := ledger.ReadBundle(bundle)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	meta, records, err := reconcile.BundleInput(members)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	rc, err := reconcile.Reconcile(meta, records, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var recorded map[string]any
	for _, r := range records {
		if fmt.Sprintf("%v", r["effect_id"]) == effectID {
			recorded = r
			break
		}
	}
	var effFindings []reconcile.Finding
	for _, f := range rc.Findings {
		if fmt.Sprintf("%v", f.Effect) == effectID {
			effFindings = append(effFindings, f)
		}
	}
	if effFindings == nil {
		effFindings = []reconcile.Finding{}
	}
	out := map[string]any{
		"effect_id":  effectID,
		"verdict":    rc.Verdict,
		"recomputed": rc.Effects[effectID],
		"findings":   effFindings,
	}
	if recorded != nil {
		out["recorded"] = map[string]any{
			"class":       recorded["class"],
			"decision":    recorded["decision"],
			"attribution": recorded["attribution"],
		}
	}
	if rc.Effects[effectID] == nil && recorded == nil {
		out["error"] = "no such effect"
	}
	if err := writeJSONTo(stdout, out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return 0
}

func cmdReconcileTrace(path, packsDir string) {
	packs, err := reconcile.LoadPacks(packsDir)
	if err != nil {
		fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		fatal(err)
	}
	defer func() { _ = f.Close() }()
	meta, records, err := reconcile.ParseTrace(f)
	if err != nil {
		fatal(err)
	}
	res, err := reconcile.Reconcile(meta, records, packs)
	if err != nil {
		fatal(err)
	}
	writeJSON(res)
}

// cmdReconcileBatch reads a JSONL file of {"meta","records"} lines and
// writes one result object per line — the differential harness.
func cmdReconcileBatch(path, packsDir string) {
	os.Exit(runReconcileBatch(path, packsDir, os.Stdout))
}

// runReconcileBatch is cmdReconcileBatch with the output writer passed
// in, so a test can inject a failing writer: a write error exits 2, a
// reconciled-line error exits 1, a clean run exits 0.
func runReconcileBatch(path, packsDir string, stdout io.Writer) int {
	packs, err := reconcile.LoadPacks(packsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	w := bufio.NewWriter(stdout)
	bad := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		meta, records, err := reconcile.ParseTraceLine(line)
		var res *reconcile.Result
		if err == nil {
			res, err = reconcile.Reconcile(meta, records, packs)
		}
		var b []byte
		if err != nil {
			bad = true
			b, err = json.Marshal(map[string]any{"error": err.Error()})
		} else {
			b, err = json.Marshal(res)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if _, err := fmt.Fprintln(w, string(b)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if bad {
		return 1
	}
	return 0
}

// cmdReconcileCorpus runs every *.jsonl trace in dir and diffs the
// recomputed result against the trace.meta expect block (same rule as
// the reference's `corpus` command).
func cmdReconcileCorpus(dir, packsDir string) {
	os.Exit(runReconcileCorpus(dir, packsDir, os.Stdout))
}

func runReconcileCorpus(dir, packsDir string, stdout io.Writer) int {
	packs, err := reconcile.LoadPacks(packsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	fails := 0
	out := func(format string, args ...any) error {
		return writeLine(stdout, fmt.Sprintf(format, args...))
	}
	for _, name := range names {
		path := dir + "/" + name
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		meta, records, err := reconcile.ParseTrace(f)
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintln(os.Stderr, cerr)
			return 2
		}
		var diffs []string
		if err != nil {
			diffs = []string{err.Error()}
		} else {
			var res *reconcile.Result
			res, err = reconcile.Reconcile(meta, records, packs)
			if err != nil {
				diffs = []string{"exception " + err.Error()}
			} else {
				diffs = compareExpected(meta, res)
			}
		}
		var werr error
		if len(diffs) > 0 {
			fails++
			werr = out("%-40s %s", name, strings.Join(diffs[:firstN(3, len(diffs))], "; "))
		} else {
			werr = out("%-40s ok", name)
		}
		if werr != nil {
			fmt.Fprintln(os.Stderr, werr)
			return 2
		}
	}
	var line string
	if fails > 0 {
		line = fmt.Sprintf("corpus: %d/%d traces FAILED", fails, len(names))
	} else {
		line = fmt.Sprintf("corpus: all %d traces as expected", len(names))
	}
	if err := writeLine(stdout, line); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if fails > 0 {
		return 1
	}
	return 0
}

func firstN(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// compareExpected diffs trace.meta.expect against the recomputed result.
func compareExpected(meta map[string]any, res *reconcile.Result) []string {
	var diffs []string
	exp, _ := meta["expect"].(map[string]any)
	ee, _ := exp["effects"].(map[string]any)
	for rid, wv := range ee {
		want, _ := wv.(map[string]any)
		got := res.Effects[rid]
		if got == nil {
			diffs = append(diffs, fmt.Sprintf("effect %s: expected but absent", rid))
			continue
		}
		for k, v := range want {
			gv := got[k]
			if !expectEqual(v, gv) {
				diffs = append(diffs, fmt.Sprintf("effect %s.%s: want %v got %v", rid, k, v, gv))
			}
		}
	}
	if len(ee) > 0 {
		for rid := range res.Effects {
			if _, ok := ee[rid]; !ok {
				diffs = append(diffs, fmt.Sprintf("effect %s: produced but not expected", rid))
			}
		}
	}
	wantF := map[string]int{}
	for _, fv := range toList(exp["findings"]) {
		fm, _ := fv.(map[string]any)
		key := fmt.Sprintf("%v|%v", fm["code"], nilIfMissing(fm["effect"]))
		wantF[key]++
	}
	gotF := map[string]int{}
	for _, f := range res.Findings {
		key := fmt.Sprintf("%v|%v", f.Code, nilIfMissing(f.Effect))
		gotF[key]++
	}
	if !mapsEqual(wantF, gotF) {
		diffs = append(diffs, fmt.Sprintf("findings: want %v got %v", sortedKeys(wantF), sortedKeys(gotF)))
	}
	if v, ok := exp["verdict"]; ok && v != res.Verdict {
		diffs = append(diffs, fmt.Sprintf("verdict: want %v got %v", v, res.Verdict))
	}
	return diffs
}

func toList(v any) []any {
	l, _ := v.([]any)
	return l
}

func nilIfMissing(v any) any {
	if v == nil {
		return ""
	}
	return v
}

func mapsEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]int) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// expectEqual compares an expected field (numbers as json.Number or
// float64) with a computed one.
func expectEqual(want, got any) bool {
	w, werr := json.Marshal(want)
	g, gerr := json.Marshal(got)
	if werr != nil || gerr != nil {
		return false
	}
	// Normalize: numbers compare by value.
	var wn, gn any
	if err := json.Unmarshal(w, &wn); err != nil {
		return false
	}
	if err := json.Unmarshal(g, &gn); err != nil {
		return false
	}
	return deepEq(wn, gn)
}

func deepEq(a, b any) bool {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, v := range av {
			if !deepEq(v, bv[k]) {
				return false
			}
		}
		return true
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !deepEq(av[i], bv[i]) {
				return false
			}
		}
		return true
	}
	return a == b
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: csverify <bundle> --keys keys.json [--reconcile]\n"+
			"       csverify explain <bundle> --keys keys.json <effect_id>\n"+
			"       csverify reconcile-trace FILE [--packs DIR]\n"+
			"       csverify reconcile-batch FILE [--packs DIR]\n"+
			"       csverify reconcile-corpus DIR [--packs DIR]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	switch cmd {
	case "explain":
		cmdExplain(args)
	case "reconcile-trace", "reconcile-batch", "reconcile-corpus":
		var packsDir string
		rest := []string{}
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "--packs" && i+1 < len(args):
				packsDir = args[i+1]
				i++
			case strings.HasPrefix(a, "--packs="):
				packsDir = a[len("--packs="):]
			default:
				rest = append(rest, a)
			}
		}
		if len(rest) != 1 {
			fmt.Fprintf(os.Stderr, "usage: csverify %s PATH [--packs DIR]\n", cmd)
			os.Exit(2)
		}
		switch cmd {
		case "reconcile-trace":
			cmdReconcileTrace(rest[0], packsDir)
		case "reconcile-batch":
			cmdReconcileBatch(rest[0], packsDir)
		case "reconcile-corpus":
			cmdReconcileCorpus(rest[0], packsDir)
		}
	default:
		cmdVerify(os.Args[1:])
	}
}
