// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// The reconciliation engine: spec/04 §5 (intents), §6 (levels, inline
// decision, offline recomputation) and §7 (MCP server sessions), on the
// abstract trace of docs/refreconcile.md.
//
// Ordering is log order and log order only: an intent is open from its
// intent.declared record until its intent.result record or the session
// seal. Timestamps are used for exactly one thing — the §7.1
// startup-grace duration — and never for ordering.
package reconcile

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// networkClasses are the intent classes that can authorize network
// effects (spec/04 §5.2); "local" cannot.
var networkClasses = map[string]bool{"exec": true, "http": true, "mcp": true, "other": true}

// intentOK are the levels that satisfy an intent condition, per
// intentMatch (spec/04 §6.4).
var intentOK = map[string]map[string]bool{
	"window": {"EXACT": true, "WINDOW": true, "CONTROL": true},
	"exact":  {"EXACT": true, "CONTROL": true},
}

var severity = map[string]string{
	"F_ATTRIBUTION_MISMATCH": "error", "F_DECISION_MISMATCH": "error",
	"F_UNATTRIBUTED": "error", "F_CREDENTIAL_SCOPE": "error",
	"F_CLASS_MISMATCH": "error", "F_CONTRACT_STARTUP": "error",
	"F_CONTRACT_IDLE": "error", "F_CONTRACT_PATTERN": "error",
	"F_CONTRACT_MAX_EFFECTS": "error", "F_CONTRACT_ANNOTATION": "error",
}

// Finding is one reconciliation finding (03 §10).
type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Effect   any    `json:"effect"`
	Detail   string `json:"detail"`
}

func finding(code string, effect any, format string, args ...any) Finding {
	sev, ok := severity[code]
	if !ok {
		sev = "error"
	}
	return Finding{code, sev, effect, fmt.Sprintf(format, args...)}
}

// TraceError marks a structurally malformed trace (mirrors the reference).
type TraceError struct{ msg string }

func (e *TraceError) Error() string { return e.msg }

func parseTS(s any) *time.Time {
	str, ok := s.(string)
	if !ok {
		return nil
	}
	for _, f := range []string{time.RFC3339Nano, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(f, str); err == nil {
			return &t
		}
	}
	return nil
}

// intent is one open-or-closed declared intent (spec/04 §5.2).
type intent struct {
	id       any
	tool     string
	cls      string
	executor string
	input    map[string]any
	inputSHA string
	open     bool
	consumed bool
	expects  []map[string]any
	order    int
}

func newIntent(r rec, order int, packs []map[string]any, commandField string) (*intent, error) {
	input, _ := mget(r, "input").(map[string]any)
	if input == nil {
		input = map[string]any{}
	}
	sha := str(mget(r, "input_sha256"))
	if sha == "" {
		var err error
		sha, err = CanonSHA256(input)
		if err != nil {
			return nil, err
		}
	}
	executor := strOr(mget(r, "executor"), "sandbox")
	if executor == "" {
		executor = "sandbox"
	}
	i := &intent{
		id:       mget(r, "intent_id"),
		tool:     strOr(mget(r, "tool"), ""),
		cls:      strOr(mget(r, "class"), ""),
		executor: executor,
		input:    input,
		inputSHA: sha,
		open:     executor == "sandbox", // 04 §5.3: provider intents never open
		order:    order,
	}
	i.expects = intentExpectations(i.cls, i.tool, i.input, commandField, packs)
	return i, nil
}

// call is one in-flight MCP tools/call on the server session.
type call struct {
	id          any
	tool        string
	args        map[string]any
	effectsUsed int
	order       int
}

type session struct {
	kind, mode   string
	policy       map[string]any
	contract     map[string]any
	openTS       *time.Time
	intents      map[string]*intent
	intentOrder  []*intent
	calls        map[string]*call
	callOrder    []string
	toolsAnn     map[string]map[string]any
	sealed       bool
	denials      int
	effects      int
	commandField string
	mcpServers   map[string]map[string]any
	mcpOrder     []string // server names in grant document order
	packs        []map[string]any
}

// Result is the reconciliation result of one trace/session.
type Result struct {
	Effects  map[string]map[string]any `json:"effects"`
	Findings []Finding                 `json:"findings"`
	Verdict  string                    `json:"verdict"`
	Denials  int                       `json:"-"`
}

func keyOf(v any) string {
	s, err := CanonString(v)
	if err != nil {
		return fmt.Sprintf("%#v", v)
	}
	return s
}

func openNetworkIntents(st *session) []*intent {
	var out []*intent
	for _, i := range st.intentOrder {
		if i.open && networkClasses[i.cls] {
			out = append(out, i)
		}
	}
	return out
}

// mapMCPTool maps an intent tool name to (server, tool) per 04 §6.3
// mcpNaming (only the default mcp__<server>__<tool> is defined).
func mapMCPTool(st *session, toolName string) (string, string, bool) {
	naming := strOr(mget(st.policy, "mcpNaming"), "")
	if naming == "" {
		naming = "mcp__<server>__<tool>"
	}
	if naming != "mcp__<server>__<tool>" {
		return "", "", false
	}
	if len(toolName) < 5 || toolName[:5] != "mcp__" {
		return "", "", false
	}
	rest := toolName[5:]
	for _, srv := range st.mcpOrder {
		pre := srv + "__"
		if len(rest) > len(pre) && rest[:len(pre)] == pre {
			return srv, rest[len(pre):], true
		}
	}
	return "", "", false
}

// matchToolCall is 04 §6.3: the open mcp-class intent that names this
// (server, tool) with the same canonical-argument digest and has not
// matched a call before.
func matchToolCall(st *session, grant map[string]any, mcp map[string]any) (*intent, error) {
	server := str(orValue(mget(mcp, "server"), mget(grant, "server")))
	tool := str(mget(mcp, "tool"))
	argsSHA := str(mget(mcp, "arguments_sha256"))
	if argsSHA == "" {
		var err error
		argsSHA, err = CanonSHA256(orValue(mget(mcp, "arguments"), map[string]any{}))
		if err != nil {
			return nil, err
		}
	}
	for _, i := range st.intentOrder {
		if !i.open || i.consumed || i.cls != "mcp" {
			continue
		}
		srv, tl, ok := mapMCPTool(st, i.tool)
		if !ok || srv != server || tl != tool {
			continue
		}
		if i.inputSHA != argsSHA {
			continue
		}
		return i, nil
	}
	return nil, nil
}

// level computes spec/04 §6.1/§6.3 attribution level and intent list.
func level(st *session, grant map[string]any, req map[string]any, mcp map[string]any) (string, []any, string, error) {
	if str(mget(grant, "inspect")) == "inference" {
		return "CONTROL", []any{}, "", nil
	}
	if str(mget(grant, "inspect")) == "mcp" && mcp != nil &&
		str(mget(mcp, "method")) != "tools/call" {
		return "CONTROL", []any{}, "", nil // 04 §6.1: protocol messages
	}
	if mcp != nil && str(mget(mcp, "method")) == "tools/call" {
		server := str(orValue(mget(mcp, "server"), mget(grant, "server")))
		if _, ok := st.mcpServers[server]; ok {
			i, err := matchToolCall(st, grant, mcp)
			if err != nil {
				return "", nil, "", err
			}
			if i != nil {
				i.consumed = true
				return "EXACT", []any{i.id}, "", nil
			}
			return "NONE", []any{}, "undeclared-call", nil
		}
	}
	openI := openNetworkIntents(st)
	var exacts []any
	for _, i := range openI {
		for _, e := range i.expects {
			if expectationMatches(e, req, grant) {
				exacts = append(exacts, i.id)
				break
			}
		}
	}
	if len(exacts) > 0 {
		return "EXACT", exacts, "", nil
	}
	if len(openI) > 0 {
		ids := make([]any, 0, len(openI))
		for _, i := range openI {
			ids = append(ids, i.id)
		}
		return "WINDOW", ids, "", nil
	}
	if str(mget(grant, "requires")) == "none" {
		return "STANDING", []any{}, "", nil
	}
	return "NONE", []any{}, "", nil
}

// proceed is the per-class action when the condition lets the effect
// through (05 §2).
func proceed(cls string) (string, string) {
	if cls == "staged" {
		return "stage", "STAGED"
	}
	return "allow", "OK"
}

// decide implements spec/04 §6.4 + 05 §2 enforce semantics.
func decide(grant map[string]any, cond, cls, lvl, lreason string) (action, reason string, noAuto bool) {
	if cond == "deny" {
		return "deny", "AUTONOMY_DENY", false
	}
	if cond == "review" && cls != "control" {
		// 05 §1: control effects are never staged, held or undone.
		if cls == "staged" {
			return "stage", "STAGED", true
		}
		return "hold", "REVIEW_REQUIRED", false
	}
	if cond == "intent" {
		ok := intentOK[strOr(mget(grant, "intentMatch"), "")]
		if ok == nil {
			ok = intentOK["window"]
		}
		if !ok[lvl] {
			if lreason == "undeclared-call" {
				return "deny", "UNDECLARED_TOOL_CALL", false
			}
			return "deny", "NO_INTENT", false
		}
	}
	a, r := proceed(cls)
	return a, r, false
}

// result accumulates the recomputed values for one effect.
type effectResult map[string]any

// claim is which broker claims a record actually carries. On the abstract
// trace any of class/decision/attribution present activates all compares
// (the reference's rule); on real evidence the record type fixes the
// scope (effect.tunnel can only record a decision).
type claim struct{ class, decision, attribution bool }

func claimOf(r rec) (claim, bool) {
	if c, ok := r["x-claim"].(claim); ok {
		return c, true
	}
	return claim{has(r, "class"), has(r, "decision"), has(r, "attribution")}, false
}

// compareRecorded is spec/04 §6.5: compare the recorded broker fields
// with the recomputation. An effect record carrying no
// decision/attribution/class makes no broker claim and is skipped.
func compareRecorded(r rec, res effectResult, findings *[]Finding) {
	cl, explicit := claimOf(r)
	if !explicit {
		if !cl.class && !cl.decision && !cl.attribution {
			return
		}
		cl = claim{true, true, true}
	}
	rid := mget(r, "effect_id")
	dec := mdict(r, "decision")
	att := mdict(r, "attribution")
	if cl.class {
		if rc := mget(r, "class"); !sameValue(nilIfEmpty(rc), res["class"]) {
			*findings = append(*findings, finding("F_CLASS_MISMATCH", rid,
				"class %v recorded, %v recomputed", rc, res["class"]))
		}
	}
	if cl.decision {
		if !sameValue(nilIfEmpty(mget(dec, "requires")), res["condition"]) {
			*findings = append(*findings, finding("F_CLASS_MISMATCH", rid,
				"condition %v recorded, %v recomputed", mget(dec, "requires"), res["condition"]))
		}
	}
	if cl.attribution {
		recI := mget(att, "intents")
		if !truthy(recI) {
			recI = []any{}
		}
		gotI := res["intents"]
		if gotI == nil {
			gotI = []any{}
		}
		if !sameValue(nilIfEmpty(mget(att, "level")), res["level"]) ||
			!jsonDeepEqual(recI, gotI) {
			*findings = append(*findings, finding("F_ATTRIBUTION_MISMATCH", rid,
				"attribution (%v,%v) recorded, (%v,%v) recomputed",
				mget(att, "level"), mget(att, "intents"), res["level"], res["intents"]))
		}
	}
	if cl.decision {
		if !sameValue(nilIfEmpty(mget(dec, "grant")), res["grant"]) {
			*findings = append(*findings, finding("F_DECISION_MISMATCH", rid,
				"grant %v recorded, %v recomputed", mget(dec, "grant"), res["grant"]))
		}
		if !sameValue(nilIfEmpty(mget(dec, "action")), res["action"]) ||
			!sameValue(nilIfEmpty(mget(dec, "reason")), res["reason"]) ||
			!sameValue(nilIfEmpty(mget(dec, "would_deny")), res["would_deny"]) {
			*findings = append(*findings, finding("F_DECISION_MISMATCH", rid,
				"decision (%v,%v,would_deny=%v) recorded, (%v,%v,would_deny=%v) recomputed",
				mget(dec, "action"), mget(dec, "reason"), mget(dec, "would_deny"),
				res["action"], res["reason"], res["would_deny"]))
		}
		if truthy(mget(dec, "credentials")) && !truthy(res["grant_has_credential"]) {
			*findings = append(*findings, finding("F_CREDENTIAL_SCOPE", rid,
				"credential recorded on a grant without one"))
		}
	}
	// 04 §6.5: an effect the broker allowed (or that recomputation allows)
	// with level NONE under an intent condition is unattributed.
	acted := res["action"]
	if has(r, "decision") {
		acted = mget(dec, "action")
	}
	if acted == "allow" && res["level"] == "NONE" &&
		res["condition"] == "intent" && res["mode"] != "learn" {
		*findings = append(*findings, finding("F_UNATTRIBUTED", rid,
			"allowed effect with no qualifying intent"))
	}
}

// nilIfEmpty maps a falsy scalar to nil (Python `x or None` for the
// recorded-field comparisons where "" and absent are the same claim).
func nilIfEmpty(v any) any {
	if !truthy(v) {
		return nil
	}
	return v
}

// evalEffect recomputes one sandbox effect.http (agent session).
func evalEffect(st *session, r rec, findings *[]Finding) (effectResult, error) {
	req := mdict(r, "request")
	if req == nil {
		req = map[string]any{}
	}
	grant, greason := selectGrant(st.policy, req)
	res := effectResult{
		"grant":                grantID(grant),
		"grant_has_credential": grant != nil && truthy(mget(grant, "credential")),
		"class":                nil,
		"condition":            nil,
		"level":                "NONE",
		"intents":              []any{},
		"action":               "deny",
		"reason":               orValue(greason, "NO_GRANT"),
		"would_deny":           nil,
		"mode":                 st.mode,
	}
	if greason != "" {
		// 04 §6.4: DENY_GRANT and SMUGGLING_SUSPECT deny in every mode;
		// audit and learn admit a NO_GRANT request so the failure is
		// observed.
		if greason == "NO_GRANT" && st.mode == "audit" {
			res["action"] = "allow"
			res["reason"] = "OK"
			res["would_deny"] = map[string]any{"action": "deny", "reason": "NO_GRANT"}
		} else if greason == "NO_GRANT" && st.mode == "learn" {
			res["action"] = "allow"
			res["reason"] = "OK"
		}
	} else {
		cls := classify(grant, req)
		cond, err := condition(st.policy, grant, cls)
		if err != nil {
			return nil, err
		}
		lvl, intents, lr, err := level(st, grant, req, mdict(req, "mcp"))
		if err != nil {
			return nil, err
		}
		a, rsn, na := decide(grant, cond, cls, lvl, lr)
		switch st.mode {
		case "audit":
			var wd any
			if a == "deny" || a == "hold" {
				wd = map[string]any{"action": a, "reason": rsn}
				a = "allow"
			}
			res["class"] = cls
			res["condition"] = cond
			res["level"] = lvl
			res["intents"] = intents
			res["action"] = a
			res["reason"] = "OK"
			res["would_deny"] = wd
		case "learn":
			// 04 §6.4: everything not hitting a deny grant is allowed.
			res["class"] = cls
			res["condition"] = cond
			res["level"] = lvl
			res["intents"] = intents
			res["action"] = "allow"
			res["reason"] = "OK"
		default:
			res["class"] = cls
			res["condition"] = cond
			res["level"] = lvl
			res["intents"] = intents
			res["action"] = a
			res["reason"] = rsn
			if na {
				res["no_auto"] = true
			}
		}
	}
	compareRecorded(r, res, findings)
	if res["action"] == "deny" {
		st.denials++
	}
	st.effects++
	return res, nil
}

func grantID(grant map[string]any) any {
	if grant == nil {
		return nil
	}
	return mget(grant, "id")
}

// --------------------------------------------------------------------------
// Scenario S2 (spec/04 §7): the MCP server's own session.

// pctSeg percent-encodes one path-segment substitution (04 §7.1): every
// byte outside the unreserved set becomes %XX.
func pctSeg(v any) string {
	var b strings.Builder
	for _, c := range []byte(fmt.Sprintf("%v", v)) {
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// patternMatch matches one contract effect pattern {host, method, path}
// where path segments that are exactly {arguments.X} bind the in-flight
// call's args.
func patternMatch(pat map[string]any, req map[string]any, args map[string]any) bool {
	host, _ := splitAuthority(str(mget(req, "authority")), 443)
	if v := mget(pat, "host"); v != nil && normHost(host) != normHost(str(v)) {
		return false
	}
	if v := mget(pat, "method"); v != nil && str(mget(req, "method")) != str(v) {
		return false
	}
	tmpl := mget(pat, "path")
	if tmpl == nil {
		return true
	}
	tsegs := strings.Split(str(tmpl), "/")
	rsegs := strings.Split(strOr(mget(req, "path"), "/"), "/")
	if len(tsegs) != len(rsegs) {
		return false
	}
	for i, t := range tsegs {
		r := rsegs[i]
		if strings.HasPrefix(t, "{arguments.") && strings.HasSuffix(t, "}") {
			key := t[len("{arguments.") : len(t)-1]
			v, ok := args[key].(string)
			if !ok {
				return false // non-string/missing: unmatchable
			}
			if pctSeg(v) != pctDecodeUnres(r) {
				return false
			}
		} else if pctDecodeUnres(t) != pctDecodeUnres(r) {
			return false
		}
	}
	return true
}

func contractFor(st *session, tool string) map[string]any {
	return mdict(mdict(mdict(st.contract, "spec"), "tools"), tool)
}

// evalServerEffect runs the 04 §7.3 checks on one server-session effect.
func evalServerEffect(st *session, r rec, findings *[]Finding) (effectResult, error) {
	req := mdict(r, "request")
	if req == nil {
		req = map[string]any{}
	}
	rid := mget(r, "effect_id")
	grant, greason := selectGrant(st.policy, req)
	res := effectResult{
		"grant":                grantID(grant),
		"grant_has_credential": grant != nil && truthy(mget(grant, "credential")),
		"class":                nil,
		"condition":            nil,
		"level":                "NONE",
		"intents":              []any{},
		"action":               "deny",
		"reason":               orValue(greason, "NO_GRANT"),
		"would_deny":           nil,
		"mode":                 st.mode,
	}
	if greason == "" {
		cls := classify(grant, req)
		cond, err := condition(st.policy, grant, cls)
		if err != nil {
			return nil, err
		}
		res["class"] = cls
		res["condition"] = cond
		contract := mdict(st.contract, "spec")

		inFlight := make([]*call, 0, len(st.calls))
		for _, c := range st.calls {
			inFlight = append(inFlight, c)
		}
		sortCalls(inFlight)

		// Check 1 — startup grace: within graceSeconds of session.open the
		// effect must match a startup.effects pattern. (The only ts use
		// anywhere: a duration bound, never an ordering.)
		inGrace := false
		if grace := mget(mdict(contract, "startup"), "graceSeconds"); grace != nil {
			gn, gok := jsonNum(grace)
			if ets, ots := parseTS(mget(r, "ts")), st.openTS; gok && ets != nil && ots != nil {
				d := ets.Sub(*ots).Seconds()
				inGrace = d >= 0 && d < gn
			}
		}

		violation := false
		if inGrace {
			matched := false
			for _, p := range asList(mget(mdict(contract, "startup"), "effects")) {
				if pm, ok := p.(map[string]any); ok && patternMatch(pm, req, nil) {
					matched = true
				}
			}
			if !matched {
				*findings = append(*findings, finding("F_CONTRACT_STARTUP", rid,
					"effect inside startup grace matches no startup.effects pattern"))
				res["action"] = "deny"
				res["reason"] = "CONTRACT_VIOLATION"
				violation = true
			}
		} else if len(inFlight) == 0 {
			// Check 2 — no call in flight: contract idle rule, else the
			// 05 §12 default (deny everything but safe/control outside a
			// call).
			idleDeny := cls != "safe" && cls != "control"
			if len(contract) > 0 {
				idleDeny = strOr(mget(contract, "idle"), "deny") == "deny"
			}
			if idleDeny {
				if len(contract) > 0 {
					*findings = append(*findings, finding("F_CONTRACT_IDLE", rid,
						"effect with no call in flight"))
				}
				res["action"] = "deny"
				res["reason"] = "EFFECT_OUTSIDE_CALL"
				violation = true
			}
		} else if len(contract) > 0 {
			// Check 3 — the effect must match a pattern of some in-flight
			// call's contract entry and keep that call within maxEffects.
			var matched *call
			overCap := false
			for _, c := range inFlight {
				entry := contractFor(st, c.tool)
				ok := false
				for _, p := range asList(mget(entry, "effects")) {
					if pm, ism := p.(map[string]any); ism && patternMatch(pm, req, c.args) {
						ok = true
					}
				}
				if !ok {
					continue
				}
				maxe := mget(entry, "maxEffects")
				if maxe == nil {
					matched = c
					break
				}
				mn, mok := jsonNum(maxe)
				if !mok || float64(c.effectsUsed) < mn {
					matched = c
					break
				}
				overCap = true
			}
			if matched != nil {
				matched.effectsUsed++
			} else {
				code := "F_CONTRACT_PATTERN"
				detail := "no in-flight call's pattern matches"
				if overCap {
					code = "F_CONTRACT_MAX_EFFECTS"
					detail = "in-flight calls admit no matching pattern under maxEffects"
				}
				*findings = append(*findings, finding(code, rid, "%s", detail))
				res["action"] = "deny"
				res["reason"] = "CONTRACT_VIOLATION"
				violation = true
			}
		}

		// Check 4 — annotation check, independent of any contract: a
		// non-GET/HEAD effect while every in-flight call's tool is
		// advertised readOnlyHint.
		if !violation && len(inFlight) > 0 && st.toolsAnn != nil {
			allRO := true
			for _, c := range inFlight {
				if mget(st.toolsAnn[c.tool], "readOnlyHint") != true {
					allRO = false
				}
			}
			m := str(mget(req, "method"))
			if allRO && m != "GET" && m != "HEAD" {
				*findings = append(*findings, finding("F_CONTRACT_ANNOTATION", rid,
					"write during read-only tool call"))
				res["action"] = "deny"
				res["reason"] = "ANNOTATION_VIOLATION"
				violation = true
			}
		}

		if !violation {
			a, rsn, _ := decide(grant, cond, cls, "NONE", "")
			res["action"] = a
			res["reason"] = rsn
		}
	}
	compareServer(r, res, findings)
	if res["action"] == "deny" {
		st.denials++
	}
	st.effects++
	return res, nil
}

// compareServer is the server-session §6.5 compare: class, condition,
// attribution (must be NONE/empty when recorded), grant, action+reason
// and credentials. Server effects never carry would_deny or intents.
func compareServer(r rec, res effectResult, findings *[]Finding) {
	cl, explicit := claimOf(r)
	if !explicit {
		if !cl.class && !cl.decision && !cl.attribution {
			return
		}
		cl = claim{true, true, has(r, "attribution")}
	}
	rid := mget(r, "effect_id")
	dec := mdict(r, "decision")
	att := mdict(r, "attribution")
	if cl.class {
		if rc := mget(r, "class"); !sameValue(nilIfEmpty(rc), res["class"]) {
			*findings = append(*findings, finding("F_CLASS_MISMATCH", rid,
				"class %v recorded, %v recomputed", rc, res["class"]))
		}
	}
	if cl.decision {
		if !sameValue(nilIfEmpty(mget(dec, "requires")), res["condition"]) {
			*findings = append(*findings, finding("F_CLASS_MISMATCH", rid,
				"condition %v recorded, %v recomputed", mget(dec, "requires"), res["condition"]))
		}
	}
	if cl.attribution {
		lvl := nilIfEmpty(mget(att, "level"))
		if lvl == nil {
			lvl = "NONE"
		}
		if lvl != "NONE" || truthy(mget(att, "intents")) {
			*findings = append(*findings, finding("F_ATTRIBUTION_MISMATCH", rid,
				"server-session effect carries intent attribution"))
		}
	}
	if cl.decision {
		if !sameValue(nilIfEmpty(mget(dec, "grant")), res["grant"]) {
			*findings = append(*findings, finding("F_DECISION_MISMATCH", rid,
				"grant %v recorded, %v recomputed", mget(dec, "grant"), res["grant"]))
		}
		if !sameValue(nilIfEmpty(mget(dec, "action")), res["action"]) ||
			!sameValue(nilIfEmpty(mget(dec, "reason")), res["reason"]) {
			*findings = append(*findings, finding("F_DECISION_MISMATCH", rid,
				"decision (%v,%v) recorded, (%v,%v) recomputed",
				mget(dec, "action"), mget(dec, "reason"), res["action"], res["reason"]))
		}
		if truthy(mget(dec, "credentials")) && !truthy(res["grant_has_credential"]) {
			*findings = append(*findings, finding("F_CREDENTIAL_SCOPE", rid,
				"credential recorded on a grant without one"))
		}
	}
}

func sortCalls(cs []*call) {
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].order < cs[j].order })
}

// ignoredTypes are records that are not inputs to §5–§7.
var ignoredTypes = map[string]bool{
	"sandbox.terminated": true, "world.closed": true, "emitter.seal": true,
	"context.observed": true, "taint.added": true, "stage.entry": true,
	"effect.http.result": true, "effect.tunnel.result": true,
	"commit.requested": true, "commit.decision": true, "commit.applied": true,
	"commit.closed": true, "prestate.captured": true, "undo.requested": true,
	"undo.applied": true, "undo.closed": true, "attestation.issued": true,
	"effect.exec": true, "effect.connect": true, "observer.gap": true,
	"intent.unknown": true, "replay.divergence": true, "world.rewound": true,
}

// Reconcile runs one trace: meta is the trace.meta object; records the
// record bodies in log order; packs the flattened §6.2 rule list (nil
// loads the packs embedded in the binary).
func Reconcile(meta map[string]any, records []rec, packs []map[string]any) (*Result, error) {
	if packs == nil {
		var err error
		if packs, err = LoadPacks(""); err != nil {
			return nil, err
		}
	}
	st := &session{
		kind:         "agent",
		mode:         "enforce",
		policy:       mdict(meta, "policy"),
		intents:      map[string]*intent{},
		calls:        map[string]*call{},
		mcpServers:   map[string]map[string]any{},
		packs:        packs,
		commandField: "command",
	}
	if st.policy == nil {
		st.policy = map[string]any{}
	}
	if cf := str(mget(st.policy, "commandField")); cf != "" {
		st.commandField = cf
	}
	for _, gv := range mlist(st.policy, "grants") {
		g, _ := gv.(map[string]any)
		srv := str(mget(g, "server"))
		if str(mget(g, "inspect")) == "mcp" && srv != "" {
			if _, seen := st.mcpServers[srv]; !seen {
				st.mcpOrder = append(st.mcpOrder, srv)
			}
			st.mcpServers[srv] = g
		}
	}
	contracts := mdict(meta, "contracts")
	st.contract = mdict(meta, "contract")
	if st.contract == nil && len(contracts) == 1 {
		for _, c := range contracts {
			st.contract, _ = c.(map[string]any)
		}
	}
	effects := map[string]map[string]any{}
	findings := []Finding{}
	for _, r := range records {
		t := str(mget(r, "type"))
		switch t {
		case "session.open":
			st.kind = strOr(mget(r, "kind"), "agent")
			if st.kind == "" {
				st.kind = "agent"
			}
			st.mode = str(orValue(mget(r, "mode"), orValue(mget(st.policy, "mode"), "enforce")))
			st.openTS = parseTS(mget(r, "ts"))
		case "intent.declared":
			iid := mget(r, "intent_id")
			if iid == nil {
				break
			}
			k := keyOf(iid)
			if _, dup := st.intents[k]; dup {
				break // 04 §5.2: not a new intent
			}
			i, err := newIntent(r, len(st.intentOrder), packs, st.commandField)
			if err != nil {
				return nil, err
			}
			st.intents[k] = i
			st.intentOrder = append(st.intentOrder, i)
		case "intent.result":
			if i, ok := st.intents[keyOf(mget(r, "intent_id"))]; ok {
				i.open = false
			}
		case "intent.unparsed":
			// 04 §5.4: nothing opens
		case "mcp.call.begin":
			cid := mget(r, "call_id")
			if cid == nil {
				break
			}
			k := keyOf(cid)
			if _, dup := st.calls[k]; dup {
				break
			}
			args, _ := orValue(mget(r, "contract_args"), mget(r, "arguments")).(map[string]any)
			if args == nil {
				args = map[string]any{}
			}
			st.calls[k] = &call{id: cid, tool: str(mget(r, "tool")),
				args: args, order: len(st.callOrder)}
			st.callOrder = append(st.callOrder, k)
		case "mcp.call.end":
			delete(st.calls, keyOf(mget(r, "call_id")))
		case "mcp.tools":
			st.toolsAnn = map[string]map[string]any{}
			for _, xv := range asList(mget(r, "tools")) {
				x, _ := xv.(map[string]any)
				if x == nil {
					continue
				}
				st.toolsAnn[str(mget(x, "name"))] = mdict(x, "annotations")
			}
		case "effect.http", "effect.tunnel":
			if str(mget(r, "actor")) == "world" {
				continue // world-side apply/sync: not §5–§7
			}
			if t == "effect.tunnel" {
				r = normalizeTunnel(r)
			}
			var res effectResult
			var err error
			if st.kind == "mcp-server" {
				res, err = evalServerEffect(st, r, &findings)
			} else {
				res, err = evalEffect(st, r, &findings)
			}
			if err != nil {
				return nil, err
			}
			effects[fmt.Sprintf("%v", mget(r, "effect_id"))] = stripNils(res)
		case "effect.denied":
			st.denials++
			st.effects++
		case "session.seal":
			st.sealed = true
			for _, i := range st.intentOrder {
				i.open = false // 04 §5.3: seal closes all
			}
		case "trace.meta":
			return nil, &TraceError{"trace.meta must be the first line only"}
		default:
			if ignoredTypes[t] {
				continue
			}
			return nil, &TraceError{fmt.Sprintf("unknown record type %q", t)}
		}
	}

	// Verdict lattice of 03 §10 (most severe first).
	errs := 0
	for _, f := range findings {
		if f.Severity == "error" {
			errs++
		}
	}
	var verdict string
	switch {
	case !st.sealed:
		verdict = "UNSEALED"
	case st.mode == "learn":
		verdict = "LEARN"
	case errs > 0:
		verdict = "VIOLATIONS"
	case st.denials > 0:
		verdict = "CLEAN_WITH_DENIALS"
	default:
		verdict = "CLEAN"
	}
	return &Result{Effects: effects, Findings: findings, Verdict: verdict, Denials: st.denials}, nil
}

// normalizeTunnel builds the synthetic request for an effect.tunnel
// record: authority, scheme, no method, root path, empty query, websocket
// marker.
func normalizeTunnel(r rec) rec {
	out := rec{}
	for k, v := range r {
		out[k] = v
	}
	scheme := strOr(mget(r, "scheme"), "https")
	if scheme == "" {
		scheme = "https"
	}
	out["request"] = map[string]any{
		"authority": mget(r, "authority"),
		"scheme":    scheme,
		"method":    nil,
		"path":      "/",
		"query":     "",
		"websocket": str(mget(r, "kind")) == "websocket",
	}
	// Real tunnel records carry SNI (spec/03 §4.2); in bundle mode it is
	// part of the smuggling pre-check. Abstract traces have no such field.
	if _, bundle := r["x-claim"]; bundle {
		if s := mget(r, "sni"); s != nil {
			out["request"].(map[string]any)["sni"] = s
		}
	}
	return out
}

// stripNils drops nil-valued keys (the reference's output filter).
func stripNils(r effectResult) map[string]any {
	out := map[string]any{}
	for k, v := range r {
		if v != nil {
			out[k] = v
		}
	}
	return out
}
