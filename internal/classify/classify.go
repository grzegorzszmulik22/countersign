// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Package classify implements spec/05 §1's ordered reversibility classes
// and §2's strictest condition for one grant-selected request, plus the
// declared_safe flag of §1 rule 2.
//
// The classifier is deterministic: no model and no state. It classifies a
// request after grant selection (04 §2); the broker wiring that records
// class and decision.requires on every effect is M2.4 (lane broker2).
package classify

import (
	"slices"
	"strconv"
	"strings"

	"github.com/countersign/countersign/internal/names"
	"github.com/countersign/countersign/internal/policy"
)

// readMethods are the methods classified safe by 05 §1 rule 6 and treated
// as non-writes by the outbox stager (05 §5).
var readMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}

// condOrder is 05 §2's strictness order (deny most strict).
var condOrder = map[string]int{"allow": 0, "intent": 1, "review": 2, "deny": 3}

var condName = []string{"allow", "intent", "review", "deny"}

// MCP is the parsed MCP message context the broker attaches to a request on
// an inspect:mcp grant (05 §1 rules 1, 7, 8).
type MCP struct {
	Method string `json:"method"` // JSON-RPC method; "tools/call" for a tool call
	Tool   string `json:"tool"`   // tool name for tools/call
}

// Request is the classification view of a request selected by a grant.
type Request struct {
	Method    string `json:"method"`
	Host      string `json:"host"` // host or host:port; normalized inside
	Path      string `json:"path"` // unreserved-decoded path as matched
	Query     string `json:"query"`
	WebSocket bool   `json:"websocket"` // request is a WebSocket upgrade (rule 3)
	Tunnel    bool   `json:"tunnel"`    // request travels a CONNECT tunnel (rule 2 flag)
	MCP       *MCP   `json:"mcp"`
}

// Decision is the 05 §1-§2 outcome for one effect.
type Decision struct {
	Class        string `json:"class"`         // control|safe|staged|compensable|irreversible
	Requires     string `json:"requires"`      // allow|intent|review|deny — condition imposed (§2)
	DeclaredSafe bool   `json:"declared_safe"` // §1 rule 2 flag
}

// Classify returns the class, the condition imposed and the declared_safe
// flag for a request selected by grant g under policy p. taint lists the
// session's current taint labels (04 §8).
func Classify(p *policy.SessionPolicy, g *policy.Grant, r *Request, taint []string) Decision {
	cls := class(g, r)
	return Decision{
		Class:    cls,
		Requires: condition(p, g, cls, taint),
		DeclaredSafe: cls == "safe" && g.Class == "safe" &&
			(r.Method != "GET" || r.Tunnel || r.WebSocket),
	}
}

// class applies 05 §1's ordered rules; the first that applies wins.
func class(g *policy.Grant, r *Request) string {
	// 1. Inference inspection, the boundary endpoint, and MCP protocol
	//    messages other than tools/call are the agent talking to its model
	//    or to its own boundary.
	if g.Inspect == "inference" || boundaryHost(r.Host) ||
		(g.Inspect == "mcp" && r.MCP != nil && r.MCP.Method != "tools/call") {
		return "control"
	}
	// 2. An explicit grant class wins next.
	if g.Class != "" {
		return g.Class
	}
	// 3. Passthrough and WebSocket upgrades cannot be staged or undone.
	if g.Mode == "passthrough" || r.WebSocket {
		return "irreversible"
	}
	// 4. The configured stager stages the request.
	if stagerStages(g, r) {
		return "staged"
	}
	// 5. A smart-HTTP read inside the grant's matcher is safe.
	if g.Match != nil && g.Match.Matcher != nil && g.Match.Matcher.GitSmartHTTP != nil {
		if acc, owner, repo, ok := policy.GitRequestOp(r.Method, r.Path, r.Query); ok &&
			acc == "read" && g.Match.Matcher.GitSmartHTTP.Covers(acc, owner, repo) {
			return "safe"
		}
	}
	// 6. GET, HEAD, OPTIONS are safe.
	if readMethods[r.Method] {
		return "safe"
	}
	// 7-8. A tools/call is control on a brokered (serialized) server; on an
	//     inspected server the grant's tools map gives the per-tool class.
	if r.MCP != nil && r.MCP.Method == "tools/call" {
		if g.Calls == "serialized" {
			return "control"
		}
		if g.Inspect == "mcp" {
			if cls := g.Tools[r.MCP.Tool]; cls != "" {
				return cls
			}
			return "irreversible"
		}
	}
	// 9. A compensate rule applying to this method makes the effect
	//    compensable.
	if c := g.Compensate; c != nil {
		if c.Restore != nil && slices.Contains(c.Restore.Methods, r.Method) {
			return "compensable"
		}
		if c.DeleteCreated != nil && slices.Contains(c.DeleteCreated.Methods, r.Method) {
			return "compensable"
		}
	}
	// 10. Otherwise the effect is irreversible.
	return "irreversible"
}

// stagerStages reports whether the grant's stager stages the request
// (05 §4 git writes in matcher scope; §5 outbox stores non-reads).
func stagerStages(g *policy.Grant, r *Request) bool {
	s := g.Stager
	if s == nil {
		return false
	}
	if s.Git != nil {
		acc, owner, repo, ok := policy.GitRequestOp(r.Method, r.Path, r.Query)
		return ok && acc == "write" && g.Match != nil && g.Match.Matcher != nil &&
			g.Match.Matcher.GitSmartHTTP != nil &&
			g.Match.Matcher.GitSmartHTTP.Covers(acc, owner, repo)
	}
	return s.Outbox != nil && !readMethods[r.Method]
}

// condition implements 05 §2: the strictest of autonomy[class] (default
// allow), the grant's requires, and for compensable/irreversible effects
// the whenTainted outcome for the labels present (04 §8).
func condition(p *policy.SessionPolicy, g *policy.Grant, cls string, taint []string) string {
	best := condOrder[condOrAllow(p.Spec.Autonomy[cls])]
	if r := condOrder[condOrAllow(g.Requires)]; r > best {
		best = r
	}
	if (cls == "compensable" || cls == "irreversible") && len(taint) > 0 {
		if r := condOrder[taintCond(g, taint)]; r > best {
			best = r
		}
	}
	return condName[best]
}

func condOrAllow(c string) string {
	if c == "" || c == "none" {
		return "allow"
	}
	return c
}

// taintCond resolves a grant's whenTainted for the labels present (04 §8):
// per-label overrides else default; the strictest result wins. An unset
// default is review for credentialed grants or grants permitting non-GET/HEAD
// methods, else allow (04 §1 defaults table).
func taintCond(g *policy.Grant, labels []string) string {
	w := g.WhenTainted
	if w == nil {
		return "allow"
	}
	def := w.Default
	if def == "" {
		def = "allow"
		if g.Credential != nil || g.Match == nil || len(g.Match.Methods) == 0 ||
			nonReadMethod(g.Match.Methods) {
			def = "review"
		}
	}
	best := 0
	for _, l := range labels {
		c := def
		if v := w.Labels[l]; v != "" {
			c = v
		}
		if n := condOrder[condOrAllow(c)]; n > best {
			best = n
		}
	}
	return condName[best]
}

func nonReadMethod(methods []string) bool {
	for _, m := range methods {
		if m != "GET" && m != "HEAD" {
			return true
		}
	}
	return false
}

// boundaryHost reports whether the request host is the boundary endpoint.
// The input may carry an authority (host[:port], IPv6 brackets) or a bare
// host; normalization matches 04 §1.
func boundaryHost(hostport string) bool {
	return normHost(authorityHost(hostport)) == names.BoundaryHost
}

// authorityHost splits host[:port]; brackets kept out. A non-numeric suffix
// stays part of the host.
func authorityHost(authority string) string {
	a := strings.ToLower(authority)
	if strings.HasPrefix(a, "[") {
		if end := strings.Index(a, "]"); end != -1 {
			return a[1:end]
		}
	}
	if i := strings.LastIndex(a, ":"); i >= 0 {
		if _, err := strconv.Atoi(a[i+1:]); err == nil {
			return a[:i]
		}
	}
	return a
}

// normHost lowercases, drops IPv6 brackets and one trailing root dot.
func normHost(h string) string {
	h = strings.ToLower(h)
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	return strings.TrimSuffix(h, ".")
}
