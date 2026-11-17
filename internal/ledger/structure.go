// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"github.com/countersign/countersign/internal/evidence"
)

// recs are decoded lines shared with verify.go.
type decLine struct {
	line []byte
	env  *evidence.Envelope
	rec  *evidence.Record
	ok   bool
}

// verifyStructure implements V11 of 03 §10: referential integrity and the
// ordering rules of §4.5 over the decoded records, in log order.
func verifyStructure(recs []decLine, _ int) []Finding {
	var errs []Finding
	at := func(i int, f string, a ...any) { errs = append(errs, errfAt("E_STRUCTURE", i, f, a...)) }

	// First pass: index referable records by their IDs.
	httpEffects := map[string]int{}   // effect_id → record index
	tunnelEffects := map[string]int{} // effect_id → index
	intents := map[string]int{}       // intent_id → index
	calls := map[string]int{}         // call_id → index
	entries := map[string]int{}       // entry_id → index
	commitReq := map[string]int{}     // commit_id → index
	commitDec := map[string]int{}     // commit_id → index
	undoReq := map[string]int{}       // undo_id → index
	results := map[string]int{}       // "http:<id>" → count guards

	for i, d := range recs {
		if !d.ok {
			continue
		}
		b := d.rec.Body
		switch d.rec.Type {
		case "effect.http":
			x := b.(*evidence.EffectHTTPBody)
			if _, dup := httpEffects[x.EffectID]; dup {
				at(i, "duplicate effect_id %s", x.EffectID)
			}
			httpEffects[x.EffectID] = i
			// §4.5 decision-before-apply: an apply effect follows the
			// commit.decision it serves.
			if x.Purpose != nil && *x.Purpose == "apply" {
				if x.For == nil {
					at(i, "apply effect %s has no for", x.EffectID)
				} else if _, ok := commitDec[*x.For]; !ok {
					at(i, "apply effect %s for %s precedes its commit.decision", x.EffectID, *x.For)
				}
			}
		case "effect.tunnel":
			x := b.(*evidence.EffectTunnelBody)
			if _, dup := tunnelEffects[x.EffectID]; dup {
				at(i, "duplicate effect_id %s", x.EffectID)
			}
			tunnelEffects[x.EffectID] = i
		case "effect.http.result":
			x := b.(*evidence.EffectHTTPResultBody)
			ei, ok := httpEffects[x.EffectID]
			if !ok {
				at(i, "result for unknown effect %s", x.EffectID)
			} else if ei >= i {
				at(i, "result precedes effect %s", x.EffectID)
			}
			if c := results["http:"+x.EffectID]; c > 0 {
				at(i, "second result for effect %s", x.EffectID)
			}
			results["http:"+x.EffectID]++
		case "effect.tunnel.result":
			x := b.(*evidence.EffectTunnelResultBody)
			ei, ok := tunnelEffects[x.EffectID]
			if !ok {
				at(i, "result for unknown tunnel %s", x.EffectID)
			} else if ei >= i {
				at(i, "result precedes tunnel %s", x.EffectID)
			}
			if c := results["tunnel:"+x.EffectID]; c > 0 {
				at(i, "second result for tunnel %s", x.EffectID)
			}
			results["tunnel:"+x.EffectID]++
		case "intent.declared":
			x := b.(*evidence.IntentDeclaredBody)
			intents[x.IntentID] = i
			if _, ok := httpEffects[x.ViaEffect]; !ok {
				if _, ok := tunnelEffects[x.ViaEffect]; !ok {
					at(i, "intent %s via unknown effect %s", x.IntentID, x.ViaEffect)
				}
			}
		case "intent.result":
			x := b.(*evidence.IntentResultBody)
			ii, ok := intents[x.IntentID]
			if !ok {
				at(i, "result for unknown intent %s", x.IntentID)
			} else if ii >= i {
				at(i, "result precedes intent %s", x.IntentID)
			}
		case "stage.entry":
			x := b.(*evidence.StageEntryBody)
			entries[x.EntryID] = i
			if _, ok := httpEffects[x.ViaEffect]; !ok {
				if _, ok := tunnelEffects[x.ViaEffect]; !ok {
					at(i, "entry %s via unknown effect %s", x.EntryID, x.ViaEffect)
				}
			}
			if x.Supersedes != nil {
				if _, ok := entries[*x.Supersedes]; !ok {
					at(i, "entry %s supersedes unknown %s", x.EntryID, *x.Supersedes)
				}
			}
		case "prestate.captured":
			x := b.(*evidence.PrestateCapturedBody)
			ei, ok := httpEffects[x.ForEffect]
			if !ok {
				at(i, "prestate for unknown effect %s", x.ForEffect)
			} else if x.When == "before" && results["http:"+x.ForEffect] > 0 {
				at(i, "before-prestate for %s after its result (idx %d)", x.ForEffect, ei)
			}
			if _, ok := httpEffects[x.ViaEffect]; !ok {
				at(i, "prestate via unknown effect %s", x.ViaEffect)
			}
		case "commit.requested":
			x := b.(*evidence.CommitRequestedBody)
			commitReq[x.CommitID] = i
			for _, e := range x.Entries {
				if _, ok := entries[e]; !ok {
					at(i, "commit %s requests unknown entry %s", x.CommitID, e)
				}
			}
		case "commit.decision":
			x := b.(*evidence.CommitDecisionBody)
			commitDec[x.CommitID] = i
			if _, ok := commitReq[x.CommitID]; !ok {
				at(i, "decision for unrequested commit %s", x.CommitID)
			}
		case "commit.applied":
			x := b.(*evidence.CommitAppliedBody)
			if _, ok := commitDec[x.CommitID]; !ok {
				at(i, "applied for undecided commit %s", x.CommitID)
			}
			if _, ok := entries[x.EntryID]; !ok {
				at(i, "applied unknown entry %s", x.EntryID)
			}
			if x.ViaEffect != nil {
				if _, ok := httpEffects[*x.ViaEffect]; !ok {
					at(i, "applied via unknown effect %s", *x.ViaEffect)
				}
			}
		case "commit.closed":
			x := b.(*evidence.CommitClosedBody)
			if _, ok := commitDec[x.CommitID]; !ok {
				at(i, "closed for undecided commit %s", x.CommitID)
			}
		case "probation.ratified":
			x := b.(*evidence.ProbationRatifiedBody)
			if _, ok := commitDec[x.CommitID]; !ok {
				at(i, "ratified for undecided commit %s", x.CommitID)
			}
		case "undo.requested":
			x := b.(*evidence.UndoRequestedBody)
			undoReq[x.UndoID] = i
		case "undo.applied":
			x := b.(*evidence.UndoAppliedBody)
			if _, ok := undoReq[x.UndoID]; !ok {
				at(i, "applied for unrequested undo %s", x.UndoID)
			}
			if x.ViaEffect != nil {
				if _, ok := httpEffects[*x.ViaEffect]; !ok {
					at(i, "undo applied via unknown effect %s", *x.ViaEffect)
				}
			}
		case "undo.closed":
			x := b.(*evidence.UndoClosedBody)
			if _, ok := undoReq[x.UndoID]; !ok {
				at(i, "closed for unrequested undo %s", x.UndoID)
			}
		case "attestation.issued":
			x := b.(*evidence.AttestationIssuedBody)
			if _, ok := entries[x.EntryID]; !ok {
				at(i, "attestation for unknown entry %s", x.EntryID)
			}
		case "context.observed", "intent.unparsed", "mcp.tools", "replay.divergence":
			x := viaOf(b)
			if x != "" {
				if _, ok := httpEffects[x]; !ok {
					if _, ok := tunnelEffects[x]; !ok {
						at(i, "%s via unknown effect %s", d.rec.Type, x)
					}
				}
			}
		case "mcp.call.begin":
			x := b.(*evidence.MCPCallBeginBody)
			calls[x.CallID] = i
		case "mcp.call.end":
			x := b.(*evidence.MCPCallEndBody)
			ci, ok := calls[x.CallID]
			if !ok {
				at(i, "end for unknown call %s", x.CallID)
			} else if ci >= i {
				at(i, "end precedes call %s", x.CallID)
			}
		}
	}
	return errs
}

// viaOf extracts the via_effect of bodies that carry one (§4.4).
func viaOf(b any) string {
	switch x := b.(type) {
	case *evidence.IntentUnparsedBody:
		return x.ViaEffect
	case *evidence.ContextObservedBody:
		return x.ViaEffect
	case *evidence.MCPToolsBody:
		return ""
	case *evidence.ReplayDivergenceBody:
		return ""
	}
	return ""
}

// verifyWarnings implements V15 of 03 §10.
func verifyWarnings(recs []decLine, sealBody *evidence.SessionSealBody, heads map[string]evidence.ChainHead) []Finding {
	var w []Finding
	at := func(code string, i int, f string, a ...any) {
		w = append(w, errfAt(code, i, f, a...))
	}
	resulted := map[string]bool{}
	var httpOrder []struct {
		id string
		i  int
	}
	for i, d := range recs {
		if !d.ok {
			continue
		}
		switch d.rec.Type {
		case "effect.http":
			b := d.rec.Body.(*evidence.EffectHTTPBody)
			httpOrder = append(httpOrder, struct {
				id string
				i  int
			}{b.EffectID, i})
		case "effect.http.result":
			resulted[d.rec.Body.(*evidence.EffectHTTPResultBody).EffectID] = true
		case "observer.gap":
			at("W_OBSERVER_GAP", i, "observer gap recorded")
		case "intent.unparsed":
			at("W_UNPARSED", i, "unparsed intent recorded")
		case "commit.closed":
			if d.rec.Body.(*evidence.CommitClosedBody).Outcome == "partial" {
				at("W_PARTIAL_COMMIT", i, "commit closed partial")
			}
		case "commit.applied":
			if d.rec.Body.(*evidence.CommitAppliedBody).Outcome == "unknown" {
				at("W_APPLY_UNKNOWN", i, "apply outcome unknown")
			}
		case "undo.closed":
			if d.rec.Body.(*evidence.UndoClosedBody).Conflicts > 0 {
				at("W_UNDO_CONFLICT", i, "undo had conflicts")
			}
		}
	}
	// W_DANGLING: effects without a result.
	for _, e := range httpOrder {
		if !resulted[e.id] {
			at("W_DANGLING", e.i, "effect %s has no result", e.id)
		}
	}
	// W_UNCLEAN_EMITTER: emitters sealed unclean.
	if sealBody != nil {
		for i, se := range sealBody.Emitters {
			if !se.Clean {
				w = append(w, errfAt("W_UNCLEAN_EMITTER", i, "emitter %s sealed unclean", se.Emitter))
			}
		}
	}
	return w
}

// hasDenial reports whether the session records any denial.
func hasDenial(recs []decLine) bool {
	for _, d := range recs {
		if !d.ok {
			continue
		}
		if d.rec.Type == "effect.denied" {
			return true
		}
	}
	return false
}
