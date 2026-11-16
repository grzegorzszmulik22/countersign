// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package ldtest

import (
	"fmt"

	"github.com/countersign/countersign/internal/ledger"
)

// CleanAllTypes emits a fully sealed session exercising every record type
// that does not itself imply a warning or denial.
func CleanAllTypes(l *ledger.Ledger, s *Session) {
	s.Open(l, "enforce")
	b := s.Emit(l, "broker", "effect.http", Body("effect.http", map[string]any{
		"effect_id": "e1", "class": "safe",
		"decision": map[string]any{"action": "allow", "reason": "OK", "requires": "allow"},
	}))
	_ = b
	s.Emit(l, "broker", "intent.declared", Body("intent.declared", map[string]any{
		"intent_id": "i1", "via_effect": "e1",
	}))
	s.Emit(l, "broker", "taint.added", Body("taint.added", map[string]any{
		"label": "pii", "source": "effect", "source_effect": "e1",
	}))
	s.Emit(l, "broker", "context.observed", Body("context.observed", map[string]any{
		"via_effect": "e1",
	}))
	s.Emit(l, "broker", "mcp.tools", Body("mcp.tools", nil))
	s.Emit(l, "broker", "mcp.call.begin", Body("mcp.call.begin", map[string]any{
		"call_id": "c1", "caller_session": s.ID, "caller_world": s.ID, "caller_effect": "e1",
	}))
	s.Emit(l, "broker", "mcp.call.end", Body("mcp.call.end", map[string]any{
		"call_id": "c1",
	}))
	s.Emit(l, "broker", "replay.divergence", Body("replay.divergence", nil))
	s.Emit(l, "broker", "effect.http", Body("effect.http", map[string]any{
		"effect_id": "e2", "class": "compensable",
		"decision": map[string]any{"action": "allow", "reason": "OK", "requires": "allow"},
	}))
	s.Emit(l, "world", "prestate.captured", Body("prestate.captured", map[string]any{
		"for_effect": "e2", "when": "before", "via_effect": "e1",
	}))
	s.Emit(l, "broker", "effect.http.result", Body("effect.http.result", map[string]any{
		"effect_id": "e1", "served_by": "upstream",
	}))
	s.Emit(l, "broker", "effect.http.result", Body("effect.http.result", map[string]any{
		"effect_id": "e2", "served_by": "upstream",
	}))
	s.Emit(l, "world", "stage.entry", Body("stage.entry", map[string]any{
		"entry_id": "en1", "journal_seq": 1, "via_effect": "e2", "supersedes": nil,
	}))
	s.Emit(l, "world", "commit.requested", Body("commit.requested", map[string]any{
		"commit_id": "k1", "trigger": "agent", "entries": []string{"en1"},
	}))
	s.Emit(l, "world", "commit.decision", Body("commit.decision", map[string]any{
		"commit_id": "k1", "decision": "commit", "by": "auto", "selected": []string{"en1"},
	}))
	s.Emit(l, "broker", "effect.http", Body("effect.http", map[string]any{
		"effect_id": "e3", "class": "compensable", "purpose": "apply", "for": "k1",
		"decision": map[string]any{"action": "allow", "reason": "OK", "requires": "allow"},
	}))
	s.Emit(l, "broker", "effect.http.result", Body("effect.http.result", map[string]any{
		"effect_id": "e3", "served_by": "upstream",
	}))
	s.Emit(l, "world", "commit.applied", Body("commit.applied", map[string]any{
		"commit_id": "k1", "entry_id": "en1", "outcome": "applied", "via_effect": "e3",
		"precondition": map[string]any{"kind": "etag", "expected": "\"a\"", "observed": "\"a\""},
	}))
	s.Emit(l, "world", "commit.closed", Body("commit.closed", map[string]any{
		"commit_id": "k1", "outcome": "committed",
	}))
	s.Emit(l, "world", "probation.ratified", Body("probation.ratified", map[string]any{
		"commit_id": "k1",
	}))
	s.Emit(l, "world", "undo.requested", Body("undo.requested", map[string]any{
		"undo_id": "u1", "scope": "commit", "targets": []string{"en1"}, "trigger": "commit-failure",
	}))
	s.Emit(l, "world", "undo.applied", Body("undo.applied", map[string]any{
		"undo_id": "u1", "target": "en1", "outcome": "restored", "via_effect": "e3",
		"precondition": map[string]any{"expected": "\"a\"", "observed": "\"a\""},
	}))
	s.Emit(l, "world", "undo.closed", Body("undo.closed", map[string]any{
		"undo_id": "u1", "restored": 1, "conflicts": 0, "not_compensable": 0, "failed": 0,
	}))
	s.Emit(l, "world", "attestation.issued", Body("attestation.issued", map[string]any{
		"commit_id": "k1", "entry_id": "en1",
		"subject": map[string]any{"kind": "file", "name": "en1", "digest": map[string]any{"sha256": fmt.Sprintf("%064x", 1)}},
	}))
	s.Emit(l, "world", "world.rewound", Body("world.rewound", nil))
	s.Emit(l, "observer", "effect.exec", Body("effect.exec", nil))
	s.Emit(l, "observer", "effect.connect", Body("effect.connect", nil))
	s.Emit(l, "broker", "effect.tunnel", Body("effect.tunnel", map[string]any{
		"effect_id": "t1",
		"decision":  map[string]any{"action": "allow", "reason": "OK", "requires": "allow"},
	}))
	s.Emit(l, "broker", "effect.tunnel.result", Body("effect.tunnel.result", map[string]any{
		"effect_id": "t1",
	}))
	s.Emit(l, "controller", "sandbox.terminated", Body("sandbox.terminated", nil))
	s.Emit(l, "world", "world.closed", Body("world.closed", map[string]any{
		"outcome": "committed", "commits": []string{"k1"},
	}))
	s.EmitterSeal(l, "broker")
	s.EmitterSeal(l, "world")
	s.EmitterSeal(l, "observer")
	s.Seal(l)
}
