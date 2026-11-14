// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package evidence

import "encoding/json"

// Record bodies of 03 §4.4 — meaning.

func init() {
	registerBody("intent.declared", func() any { return &IntentDeclaredBody{} })
	registerBody("intent.result", func() any { return &IntentResultBody{} })
	registerBody("intent.unparsed", func() any { return &IntentUnparsedBody{} })
	registerBody("context.observed", func() any { return &ContextObservedBody{} })
	registerBody("taint.added", func() any { return &TaintAddedBody{} })
	registerBody("mcp.call.begin", func() any { return &MCPCallBeginBody{} })
	registerBody("mcp.call.end", func() any { return &MCPCallEndBody{} })
	registerBody("mcp.tools", func() any { return &MCPToolsBody{} })
	registerBody("replay.divergence", func() any { return &ReplayDivergenceBody{} })
}

type IntentDeclaredBody struct {
	IntentID     string  `json:"intent_id"`
	Source       string  `json:"source" cs:"enum:inference|mcp"`
	Provider     string  `json:"provider"`
	Model        *string `json:"model"`
	ViaEffect    string  `json:"via_effect"`
	Tool         string  `json:"tool"`
	Class        string  `json:"class" cs:"enum:exec|http|mcp|other"`
	Executor     string  `json:"executor" cs:"enum:sandbox|provider"`
	InputSHA256  string  `json:"input_sha256" cs:"hex64"`
	InputLen     uint64  `json:"input_len"`
	InputPreview *string `json:"input_preview"`
	AnchorSHA256 *string `json:"anchor_sha256" cs:"hex64"`
}

type IntentResultBody struct {
	IntentID      string  `json:"intent_id"`
	ViaEffect     string  `json:"via_effect"`
	ClosedBy      string  `json:"closed_by" cs:"enum:tool_result|seal|timeout"`
	ContentSHA256 *string `json:"content_sha256" cs:"hex64"`
	ContentLen    *uint64 `json:"content_len"`
	IsError       *bool   `json:"is_error"`
}

type IntentUnparsedBody struct {
	ViaEffect string `json:"via_effect"`
	Provider  string `json:"provider"`
	Detail    string `json:"detail"`
}

type ContextBlock struct {
	Index    int64   `json:"index"`
	Role     string  `json:"role"`
	Kind     string  `json:"kind"`
	SHA256   string  `json:"sha256" cs:"hex64"`
	Len      uint64  `json:"len"`
	IntentID *string `json:"intent_id"`
}

type ContextObservedBody struct {
	ViaEffect     string         `json:"via_effect"`
	Provider      string         `json:"provider"`
	Model         *string        `json:"model"`
	BlockCount    uint64         `json:"block_count"`
	ContextSHA256 string         `json:"context_sha256" cs:"hex64"`
	NewBlocks     []ContextBlock `json:"new_blocks"`
}

type TaintAddedBody struct {
	Label        string  `json:"label"`
	Source       string  `json:"source" cs:"enum:effect|provider-tool|initial"`
	SourceEffect *string `json:"source_effect"`
	SourceGrant  *string `json:"source_grant"`
}

type MCPCallBeginBody struct {
	CallID          string          `json:"call_id"`
	CallerSession   string          `json:"caller_session" cs:"ulid"`
	CallerWorld     string          `json:"caller_world"`
	CallerEffect    string          `json:"caller_effect"`
	Tool            string          `json:"tool"`
	ArgumentsSHA256 string          `json:"arguments_sha256" cs:"hex64"`
	ContractArgs    json.RawMessage `json:"contract_args" cs:"raw"`
}

type MCPCallEndBody struct {
	CallID       string `json:"call_id"`
	IsError      bool   `json:"is_error"`
	ResultSHA256 string `json:"result_sha256" cs:"hex64"`
}

type MCPTool struct {
	Name         string          `json:"name"`
	Annotations  json.RawMessage `json:"annotations" cs:"raw"`
	SchemaSHA256 string          `json:"schema_sha256" cs:"hex64"`
}

type MCPToolsBody struct {
	Server string    `json:"server"`
	Tools  []MCPTool `json:"tools"`
}

type DivergenceExpected struct {
	EffectID      string `json:"effect_id"`
	RequestDigest string `json:"request_digest" cs:"hex64"`
}

type DivergenceObserved struct {
	Method        string  `json:"method"`
	Authority     string  `json:"authority"`
	Path          string  `json:"path"`
	RequestDigest *string `json:"request_digest" cs:"hex64"`
	Class         string  `json:"class" cs:"enum:control|safe|staged|compensable|irreversible"`
}

type ReplayDivergenceBody struct {
	Position       uint64              `json:"position"`
	Expected       *DivergenceExpected `json:"expected"`
	Observed       DivergenceObserved  `json:"observed"`
	PolicyDecision string              `json:"policy_decision"`
}
