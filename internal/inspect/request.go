// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Request-side parsing (M8.3): find tool results that close intent
// windows and enumerate context blocks for context.observed. Request
// bodies are already fully buffered under bufferLimit (03 §4.5), so the
// whole document is decoded once; json.RawMessage members keep the exact
// transmitted serialization every len field reports.

// RequestBlock is one context block of an inference request.
type RequestBlock struct {
	Index    int    `json:"index"`
	Role     string `json:"role"`
	Kind     string `json:"kind"`
	SHA256   string `json:"sha256"`
	Len      int    `json:"len"`
	IntentID string `json:"intent_id,omitempty"`

	digest string // dedup key (canonical digest, same as SHA256)
}

// ToolResult is a result reference found inside a request body.
type ToolResult struct {
	IntentID string
	// ContentSHA256/ContentLen describe the result content only — never
	// the text (M8-wide denied item: no tool-result content inspection
	// beyond digest and length).
	ContentSHA256 string
	ContentLen    int
	HasContent    bool
	IsError       bool
	HasIsError    bool
}

// RequestInfo is the parsed content of an inference request body.
type RequestInfo struct {
	Model   string
	Blocks  []RequestBlock
	Results []ToolResult
}

// ParseRequest decodes one inference request body for endpoint e. A
// non-JSON body is a parse failure (the caller records intent.unparsed
// and still forwards — spec/04 §5.4).
func ParseRequest(e Endpoint, body []byte) (*RequestInfo, error) {
	switch e {
	case EndpointAnthropic:
		return parseAnthropicRequest(body)
	case EndpointResponses:
		return parseResponsesRequest(body)
	case EndpointChat:
		return parseChatRequest(body)
	}
	return nil, fmt.Errorf("no request parser for endpoint %d", e)
}

// digestContent computes the recorded digest/len of a result's content:
// strings digest their own bytes; structured content its canonical form;
// absent content reports HasContent=false.
func digestContent(raw json.RawMessage) (sha string, ln int, has bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", 0, false
	}
	var s string
	if len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, &s) == nil {
		return sha256Hex([]byte(s)), len(s), true
	}
	v, err := decodeCanon(raw)
	if err != nil {
		return "", 0, false
	}
	c, err := canonSHA256(v)
	if err != nil {
		return "", 0, false
	}
	return c, len(raw), true
}

func blockOf(idx int, role, kind string, raw json.RawMessage, intentID string) (RequestBlock, error) {
	v, err := decodeCanon(raw)
	if err != nil {
		return RequestBlock{}, err
	}
	sha, err := canonSHA256(v)
	if err != nil {
		return RequestBlock{}, err
	}
	return RequestBlock{
		Index: idx, Role: role, Kind: kind, SHA256: sha,
		Len: len(raw), IntentID: intentID, digest: sha,
	}, nil
}

// ------------------------------------------------------------------
// Anthropic Messages request

func parseAnthropicRequest(body []byte) (*RequestInfo, error) {
	var req struct {
		Model    string            `json:"model"`
		System   json.RawMessage   `json:"system"`
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	info := &RequestInfo{Model: req.Model}
	idx := 0
	add := func(role, kind string, raw json.RawMessage, intentID string) error {
		b, err := blockOf(idx, role, kind, raw, intentID)
		if err != nil {
			return err
		}
		info.Blocks = append(info.Blocks, b)
		idx++
		return nil
	}
	// system: a string or an array of text blocks — one context block each.
	if len(req.System) > 0 {
		if req.System[0] == '[' {
			var parts []json.RawMessage
			if err := json.Unmarshal(req.System, &parts); err != nil {
				return nil, fmt.Errorf("system: %v", err)
			}
			for _, p := range parts {
				if err := add("system", "text", p, ""); err != nil {
					return nil, err
				}
			}
		} else {
			if err := add("system", "text", req.System, ""); err != nil {
				return nil, err
			}
		}
	}
	for _, mraw := range req.Messages {
		var msg struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		}
		if err := json.Unmarshal(mraw, &msg); err != nil {
			return nil, fmt.Errorf("message: %v", err)
		}
		c := msg.Content
		if len(c) == 0 {
			continue
		}
		if c[0] == '"' {
			if err := add(msg.Role, "text", c, ""); err != nil {
				return nil, err
			}
			continue
		}
		var blocks []json.RawMessage
		if err := json.Unmarshal(c, &blocks); err != nil {
			return nil, fmt.Errorf("message content: %v", err)
		}
		for _, braw := range blocks {
			var bl struct {
				Type      string          `json:"type"`
				ID        string          `json:"id"`
				ToolUseID string          `json:"tool_use_id"`
				IsError   *bool           `json:"is_error"`
				Content   json.RawMessage `json:"content"`
			}
			if err := json.Unmarshal(braw, &bl); err != nil {
				return nil, fmt.Errorf("content block: %v", err)
			}
			kind := bl.Type
			if kind == "" {
				kind = "unknown"
			}
			intentID := ""
			switch bl.Type {
			case "tool_result":
				intentID = bl.ToolUseID
				sha, ln, has := digestContent(bl.Content)
				tr := ToolResult{
					IntentID: intentID, ContentSHA256: sha,
					ContentLen: ln, HasContent: has,
				}
				if bl.IsError != nil {
					tr.IsError = *bl.IsError
					tr.HasIsError = true
				}
				info.Results = append(info.Results, tr)
			case "tool_use", "server_tool_use":
				intentID = bl.ID
			}
			if err := add(msg.Role, kind, braw, intentID); err != nil {
				return nil, err
			}
		}
	}
	return info, nil
}

// ------------------------------------------------------------------
// OpenAI Responses request

func parseResponsesRequest(body []byte) (*RequestInfo, error) {
	var req struct {
		Model string            `json:"model"`
		Input []json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	info := &RequestInfo{Model: req.Model}
	idx := 0
	for _, iraw := range req.Input {
		var item struct {
			Type    string          `json:"type"`
			Role    string          `json:"role"`
			CallID  string          `json:"call_id"`
			ID      string          `json:"id"`
			Name    string          `json:"name"`
			Output  json.RawMessage `json:"output"`
			Content json.RawMessage `json:"content"`
		}
		if err := json.Unmarshal(iraw, &item); err != nil {
			return nil, fmt.Errorf("input item: %v", err)
		}
		switch item.Type {
		case "", "message":
			role := item.Role
			if role == "" {
				role = "user"
			}
			var err error
			idx, err = addContentBlocks(info, idx, role, item.Content)
			if err != nil {
				return nil, err
			}
		case "function_call", "custom_tool_call":
			id := item.CallID
			if id == "" {
				id = item.ID
			}
			b, err := blockOf(idx, "assistant", item.Type, iraw, id)
			if err != nil {
				return nil, err
			}
			info.Blocks = append(info.Blocks, b)
			idx++
		case "function_call_output":
			sha, ln, has := digestContent(item.Output)
			info.Results = append(info.Results, ToolResult{
				IntentID: item.CallID, ContentSHA256: sha,
				ContentLen: ln, HasContent: has,
			})
			b, err := blockOf(idx, "tool", "function_call_output", iraw, item.CallID)
			if err != nil {
				return nil, err
			}
			info.Blocks = append(info.Blocks, b)
			idx++
		default:
			// Reasoning summaries, hosted-call echoes, item references:
			// context blocks like any other.
			b, err := blockOf(idx, "assistant", item.Type, iraw, "")
			if err != nil {
				return nil, err
			}
			info.Blocks = append(info.Blocks, b)
			idx++
		}
	}
	return info, nil
}

// ------------------------------------------------------------------
// OpenAI Chat Completions request

func parseChatRequest(body []byte) (*RequestInfo, error) {
	var req struct {
		Model    string            `json:"model"`
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	info := &RequestInfo{Model: req.Model}
	idx := 0
	for _, mraw := range req.Messages {
		var msg struct {
			Role       string            `json:"role"`
			Content    json.RawMessage   `json:"content"`
			ToolCalls  []json.RawMessage `json:"tool_calls"`
			ToolCallID string            `json:"tool_call_id"`
		}
		if err := json.Unmarshal(mraw, &msg); err != nil {
			return nil, fmt.Errorf("message: %v", err)
		}
		var err error
		if len(msg.Content) > 0 && string(msg.Content) != "null" {
			idx, err = addContentBlocks(info, idx, msg.Role, msg.Content)
			if err != nil {
				return nil, err
			}
		}
		for _, traw := range msg.ToolCalls {
			var tc struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			}
			if err := json.Unmarshal(traw, &tc); err != nil {
				return nil, fmt.Errorf("tool_call: %v", err)
			}
			kind := "tool_call"
			b, err := blockOf(idx, "assistant", kind, traw, tc.ID)
			if err != nil {
				return nil, err
			}
			info.Blocks = append(info.Blocks, b)
			idx++
		}
		if msg.Role == "tool" && msg.ToolCallID != "" {
			sha, ln, has := digestContent(msg.Content)
			info.Results = append(info.Results, ToolResult{
				IntentID: msg.ToolCallID, ContentSHA256: sha,
				ContentLen: ln, HasContent: has,
			})
		}
	}
	return info, nil
}

// addContentBlocks expands a message content member: a string is one
// text block; an array of parts is one block each; anything else is one
// block of its own JSON kind.
func addContentBlocks(info *RequestInfo, idx int, role string, content json.RawMessage) (int, error) {
	if len(content) == 0 {
		return idx, nil
	}
	if content[0] == '[' {
		var parts []json.RawMessage
		if err := json.Unmarshal(content, &parts); err != nil {
			return idx, fmt.Errorf("content: %v", err)
		}
		for _, p := range parts {
			var pt struct {
				Type string `json:"type"`
			}
			// The array elements are always valid JSON (the outer
			// Unmarshal succeeded), so a decode error means p is not an
			// object — a bare string/number part, whose kind is "part" —
			// or an object with a non-string `type`, which is malformed
			// and must not silently degrade to an unrecorded block kind.
			if err := json.Unmarshal(p, &pt); err != nil {
				if t := bytes.TrimSpace(p); len(t) > 0 && t[0] == '{' {
					return idx, fmt.Errorf("content part: %v", err)
				}
			}
			kind := pt.Type
			if kind == "" {
				kind = "part"
			}
			b, err := blockOf(idx, role, kind, p, "")
			if err != nil {
				return idx, err
			}
			info.Blocks = append(info.Blocks, b)
			idx++
		}
		return idx, nil
	}
	b, err := blockOf(idx, role, "text", content, "")
	if err != nil {
		return idx, err
	}
	info.Blocks = append(info.Blocks, b)
	return idx + 1, nil
}
