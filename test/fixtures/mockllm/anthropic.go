// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package mockllm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// anthExtract pulls tool_result blocks and user text from a /v1/messages body.
func anthExtract(body []byte) (map[string]string, string, bool, error) {
	var req struct {
		Stream   bool `json:"stream"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, "", false, fmt.Errorf("bad request json: %w", err)
	}
	results := map[string]string{}
	var user strings.Builder
	for _, m := range req.Messages {
		var blocks []struct {
			Type      string          `json:"type"`
			Text      string          `json:"text"`
			ToolUseID string          `json:"tool_use_id"`
			Content   json.RawMessage `json:"content"`
		}
		raw := m.Content
		if len(raw) > 0 && raw[0] == '"' {
			var s string
			if json.Unmarshal(raw, &s) == nil && m.Role == "user" {
				user.WriteString(s)
			}
			continue
		}
		if err := json.Unmarshal(raw, &blocks); err != nil {
			return nil, "", false, fmt.Errorf("bad content blocks: %w", err)
		}
		for _, b := range blocks {
			switch b.Type {
			case "tool_result":
				var txt string
				if len(b.Content) > 0 && b.Content[0] == '"' {
					if err := json.Unmarshal(b.Content, &txt); err != nil {
						return nil, "", false, fmt.Errorf("bad tool_result content: %w", err)
					}
				} else if len(b.Content) > 0 {
					var parts []struct {
						Text string `json:"text"`
					}
					if err := json.Unmarshal(b.Content, &parts); err != nil {
						return nil, "", false, fmt.Errorf("bad tool_result content: %w", err)
					}
					for _, p := range parts {
						txt += p.Text
					}
				}
				results[b.ToolUseID] += txt
			case "text":
				if m.Role == "user" {
					user.WriteString(b.Text)
				}
			}
		}
	}
	return results, user.String(), req.Stream, nil
}

func (s *Server) anthropic(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeErr(w, 400, "read body: "+err.Error())
		return
	}
	s.serve(w, r, "anthropic", body, anthExtract, anthRender)
}

// anthRender writes one assistant turn, stream (SSE) or not, deterministically.
func anthRender(w http.ResponseWriter, m *Transcript, idx int, resp Resp, stream bool) {
	id := fmt.Sprintf("msg_%s_%d", m.Name, idx)
	blocks := anthContent(resp)
	stop := resp.Stop
	if stop == "" {
		stop = "end_turn"
	}
	out := usage(resp)
	in := 100 + idx*13
	if !stream {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": id, "type": "message", "role": "assistant", "model": m.Model,
			"content": blocks, "stop_reason": stop, "stop_sequence": nil,
			"usage": map[string]int{"input_tokens": in, "output_tokens": out},
		})
		return
	}
	s := sse(w)
	s.ev("message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id": id, "type": "message", "role": "assistant", "model": m.Model,
			"content": []any{}, "stop_reason": nil, "stop_sequence": nil,
			"usage": map[string]int{"input_tokens": in, "output_tokens": 0},
		},
	})
	i := 0
	if resp.Text != "" {
		s.ev("content_block_start", map[string]any{"type": "content_block_start", "index": i, "content_block": map[string]any{"type": "text", "text": ""}})
		s.ev("ping", map[string]any{"type": "ping"})
		for _, frag := range chunks(resp.Text) {
			s.ev("content_block_delta", map[string]any{"type": "content_block_delta", "index": i, "delta": map[string]string{"type": "text_delta", "text": frag}})
		}
		s.ev("content_block_stop", map[string]any{"type": "content_block_stop", "index": i})
		i++
	}
	for _, c := range resp.Calls {
		s.ev("content_block_start", map[string]any{"type": "content_block_start", "index": i, "content_block": map[string]any{"type": "tool_use", "id": "toolu_" + c.Key, "name": c.Tool, "input": map[string]any{}}})
		for _, frag := range chunks(string(c.Input)) {
			s.ev("content_block_delta", map[string]any{"type": "content_block_delta", "index": i, "delta": map[string]string{"type": "input_json_delta", "partial_json": frag}})
		}
		s.ev("content_block_stop", map[string]any{"type": "content_block_stop", "index": i})
		i++
	}
	s.ev("message_delta", map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": stop, "stop_sequence": nil},
		"usage": map[string]int{"output_tokens": out},
	})
	s.ev("message_stop", map[string]any{"type": "message_stop"})
}

// anthContent is the non-stream content array.
func anthContent(resp Resp) []any {
	var blocks []any
	if resp.Text != "" {
		blocks = append(blocks, map[string]any{"type": "text", "text": resp.Text})
	}
	for _, c := range resp.Calls {
		blocks = append(blocks, map[string]any{
			"type": "tool_use", "id": "toolu_" + c.Key, "name": c.Tool, "input": c.Input,
		})
	}
	if blocks == nil {
		blocks = []any{}
	}
	return blocks
}
