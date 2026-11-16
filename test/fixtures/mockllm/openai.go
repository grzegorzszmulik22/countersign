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

const createdAt = 1700000000

// ---------------------------------------------------------------------------
// /v1/responses
// ---------------------------------------------------------------------------

func (s *Server) responses(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeErr(w, 400, "read body: "+err.Error())
		return
	}
	s.serve(w, r, "responses", body, respExtract, respRender)
}

// respExtract reads function_call_output items and the last user message.
func respExtract(body []byte) (map[string]string, string, bool, error) {
	var req struct {
		Stream bool            `json:"stream"`
		Input  json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, "", false, fmt.Errorf("bad request json: %w", err)
	}
	results := map[string]string{}
	var user strings.Builder
	var items []struct {
		Type    string          `json:"type"`
		Role    string          `json:"role"`
		CallID  string          `json:"call_id"`
		Output  json.RawMessage `json:"output"`
		Content json.RawMessage `json:"content"`
	}
	raw := req.Input
	if len(raw) > 0 && raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, "", false, fmt.Errorf("bad input string: %w", err)
		}
		return results, s, req.Stream, nil
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, "", false, fmt.Errorf("bad input items: %w", err)
	}
	for _, it := range items {
		switch it.Type {
		case "function_call_output":
			var out string
			if len(it.Output) > 0 && it.Output[0] == '"' {
				if err := json.Unmarshal(it.Output, &out); err != nil {
					return nil, "", false, fmt.Errorf("bad call output: %w", err)
				}
			} else if len(it.Output) > 0 {
				var parts []struct {
					Text string `json:"text"`
				}
				if err := json.Unmarshal(it.Output, &parts); err != nil {
					return nil, "", false, fmt.Errorf("bad call output: %w", err)
				}
				for _, p := range parts {
					out += p.Text
				}
			}
			results[it.CallID] += out
		case "message":
			if it.Role == "user" {
				var c string
				if len(it.Content) > 0 && it.Content[0] == '"' {
					if err := json.Unmarshal(it.Content, &c); err != nil {
						return nil, "", false, fmt.Errorf("bad message content: %w", err)
					}
				} else if len(it.Content) > 0 {
					var parts []struct {
						Text string `json:"text"`
					}
					if err := json.Unmarshal(it.Content, &parts); err != nil {
						return nil, "", false, fmt.Errorf("bad message content: %w", err)
					}
					for _, p := range parts {
						c += p.Text
					}
				}
				user.WriteString(c)
			}
		}
	}
	return results, user.String(), req.Stream, nil
}

// respOutput builds the completed-output array: an optional message item plus
// one function_call item per call. Deterministic ids.
func respOutput(m *Transcript, idx int, resp Resp) []any {
	var out []any
	if resp.Text != "" {
		out = append(out, map[string]any{
			"id": fmt.Sprintf("msg_%s_%d", m.Name, idx), "type": "message",
			"status": "completed", "role": "assistant",
			"content": []any{map[string]any{"type": "output_text", "text": resp.Text, "annotations": []any{}}},
		})
	}
	for _, c := range resp.Calls {
		out = append(out, map[string]any{
			"id": "fc_" + c.Key, "type": "function_call", "status": "completed",
			"call_id": "call_" + c.Key, "name": c.Tool,
			"arguments": string(c.Input),
		})
	}
	if out == nil {
		out = []any{}
	}
	return out
}

func respUsage(resp Resp) map[string]any {
	return map[string]any{
		"input_tokens": 100, "output_tokens": usage(resp), "total_tokens": 100 + usage(resp),
		"input_tokens_details":  map[string]int{"cached_tokens": 0},
		"output_tokens_details": map[string]int{"reasoning_tokens": 0},
	}
}

func respObject(m *Transcript, idx int, resp Resp, status string) map[string]any {
	return map[string]any{
		"id": fmt.Sprintf("resp_%s_%d", m.Name, idx), "object": "response",
		"created_at": createdAt, "status": status, "model": m.Model,
		"output": respOutput(m, idx, resp), "usage": respUsage(resp),
		"error": nil, "incomplete_details": nil,
	}
}

func respRender(w http.ResponseWriter, m *Transcript, idx int, resp Resp, stream bool) {
	if !stream {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(respObject(m, idx, resp, "completed"))
		return
	}
	s := sse(w)
	final := respObject(m, idx, resp, "completed")
	inprog := respObject(m, idx, resp, "in_progress")
	inprog["output"] = []any{}
	s.ev("response.created", map[string]any{"type": "response.created", "response": inprog})
	s.ev("response.in_progress", map[string]any{"type": "response.in_progress", "response": inprog})
	i := 0
	if resp.Text != "" {
		item := map[string]any{
			"id": fmt.Sprintf("msg_%s_%d", m.Name, idx), "type": "message",
			"status": "in_progress", "role": "assistant", "content": []any{},
		}
		s.ev("response.output_item.added", map[string]any{"type": "response.output_item.added", "output_index": i, "item": item})
		s.ev("response.content_part.added", map[string]any{"type": "response.content_part.added", "item_id": item["id"], "output_index": i, "content_index": 0, "part": map[string]any{"type": "output_text", "text": "", "annotations": []any{}}})
		for _, frag := range chunks(resp.Text) {
			s.ev("response.output_text.delta", map[string]any{"type": "response.output_text.delta", "item_id": item["id"], "output_index": i, "content_index": 0, "delta": frag})
		}
		s.ev("response.content_part.done", map[string]any{"type": "response.content_part.done", "item_id": item["id"], "output_index": i, "content_index": 0, "part": map[string]any{"type": "output_text", "text": resp.Text, "annotations": []any{}}})
		item["status"] = "completed"
		item["content"] = []any{map[string]any{"type": "output_text", "text": resp.Text, "annotations": []any{}}}
		s.ev("response.output_item.done", map[string]any{"type": "response.output_item.done", "output_index": i, "item": item})
		i++
	}
	for _, c := range resp.Calls {
		item := map[string]any{
			"id": "fc_" + c.Key, "type": "function_call", "status": "in_progress",
			"call_id": "call_" + c.Key, "name": c.Tool, "arguments": "",
		}
		s.ev("response.output_item.added", map[string]any{"type": "response.output_item.added", "output_index": i, "item": item})
		for _, frag := range chunks(string(c.Input)) {
			s.ev("response.function_call_arguments.delta", map[string]any{"type": "response.function_call_arguments.delta", "item_id": item["id"], "output_index": i, "delta": frag})
		}
		s.ev("response.function_call_arguments.done", map[string]any{"type": "response.function_call_arguments.done", "item_id": item["id"], "output_index": i, "arguments": string(c.Input)})
		item["status"] = "completed"
		item["arguments"] = string(c.Input)
		s.ev("response.output_item.done", map[string]any{"type": "response.output_item.done", "output_index": i, "item": item})
		i++
	}
	s.ev("response.completed", map[string]any{"type": "response.completed", "response": final})
}

// ---------------------------------------------------------------------------
// /v1/chat/completions
// ---------------------------------------------------------------------------

func (s *Server) chatCompletions(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeErr(w, 400, "read body: "+err.Error())
		return
	}
	s.serve(w, r, "chat", body, chatExtract, chatRender)
}

// chatExtract reads role:"tool" messages and user text.
func chatExtract(body []byte) (map[string]string, string, bool, error) {
	var req struct {
		Stream   bool `json:"stream"`
		Messages []struct {
			Role       string          `json:"role"`
			ToolCallID string          `json:"tool_call_id"`
			Content    json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, "", false, fmt.Errorf("bad request json: %w", err)
	}
	results := map[string]string{}
	var user strings.Builder
	for _, msg := range req.Messages {
		var content string
		if len(msg.Content) > 0 && msg.Content[0] == '"' {
			if err := json.Unmarshal(msg.Content, &content); err != nil {
				return nil, "", false, fmt.Errorf("bad tool message content: %w", err)
			}
		} else if len(msg.Content) > 0 {
			var parts []struct {
				Text string `json:"text"`
			}
			if err := json.Unmarshal(msg.Content, &parts); err != nil {
				return nil, "", false, fmt.Errorf("bad tool message content: %w", err)
			}
			for _, p := range parts {
				content += p.Text
			}
		}
		switch msg.Role {
		case "tool":
			results[msg.ToolCallID] += content
		case "user":
			user.WriteString(content)
		}
	}
	return results, user.String(), req.Stream, nil
}

func chatToolCalls(resp Resp) []any {
	var tc []any
	for i, c := range resp.Calls {
		tc = append(tc, map[string]any{
			"id": "call_" + c.Key, "type": "function", "index": i,
			"function": map[string]any{"name": c.Tool, "arguments": string(c.Input)},
		})
	}
	return tc
}

func chatRender(w http.ResponseWriter, m *Transcript, idx int, resp Resp, stream bool) {
	id := fmt.Sprintf("chatcmpl-%s-%d", m.Name, idx)
	finish := "stop"
	if resp.Stop == "tool_use" && len(resp.Calls) > 0 {
		finish = "tool_calls"
	}
	msg := map[string]any{"role": "assistant"}
	if resp.Text != "" {
		msg["content"] = resp.Text
	} else {
		msg["content"] = nil
	}
	if len(resp.Calls) > 0 {
		msg["tool_calls"] = chatToolCalls(resp)
	}
	if !stream {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": id, "object": "chat.completion", "created": createdAt, "model": m.Model,
			"choices": []any{map[string]any{"index": 0, "message": msg, "finish_reason": finish}},
			"usage":   map[string]int{"prompt_tokens": 100, "completion_tokens": usage(resp), "total_tokens": 100 + usage(resp)},
		})
		return
	}
	s := sse(w)
	chunk := func(delta map[string]any, finish any) {
		b, _ := json.Marshal(map[string]any{
			"id": id, "object": "chat.completion.chunk", "created": createdAt, "model": m.Model,
			"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}},
		})
		_, _ = fmt.Fprintf(s.w, "data: %s\n\n", b)
		if s.fl != nil {
			s.fl.Flush()
		}
	}
	chunk(map[string]any{"role": "assistant"}, nil)
	if resp.Text != "" {
		for _, frag := range chunks(resp.Text) {
			chunk(map[string]any{"content": frag}, nil)
		}
	}
	for i, c := range resp.Calls {
		chunk(map[string]any{"tool_calls": []any{map[string]any{
			"index": i, "id": "call_" + c.Key, "type": "function",
			"function": map[string]any{"name": c.Tool, "arguments": ""},
		}}}, nil)
		for _, frag := range chunks(string(c.Input)) {
			chunk(map[string]any{"tool_calls": []any{map[string]any{
				"index": i, "function": map[string]any{"arguments": frag},
			}}}, nil)
		}
	}
	chunk(map[string]any{}, finish)
	_, _ = fmt.Fprint(s.w, "data: [DONE]\n\n")
	if s.fl != nil {
		s.fl.Flush()
	}
}
