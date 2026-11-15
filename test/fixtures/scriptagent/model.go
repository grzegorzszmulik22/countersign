// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package scriptagent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// Call is one tool call requested by the model. ID is the wire identifier
// results must reference (toolu_*, call_*); ItemID is the Responses API
// output-item id (fc_*) echoed back in history.
type Call struct {
	ID     string
	ItemID string
	Name   string
	Input  json.RawMessage
}

// result is one executed tool call.
type result struct {
	ID      string
	Content string
}

// turn is one assistant response: text plus requested calls.
type turn struct {
	Text  string
	Calls []Call
}

// msg is a normalized conversation-history item.
type msg struct {
	kind    string // "prompt" | "assistant" | "results"
	text    string
	calls   []Call
	results []result
}

// toolDef is a normalized tool descriptor rendered per API shape.
type toolDef struct {
	Name        string
	Description string
	Schema      map[string]any
}

// driver renders history into a provider request body and parses responses.
type driver interface {
	path() string
	setAuth(r *http.Request)
	body(hist []msg, model string, stream bool, tools []toolDef) ([]byte, error)
	parse(b []byte) (turn, error)
	parseStream(r io.Reader) (turn, error)
}

func driverFor(api string) (driver, error) {
	switch api {
	case "anthropic":
		return anthropicDriver{key: os.Getenv("ANTHROPIC_API_KEY")}, nil
	case "openai-responses":
		return responsesDriver{key: os.Getenv("OPENAI_API_KEY")}, nil
	case "openai-chat":
		return chatDriver{key: os.Getenv("OPENAI_API_KEY")}, nil
	}
	return nil, fmt.Errorf("unknown --api %q (anthropic|openai-responses|openai-chat)", api)
}

// ---------------------------------------------------------------------------
// Anthropic Messages
// ---------------------------------------------------------------------------

type anthropicDriver struct{ key string }

func (anthropicDriver) path() string { return "/v1/messages" }

func (d anthropicDriver) setAuth(r *http.Request) {
	if d.key != "" {
		r.Header.Set("x-api-key", d.key)
	}
	r.Header.Set("anthropic-version", "2023-06-01")
}

func (anthropicDriver) body(hist []msg, model string, stream bool, tools []toolDef) ([]byte, error) {
	var msgs []any
	for _, m := range hist {
		switch m.kind {
		case "prompt":
			msgs = append(msgs, map[string]any{"role": "user", "content": m.text})
		case "assistant":
			var blocks []any
			if m.text != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": m.text})
			}
			for _, c := range m.calls {
				blocks = append(blocks, map[string]any{
					"type": "tool_use", "id": c.ID, "name": c.Name, "input": c.Input})
			}
			if blocks == nil {
				blocks = []any{}
			}
			msgs = append(msgs, map[string]any{"role": "assistant", "content": blocks})
		case "results":
			var blocks []any
			for _, r := range m.results {
				blocks = append(blocks, map[string]any{
					"type": "tool_result", "tool_use_id": r.ID, "content": r.Content})
			}
			if blocks == nil {
				blocks = []any{}
			}
			msgs = append(msgs, map[string]any{"role": "user", "content": blocks})
		}
	}
	out := map[string]any{"model": model, "max_tokens": 4096, "stream": stream, "messages": msgs}
	if len(tools) > 0 {
		var tdefs []any
		for _, t := range tools {
			tdefs = append(tdefs, map[string]any{
				"name": t.Name, "description": t.Description, "input_schema": t.Schema})
		}
		out["tools"] = tdefs
	}
	return json.Marshal(out)
}

func (anthropicDriver) parse(b []byte) (turn, error) {
	var v struct {
		Content []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return turn{}, fmt.Errorf("anthropic response: %w", err)
	}
	var t turn
	for _, blk := range v.Content {
		switch blk.Type {
		case "text":
			t.Text += blk.Text
		case "tool_use":
			t.Calls = append(t.Calls, Call{ID: blk.ID, Name: blk.Name, Input: blk.Input})
		}
	}
	return t, nil
}

// parseStream reads Anthropic SSE: content_block_start/delta/stop assemble
// blocks; message_delta carries stop_reason; message_stop ends.
func (anthropicDriver) parseStream(r io.Reader) (turn, error) {
	var t turn
	open := map[int]*Call{}
	order := []int{}
	err := readSSE(r, func(ev string, data []byte) bool {
		var d struct {
			Type         string          `json:"type"`
			Index        int             `json:"index"`
			ContentBlock json.RawMessage `json:"content_block"`
			Delta        json.RawMessage `json:"delta"`
		}
		if json.Unmarshal(data, &d) != nil {
			return true
		}
		switch d.Type {
		case "content_block_start":
			var blk struct {
				Type string `json:"type"`
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if json.Unmarshal(d.ContentBlock, &blk) == nil && blk.Type == "tool_use" {
				open[d.Index] = &Call{ID: blk.ID, Name: blk.Name, Input: json.RawMessage("")}
				order = append(order, d.Index)
			}
		case "content_block_delta":
			var dd struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
			}
			if json.Unmarshal(d.Delta, &dd) != nil {
				return true
			}
			switch dd.Type {
			case "text_delta":
				t.Text += dd.Text
			case "input_json_delta":
				if c, ok := open[d.Index]; ok {
					c.Input = append(c.Input, dd.PartialJSON...)
				}
			}
		case "content_block_stop":
			if c, ok := open[d.Index]; ok {
				if len(c.Input) == 0 {
					c.Input = json.RawMessage("{}")
				}
				t.Calls = append(t.Calls, *c)
				delete(open, d.Index)
			}
		}
		return d.Type != "message_stop"
	})
	if err != nil {
		return t, err
	}
	return t, nil
}

// ---------------------------------------------------------------------------
// OpenAI Responses
// ---------------------------------------------------------------------------

type responsesDriver struct{ key string }

func (responsesDriver) path() string { return "/v1/responses" }

func (d responsesDriver) setAuth(r *http.Request) {
	if d.key != "" {
		r.Header.Set("Authorization", "Bearer "+d.key)
	}
}

func (responsesDriver) body(hist []msg, model string, stream bool, tools []toolDef) ([]byte, error) {
	var input []any
	for _, m := range hist {
		switch m.kind {
		case "prompt":
			input = append(input, map[string]any{"type": "message", "role": "user", "content": m.text})
		case "assistant":
			if m.text != "" {
				input = append(input, map[string]any{"type": "message", "role": "assistant",
					"content": []any{map[string]any{"type": "output_text", "text": m.text}}})
			}
			for _, c := range m.calls {
				itemID := c.ItemID
				if itemID == "" {
					itemID = "fc_" + strings.TrimPrefix(c.ID, "call_")
				}
				input = append(input, map[string]any{
					"type": "function_call", "id": itemID, "call_id": c.ID,
					"name": c.Name, "arguments": string(c.Input), "status": "completed"})
			}
		case "results":
			for _, r := range m.results {
				input = append(input, map[string]any{
					"type": "function_call_output", "call_id": r.ID, "output": r.Content})
			}
		}
	}
	out := map[string]any{"model": model, "stream": stream, "input": input}
	if len(tools) > 0 {
		var tdefs []any
		for _, t := range tools {
			tdefs = append(tdefs, map[string]any{
				"type": "function", "name": t.Name,
				"description": t.Description, "parameters": t.Schema})
		}
		out["tools"] = tdefs
	}
	return json.Marshal(out)
}

func responsesTurn(output []any) (turn, error) {
	var t turn
	for _, raw := range output {
		b, _ := json.Marshal(raw)
		var it struct {
			Type      string `json:"type"`
			ID        string `json:"id"`
			CallID    string `json:"call_id"`
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
			Content   []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if json.Unmarshal(b, &it) != nil {
			continue
		}
		switch it.Type {
		case "function_call":
			t.Calls = append(t.Calls, Call{
				ID: it.CallID, ItemID: it.ID, Name: it.Name,
				Input: json.RawMessage(it.Arguments)})
		case "message":
			for _, c := range it.Content {
				if c.Type == "output_text" || c.Type == "text" {
					t.Text += c.Text
				}
			}
		}
	}
	return t, nil
}

func (responsesDriver) parse(b []byte) (turn, error) {
	var v struct {
		Output []any `json:"output"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return turn{}, fmt.Errorf("responses response: %w", err)
	}
	return responsesTurn(v.Output)
}

// parseStream buffers until response.completed, which carries the full
// response object; delta events need no assembly.
func (responsesDriver) parseStream(r io.Reader) (turn, error) {
	var t turn
	err := readSSE(r, func(ev string, data []byte) bool {
		var d struct {
			Type     string `json:"type"`
			Response struct {
				Output []any `json:"output"`
			} `json:"response"`
		}
		if json.Unmarshal(data, &d) != nil {
			return true
		}
		if d.Type == "response.completed" {
			tt, err := responsesTurn(d.Response.Output)
			if err == nil {
				t = tt
			}
			return false
		}
		return true
	})
	return t, err
}

// ---------------------------------------------------------------------------
// OpenAI Chat Completions
// ---------------------------------------------------------------------------

type chatDriver struct{ key string }

func (chatDriver) path() string { return "/v1/chat/completions" }

func (d chatDriver) setAuth(r *http.Request) {
	if d.key != "" {
		r.Header.Set("Authorization", "Bearer "+d.key)
	}
}

func (chatDriver) body(hist []msg, model string, stream bool, tools []toolDef) ([]byte, error) {
	var msgs []any
	for _, m := range hist {
		switch m.kind {
		case "prompt":
			msgs = append(msgs, map[string]any{"role": "user", "content": m.text})
		case "assistant":
			am := map[string]any{"role": "assistant"}
			if m.text != "" {
				am["content"] = m.text
			} else {
				am["content"] = nil
			}
			if len(m.calls) > 0 {
				var tcs []any
				for i, c := range m.calls {
					tcs = append(tcs, map[string]any{
						"id": c.ID, "type": "function", "index": i,
						"function": map[string]any{"name": c.Name, "arguments": string(c.Input)}})
				}
				am["tool_calls"] = tcs
			}
			msgs = append(msgs, am)
		case "results":
			for _, r := range m.results {
				msgs = append(msgs, map[string]any{
					"role": "tool", "tool_call_id": r.ID, "content": r.Content})
			}
		}
	}
	out := map[string]any{"model": model, "stream": stream, "messages": msgs}
	if len(tools) > 0 {
		var tdefs []any
		for _, t := range tools {
			tdefs = append(tdefs, map[string]any{
				"type": "function",
				"function": map[string]any{
					"name": t.Name, "description": t.Description, "parameters": t.Schema}})
		}
		out["tools"] = tdefs
	}
	return json.Marshal(out)
}

func (chatDriver) parse(b []byte) (turn, error) {
	var v struct {
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return turn{}, fmt.Errorf("chat response: %w", err)
	}
	var t turn
	if len(v.Choices) > 0 {
		m := v.Choices[0].Message
		t.Text = m.Content
		for _, tc := range m.ToolCalls {
			t.Calls = append(t.Calls, Call{
				ID: tc.ID, Name: tc.Function.Name,
				Input: json.RawMessage(tc.Function.Arguments)})
		}
	}
	return t, nil
}

// parseStream accumulates chat.completion.chunk deltas: tool_calls keyed by
// index (id/name on the first chunk, arguments as fragments) until [DONE].
func (chatDriver) parseStream(r io.Reader) (turn, error) {
	var t turn
	byIdx := map[int]*Call{}
	order := []int{}
	err := readSSE(r, func(ev string, data []byte) bool {
		if string(bytes.TrimSpace(data)) == "[DONE]" {
			return false
		}
		var d struct {
			Choices []struct {
				Delta struct {
					Content   string `json:"content"`
					ToolCalls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal(data, &d) != nil || len(d.Choices) == 0 {
			return true
		}
		dl := d.Choices[0].Delta
		t.Text += dl.Content
		for _, tc := range dl.ToolCalls {
			c, ok := byIdx[tc.Index]
			if !ok {
				c = &Call{Input: json.RawMessage("")}
				byIdx[tc.Index] = c
				order = append(order, tc.Index)
			}
			if tc.ID != "" {
				c.ID = tc.ID
			}
			if tc.Function.Name != "" {
				c.Name = tc.Function.Name
			}
			c.Input = append(c.Input, tc.Function.Arguments...)
		}
		return true
	})
	for _, i := range order {
		c := byIdx[i]
		if len(c.Input) == 0 {
			c.Input = json.RawMessage("{}")
		}
		t.Calls = append(t.Calls, *c)
	}
	return t, err
}

// ---------------------------------------------------------------------------
// SSE frames
// ---------------------------------------------------------------------------

// readSSE scans "event: x\ndata: y\n\n" frames and invokes cb until it
// returns false or the stream ends.
func readSSE(r io.Reader, cb func(event string, data []byte) bool) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var event string
	var data bytes.Buffer
	flush := func() bool {
		if data.Len() == 0 {
			return true
		}
		b := append([]byte(nil), data.Bytes()...)
		data.Reset()
		return cb(event, b)
	}
	cont := true
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data.WriteString(strings.TrimPrefix(line, "data:"))
			data.WriteString("\n")
		case line == "":
			cont = flush()
		}
		if !cont {
			return nil
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if data.Len() > 0 {
		flush()
	}
	return nil
}
