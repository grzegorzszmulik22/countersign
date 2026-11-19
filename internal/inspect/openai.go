// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"encoding/json"
	"sort"
	"strings"
)

// OpenAI Responses + Chat Completions response parsing (spec/04 §5.1, M8.2).
//
// Responses streaming: response.output_item.added opens an item at
// output_index; response.function_call_arguments.{delta,done} carry the
// arguments; response.output_item.done completes the item — that event's
// first byte is the hold point. Provider-hosted calls (*_call types other
// than function_call) yield executor "provider".
//
// Responses non-streaming: output[] elements scanned as bytes arrive; a
// call item's closing '}' is the hold point.
//
// Chat Completions: tool_calls[] elements (JSON) or streamed tool_call
// deltas keyed by index within each choice; the chunk event carrying a
// non-null finish_reason completes every accumulated call of that choice.

// respExecutor maps a Responses output-item type to an executor ("" =
// not intent-bearing).
func respExecutor(t string) string {
	switch t {
	case "function_call", "custom_tool_call":
		return ExecutorSandbox
	case "web_search_call", "file_search_call", "computer_call",
		"code_interpreter_call", "mcp_call", "local_shell_call",
		"shell_call", "image_generation_call":
		return ExecutorProvider
	}
	return ""
}

// respItemWire is the subset of a Responses output item the parser
// reads; raw members keep the exact transmitted serialization for
// input_len and previews.
type respItemWire struct {
	Type      string          `json:"type"`
	ID        string          `json:"id"`
	CallID    string          `json:"call_id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	Input     json.RawMessage `json:"input"`
	Action    json.RawMessage `json:"action"`

	raw json.RawMessage // the item's own transmitted bytes
}

func (w *respItemWire) id() string {
	if w.CallID != "" {
		return w.CallID
	}
	return w.ID
}

// inputRaw returns the item's input member as transmitted: arguments
// (a JSON string for function_call), then input, then action, then —
// for call shapes with none — the item itself.
func (w *respItemWire) inputRaw() json.RawMessage {
	for _, m := range []json.RawMessage{w.Arguments, w.Input, w.Action} {
		if len(m) > 0 {
			return m
		}
	}
	return w.raw
}

// intentFromItem digests one call input that arrived as a string:
// function-call arguments or a custom tool's freeform input. A string
// carrying a JSON document digests the document; any other string is
// itself the input value (canonicalization of the string is honest,
// never a rewrite).
func intentFromItem(s string) (*Intent, error) {
	if doc, err := decodeCanon([]byte(s)); err == nil {
		sha, err := canonSHA256(doc)
		if err != nil {
			return nil, err
		}
		return &Intent{InputRaw: []byte(s), InputSHA256: sha}, nil
	}
	sha, err := canonSHA256(s)
	if err != nil {
		return nil, err
	}
	return &Intent{InputRaw: []byte(s), InputSHA256: sha}, nil
}

// intentFromItemRaw digests one call input still in its wire encoding:
// a string member decodes to its value and runs through intentFromItem;
// anything else canonicalizes the raw bytes directly (InputRaw = the
// transmitted member bytes).
func intentFromItemRaw(raw json.RawMessage) (*Intent, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return intentFrom([]byte("{}"))
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		return intentFromItem(s)
	}
	return intentFrom(raw)
}

// ------------------------------------------------------------------
// Responses API

type respItemState struct {
	kind     string
	args     []byte // assembled delta fragments
	doneArgs string // arguments from function_call_arguments.done
	hasDone  bool
	item     *respItemWire // the added item (may be partial)
}

type respParser struct {
	sse   bool
	model string
	abs   int64
	ss    sseSplitter
	js    *jsonScanner
	items map[int]*respItemState
	fin   bool
	dead  bool
}

func newResponsesParser(sse bool) *respParser {
	p := &respParser{sse: sse, items: map[int]*respItemState{}}
	if !sse {
		p.js = newJSONScanner([]string{"output"}, nil, nil)
	}
	return p
}

func (p *respParser) Model() string { return p.model }

func (p *respParser) Feed(b []byte) ([]Completion, error) {
	if p.dead {
		return nil, nil
	}
	if p.sse {
		return p.feedSSE(b)
	}
	return p.feedJSON(b)
}

func (p *respParser) feedSSE(b []byte) ([]Completion, error) {
	evs, err := p.ss.feed(b)
	p.abs += int64(len(b))
	var comps []Completion
	for i := range evs {
		c, perr := p.event(&evs[i])
		if c != nil {
			comps = append(comps, *c)
		}
		if perr != nil {
			p.dead = true
			return comps, perr
		}
	}
	return comps, err
}

func (p *respParser) event(ev *sseEvent) (*Completion, error) {
	name := ev.event
	if name == "" {
		var t struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(ev.data, &t) == nil {
			name = t.Type
		}
	}
	switch name {
	case "response.created", "response.in_progress":
		var d struct {
			Response struct {
				Model string `json:"model"`
			} `json:"response"`
		}
		if json.Unmarshal(ev.data, &d) == nil && d.Response.Model != "" {
			p.model = d.Response.Model
		}
	case "response.output_item.added":
		var d struct {
			OutputIndex int             `json:"output_index"`
			Item        json.RawMessage `json:"item"`
		}
		if err := json.Unmarshal(ev.data, &d); err != nil {
			return nil, parseErrf("output_item.added: %v", err)
		}
		var w respItemWire
		if err := json.Unmarshal(d.Item, &w); err != nil {
			return nil, parseErrf("output_item.added: %v", err)
		}
		if respExecutor(w.Type) != "" {
			w.raw = d.Item
			p.items[d.OutputIndex] = &respItemState{kind: w.Type, item: &w}
		}
	case "response.function_call_arguments.delta":
		var d struct {
			OutputIndex int    `json:"output_index"`
			Delta       string `json:"delta"`
		}
		if err := json.Unmarshal(ev.data, &d); err != nil {
			return nil, parseErrf("function_call_arguments.delta: %v", err)
		}
		it, ok := p.items[d.OutputIndex]
		if !ok {
			return nil, parseErrf("function_call_arguments.delta: index %d not open", d.OutputIndex)
		}
		it.args = append(it.args, d.Delta...)
	case "response.function_call_arguments.done":
		var d struct {
			OutputIndex int    `json:"output_index"`
			Arguments   string `json:"arguments"`
		}
		if err := json.Unmarshal(ev.data, &d); err != nil {
			return nil, parseErrf("function_call_arguments.done: %v", err)
		}
		it, ok := p.items[d.OutputIndex]
		if !ok {
			return nil, parseErrf("function_call_arguments.done: index %d not open", d.OutputIndex)
		}
		it.doneArgs = d.Arguments
		it.hasDone = true
	case "response.output_item.done":
		var d struct {
			OutputIndex int             `json:"output_index"`
			Item        json.RawMessage `json:"item"`
		}
		if err := json.Unmarshal(ev.data, &d); err != nil {
			return nil, parseErrf("output_item.done: %v", err)
		}
		var w respItemWire
		if err := json.Unmarshal(d.Item, &w); err != nil {
			return nil, parseErrf("output_item.done: %v", err)
		}
		w.raw = d.Item
		it, ok := p.items[d.OutputIndex]
		if !ok {
			if respExecutor(w.Type) != "" {
				// The added event never arrived, but done carries the
				// complete item — the provider's declaration is whole.
				return p.complete(&respItemState{kind: w.Type, item: &w}, &w, ev.start)
			}
			return nil, nil // non-call item (message, reasoning, ...)
		}
		delete(p.items, d.OutputIndex)
		return p.complete(it, &w, ev.start)
	case "response.completed", "response.incomplete", "response.failed":
		p.fin = true
	case "error":
		var d struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		cls := "error"
		if json.Unmarshal(ev.data, &d) == nil && d.Code != "" {
			cls = d.Code
		}
		return nil, parseErrf("provider error event: %s", cls)
	case "":
		// event-less data frames
	default:
		// All other Responses events (output_text.*, content_part.*,
		// reasoning.*, web_search_call.*, rate_limits, ...) are ignored.
	}
	return nil, nil
}

// complete emits the intent for one done output item. doneArgs (from
// function_call_arguments.done) beats assembled deltas, which beat the
// done item's own input members, then the added item's.
func (p *respParser) complete(st *respItemState, doneItem *respItemWire, holdAt int64) (*Completion, error) {
	var it *Intent
	var err error
	switch {
	case st.hasDone:
		it, err = intentFromItem(st.doneArgs)
	case len(st.args) > 0:
		it, err = intentFromItem(string(st.args))
	default:
		in := doneItem.inputRaw()
		if len(in) == 0 && st.item != nil {
			in = st.item.inputRaw()
		}
		it, err = intentFromItemRaw(in)
	}
	if err != nil {
		return nil, parseErrf("%s: input: %v", st.kind, err)
	}
	it.ID = doneItem.id()
	if it.ID == "" && st.item != nil {
		it.ID = st.item.id()
	}
	it.Tool = doneItem.Name
	if it.Tool == "" && st.item != nil {
		it.Tool = st.item.Name
	}
	if it.Tool == "" {
		it.Tool = st.kind
	}
	it.Executor = respExecutor(st.kind)
	it.Model = p.model
	return &Completion{HoldAt: holdAt, Intent: it}, nil
}

func (p *respParser) feedJSON(b []byte) ([]Completion, error) {
	var comps []Completion
	var ferr error
	p.js.onElem = func(member string, raw []byte, start, end int64) {
		if member != "output" || ferr != nil {
			return
		}
		var w respItemWire
		if err := json.Unmarshal(raw, &w); err != nil {
			ferr = parseErrf("output element: %v", err)
			return
		}
		exec := respExecutor(w.Type)
		if exec == "" {
			return
		}
		w.raw = raw
		it, err := intentFromItemRaw(w.inputRaw())
		if err != nil {
			ferr = parseErrf("%s: input: %v", w.Type, err)
			return
		}
		it.ID = w.id()
		it.Tool = w.Name
		if it.Tool == "" {
			it.Tool = w.Type
		}
		it.Executor = exec
		comps = append(comps, Completion{HoldAt: end - 1, Intent: it})
	}
	p.js.onMember = func(name string, raw []byte) {
		if name == "model" {
			var s string
			if json.Unmarshal(raw, &s) == nil {
				p.model = s
			}
		}
	}
	if err := p.js.feed(b); err != nil {
		p.dead = true
		return comps, err
	}
	if ferr != nil {
		p.dead = true
		return comps, ferr
	}
	for i := range comps {
		comps[i].Intent.Model = p.model
	}
	return comps, nil
}

func (p *respParser) Finish() (string, bool) {
	if p.dead {
		return "", true
	}
	if p.sse {
		if p.ss.pending() {
			return "responses stream: truncated mid-event", false
		}
		if len(p.items) != 0 {
			return "responses stream: cut with an output item open", false
		}
		if !p.fin {
			return "responses stream: ended before response.completed", false
		}
		return "", true
	}
	return p.js.finish()
}

// ------------------------------------------------------------------
// Chat Completions

// chatCall is one streamed tool_call under assembly (keyed by its index
// inside the choice's tool_calls array — arrival order is meaningless).
type chatCall struct {
	id, typ, name string
	args          []byte
}

type chatParser struct {
	sse   bool
	model string
	abs   int64
	ss    sseSplitter
	js    *jsonScanner
	calls map[int]map[int]*chatCall // choice index -> tool_call index -> state
	fin   bool
	dead  bool
}

func newChatParser(sse bool) *chatParser {
	p := &chatParser{sse: sse, calls: map[int]map[int]*chatCall{}}
	if !sse {
		p.js = newJSONScanner([]string{"tool_calls"}, nil, nil)
	}
	return p
}

func (p *chatParser) Model() string { return p.model }

func (p *chatParser) Feed(b []byte) ([]Completion, error) {
	if p.dead {
		return nil, nil
	}
	if p.sse {
		return p.feedSSE(b)
	}
	return p.feedJSON(b)
}

type chatChunk struct {
	Model   string `json:"model"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			ToolCalls []struct {
				Index    int    `json:"index"`
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
}

func (p *chatParser) feedSSE(b []byte) ([]Completion, error) {
	evs, err := p.ss.feed(b)
	p.abs += int64(len(b))
	var comps []Completion
	for i := range evs {
		if strings.TrimSpace(string(evs[i].data)) == "[DONE]" {
			p.fin = true
			continue
		}
		cs, perr := p.chunk(&evs[i])
		comps = append(comps, cs...)
		if perr != nil {
			p.dead = true
			return comps, perr
		}
	}
	return comps, err
}

// chunk merges one streamed chunk's deltas and completes the choice's
// calls when its finish_reason lands.
func (p *chatParser) chunk(ev *sseEvent) ([]Completion, error) {
	var d chatChunk
	if err := json.Unmarshal(ev.data, &d); err != nil {
		return nil, parseErrf("chat chunk: %v", err)
	}
	var errObj struct {
		Error struct {
			Type    string `json:"type"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(ev.data, &errObj) == nil && errObj.Error.Type != "" {
		return nil, parseErrf("provider error event: %s", errObj.Error.Type)
	}
	if d.Model != "" {
		p.model = d.Model
	}
	var comps []Completion
	for _, ch := range d.Choices {
		if p.calls[ch.Index] == nil {
			p.calls[ch.Index] = map[int]*chatCall{}
		}
		for _, tc := range ch.Delta.ToolCalls {
			cc := p.calls[ch.Index][tc.Index]
			if cc == nil {
				cc = &chatCall{}
				p.calls[ch.Index][tc.Index] = cc
			}
			if tc.ID != "" {
				cc.id = tc.ID
			}
			if tc.Type != "" {
				cc.typ = tc.Type
			}
			if tc.Function.Name != "" {
				cc.name = tc.Function.Name
			}
			cc.args = append(cc.args, tc.Function.Arguments...)
		}
		if ch.FinishReason != nil {
			c, err := p.finishChoice(ch.Index, ev.start)
			if err != nil {
				return comps, err
			}
			comps = append(comps, c...)
			p.fin = true
		}
	}
	return comps, nil
}

// finishChoice emits intents for every call accumulated under a choice,
// in tool_call index order (interleaved fragments reassemble by index).
func (p *chatParser) finishChoice(choice int, holdAt int64) ([]Completion, error) {
	m := p.calls[choice]
	delete(p.calls, choice)
	idx := make([]int, 0, len(m))
	for i := range m {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	var comps []Completion
	for _, i := range idx {
		cc := m[i]
		it, err := intentFromItem(string(cc.args))
		if err != nil {
			return comps, parseErrf("tool_call %d: arguments: %v", i, err)
		}
		it.ID = cc.id
		it.Tool = cc.name
		if cc.typ == "" || cc.typ == "function" {
			it.Executor = ExecutorSandbox
		} else {
			it.Executor = ExecutorProvider
		}
		it.Model = p.model
		comps = append(comps, Completion{HoldAt: holdAt, Intent: it})
	}
	return comps, nil
}

func (p *chatParser) feedJSON(b []byte) ([]Completion, error) {
	var comps []Completion
	var ferr error
	p.js.onElem = func(member string, raw []byte, start, end int64) {
		if member != "tool_calls" || ferr != nil {
			return
		}
		var tc struct {
			ID       string `json:"id"`
			Type     string `json:"type"`
			Function struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			} `json:"function"`
		}
		if err := json.Unmarshal(raw, &tc); err != nil {
			ferr = parseErrf("tool_calls element: %v", err)
			return
		}
		it, err := intentFromItem(tc.Function.Arguments)
		if err != nil {
			ferr = parseErrf("tool_call %s: arguments: %v", tc.ID, err)
			return
		}
		it.ID = tc.ID
		it.Tool = tc.Function.Name
		if tc.Type == "" || tc.Type == "function" {
			it.Executor = ExecutorSandbox
		} else {
			it.Executor = ExecutorProvider
		}
		comps = append(comps, Completion{HoldAt: end - 1, Intent: it})
	}
	p.js.onMember = func(name string, raw []byte) {
		if name == "model" {
			var s string
			if json.Unmarshal(raw, &s) == nil {
				p.model = s
			}
		}
	}
	if err := p.js.feed(b); err != nil {
		p.dead = true
		return comps, err
	}
	if ferr != nil {
		p.dead = true
		return comps, ferr
	}
	for i := range comps {
		comps[i].Intent.Model = p.model
	}
	return comps, nil
}

func (p *chatParser) Finish() (string, bool) {
	if p.dead {
		return "", true
	}
	if p.sse {
		if p.ss.pending() {
			return "chat stream: truncated mid-event", false
		}
		if len(p.calls) != 0 {
			// Tool-call deltas never closed by finish_reason: the stream
			// cut inside a call — nothing fabricated, record unparsed.
			return "chat stream: cut inside a tool_call", false
		}
		if !p.fin {
			return "chat stream: ended without [DONE]", false
		}
		return "", true
	}
	return p.js.finish()
}
