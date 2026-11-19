// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"encoding/json"
	"fmt"
)

// Anthropic Messages response parsing (spec/04 §5.1, M8.1).
//
// Streaming (text/event-stream): events message_start, content_block_*,
// message_delta, message_stop, ping, error per the pinned upstream doc.
// content_block_start opens a block at index; input_json_delta fragments
// accumulate; content_block_stop completes the block — that event's first
// byte is the hold point. Unknown event names and block types are ignored
// (never intents, never unparsed). A provider `error` event is a terminal
// parse fault.
//
// Non-streaming (application/json): content[] elements are scanned while
// bytes arrive; a tool_use/server_tool_use element's closing '}' is the
// hold point.

// anthBlock is one open content block in an SSE stream.
type anthBlock struct {
	kind       string
	id, tool   string
	input      []byte // assembled input_json_delta fragments
	startInput []byte // raw "input" member from the start event, if any
	deltaSeen  bool
}

// anthExecutor maps a block type to an executor ("" = not intent-bearing).
func anthExecutor(kind string) string {
	switch kind {
	case "tool_use":
		return ExecutorSandbox
	case "server_tool_use":
		return ExecutorProvider
	}
	return ""
}

type anthParser struct {
	sse    bool
	model  string
	abs    int64
	ss     sseSplitter
	js     *jsonScanner
	blocks map[int]*anthBlock
	sawMsg bool // a message_start (SSE) was seen
	fin    bool // stream reached message_stop
	dead   bool // terminal fault
}

func newAnthropicParser(sse bool) *anthParser {
	p := &anthParser{sse: sse, blocks: map[int]*anthBlock{}}
	if !sse {
		p.js = newJSONScanner([]string{"content"}, nil, p.onMember)
	}
	return p
}

func (p *anthParser) Model() string { return p.model }

func (p *anthParser) Feed(b []byte) ([]Completion, error) {
	if p.dead {
		return nil, nil
	}
	if p.sse {
		return p.feedSSE(b)
	}
	return p.feedJSON(b)
}

// ---------------------------------------------------------------- SSE

type anthStartData struct {
	Index int `json:"index"`
	Block struct {
		Type  string          `json:"type"`
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"content_block"`
}

type anthDeltaData struct {
	Index int `json:"index"`
	Delta struct {
		Type        string `json:"type"`
		PartialJSON string `json:"partial_json"`
	} `json:"delta"`
}

func (p *anthParser) feedSSE(b []byte) ([]Completion, error) {
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

func (p *anthParser) event(ev *sseEvent) (*Completion, error) {
	name := ev.event
	if name == "" {
		// Streams may omit the event: line; the envelope's own type
		// carries the name then.
		var t struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(ev.data, &t) == nil {
			name = t.Type
		}
	}
	switch name {
	case "message_start":
		var d struct {
			Message struct {
				Model string `json:"model"`
			} `json:"message"`
		}
		if json.Unmarshal(ev.data, &d) == nil && d.Message.Model != "" {
			p.model = d.Message.Model
		}
		p.sawMsg = true
	case "content_block_start":
		var d anthStartData
		if err := json.Unmarshal(ev.data, &d); err != nil {
			return nil, parseErrf("content_block_start: %v", err)
		}
		if _, dup := p.blocks[d.Index]; dup {
			return nil, parseErrf("content_block_start: index %d already open", d.Index)
		}
		p.blocks[d.Index] = &anthBlock{
			kind: d.Block.Type, id: d.Block.ID, tool: d.Block.Name,
			startInput: append([]byte(nil), d.Block.Input...),
		}
	case "content_block_delta":
		var d anthDeltaData
		if err := json.Unmarshal(ev.data, &d); err != nil {
			return nil, parseErrf("content_block_delta: %v", err)
		}
		bl, ok := p.blocks[d.Index]
		if !ok {
			return nil, parseErrf("content_block_delta: index %d not open", d.Index)
		}
		if d.Delta.Type == "input_json_delta" {
			bl.input = append(bl.input, d.Delta.PartialJSON...)
			bl.deltaSeen = true
		}
		// Other delta types (text_delta, thinking_delta, signature_delta,
		// citations_delta) are ignored — only indexes are structural.
	case "content_block_stop":
		var d struct {
			Index int `json:"index"`
		}
		if err := json.Unmarshal(ev.data, &d); err != nil {
			return nil, parseErrf("content_block_stop: %v", err)
		}
		bl, ok := p.blocks[d.Index]
		if !ok {
			// Stop for a block never opened (or already closed): not
			// intent-bearing; tolerate as stream noise? No — a stop with
			// no start is malformed stream shape, like a delta for an
			// unknown index is not. Deltas for unknown indexes are
			// ignored because unknown BLOCK types may carry them; a stop
			// for an index never started means the stream lied about
			// structure.
			return nil, parseErrf("content_block_stop: index %d not open", d.Index)
		}
		delete(p.blocks, d.Index)
		return p.complete(bl, ev.start)
	case "error":
		var d struct {
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		cls := "error"
		if json.Unmarshal(ev.data, &d) == nil && d.Error.Type != "" {
			cls = d.Error.Type
		}
		return nil, parseErrf("provider error event: %s", cls)
	case "message_stop":
		p.fin = true
	case "message_delta", "ping", "content_block_start_ack", "":
		// Known lifecycle events; "" = event-less data frames.
	default:
		// Unknown event types are ignored (spec/04 §5.4 class of
		// tolerated shapes; C8.1.5).
	}
	return nil, nil
}

// complete finishes one closed block: assemble input (deltas win over
// the start-event partial object), digest it and emit the intent.
func (p *anthParser) complete(bl *anthBlock, holdAt int64) (*Completion, error) {
	exec := anthExecutor(bl.kind)
	if exec == "" {
		return nil, nil
	}
	input := bl.input
	if len(input) == 0 {
		input = bl.startInput
	}
	if len(input) == 0 {
		input = []byte("{}")
	}
	it, err := intentFrom(input)
	if err != nil {
		return nil, parseErrf("%s %s: input: %v", bl.kind, bl.id, err)
	}
	it.ID = bl.id
	it.Tool = bl.tool
	it.Executor = exec
	it.Model = p.model
	return &Completion{HoldAt: holdAt, Intent: it}, nil
}

// ---------------------------------------------------------------- JSON

func (p *anthParser) feedJSON(b []byte) ([]Completion, error) {
	var comps []Completion
	var ferr error
	p.js.onElem = func(member string, raw []byte, start, end int64) {
		if member != "content" || ferr != nil {
			return
		}
		var el struct {
			Type  string          `json:"type"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		}
		if err := json.Unmarshal(raw, &el); err != nil {
			ferr = parseErrf("content element: %v", err)
			return
		}
		exec := anthExecutor(el.Type)
		if exec == "" {
			return // text/thinking/unknown block types: ignored
		}
		input := el.Input
		if len(input) == 0 {
			input = []byte("{}")
		}
		it, err := intentFrom(input)
		if err != nil {
			ferr = parseErrf("%s %s: input: %v", el.Type, el.ID, err)
			return
		}
		it.ID = el.ID
		it.Tool = el.Name
		it.Executor = exec
		comps = append(comps, Completion{HoldAt: end - 1, Intent: it})
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

func (p *anthParser) onMember(name string, raw []byte) {
	if name == "model" {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			p.model = s
		}
	}
}

func (p *anthParser) Finish() (string, bool) {
	if p.dead {
		return "", true // fault already reported via Feed's error
	}
	if p.sse {
		if p.ss.pending() {
			return "anthropic stream: truncated mid-event", false
		}
		if len(p.blocks) != 0 {
			return "anthropic stream: cut inside a content block", false
		}
		if !p.sawMsg {
			return "anthropic stream: no message_start", false
		}
		if !p.fin {
			return "anthropic stream: ended before message_stop", false
		}
		return "", true
	}
	return p.js.finish()
}

// intentFrom builds the Intent fields that come from the input document
// itself: the RFC 8785 canonical digest (spec/04 §6.3 compares this) and
// the input's raw byte length as transmitted.
func intentFrom(raw []byte) (*Intent, error) {
	v, err := decodeCanon(raw)
	if err != nil {
		return nil, fmt.Errorf("not valid JSON: %v", err)
	}
	sha, err := canonSHA256(v)
	if err != nil {
		return nil, fmt.Errorf("cannot canonicalize input: %v", err)
	}
	return &Intent{InputRaw: raw, InputSHA256: sha}, nil
}
