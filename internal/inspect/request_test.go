// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestParseAnthropicRequest checks block enumeration, result detection
// and that no content text is captured (digests + lengths only).
func TestParseAnthropicRequest(t *testing.T) {
	body := []byte(`{
	  "model": "claude-test",
	  "system": [{"type":"text","text":"sys prompt SECRET-MARK"}],
	  "messages": [
	    {"role":"user","content":"do it SECRET-MARK-2"},
	    {"role":"assistant","content":[
	      {"type":"text","text":"I will SECRET-MARK-3"},
	      {"type":"tool_use","id":"toolu_x","name":"Bash","input":{"command":"ls SECRET-MARK-4"}}
	    ]},
	    {"role":"user","content":[
	      {"type":"tool_result","tool_use_id":"toolu_x","content":"out text SECRET-MARK-5","is_error":false}
	    ]}
	  ]
	}`)
	info, err := ParseRequest(EndpointAnthropic, body)
	if err != nil {
		t.Fatal(err)
	}
	if info.Model != "claude-test" {
		t.Fatalf("model %q", info.Model)
	}
	if len(info.Blocks) != 5 {
		t.Fatalf("blocks = %d, want 5: %+v", len(info.Blocks), info.Blocks)
	}
	if info.Blocks[0].Role != "system" || info.Blocks[1].Role != "user" ||
		info.Blocks[2].Role != "assistant" {
		t.Fatalf("roles: %+v", info.Blocks)
	}
	if info.Blocks[3].IntentID != "toolu_x" || info.Blocks[3].Kind != "tool_use" {
		t.Fatalf("tool_use block: %+v", info.Blocks[3])
	}
	if len(info.Results) != 1 {
		t.Fatalf("results: %+v", info.Results)
	}
	tr := info.Results[0]
	if tr.IntentID != "toolu_x" || !tr.HasContent {
		t.Fatalf("result: %+v", tr)
	}
	sum := sha256.Sum256([]byte("out text SECRET-MARK-5"))
	if tr.ContentSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("content sha %q", tr.ContentSHA256)
	}
	if tr.ContentLen != len("out text SECRET-MARK-5") {
		t.Fatalf("content len %d", tr.ContentLen)
	}
	if tr.HasIsError != true || tr.IsError != false {
		t.Fatalf("is_error: %+v", tr)
	}
}

// TestParseResponsesRequest: function_call_output closes by call_id.
func TestParseResponsesRequest(t *testing.T) {
	body := []byte(`{
	  "model": "gpt-test",
	  "input": [
	    {"type":"message","role":"user","content":[{"type":"input_text","text":"run it"}]},
	    {"type":"function_call","call_id":"call_9","name":"run","arguments":"{}"},
	    {"type":"function_call_output","call_id":"call_9","output":"done ok"}
	  ]
	}`)
	info, err := ParseRequest(EndpointResponses, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Results) != 1 || info.Results[0].IntentID != "call_9" {
		t.Fatalf("results: %+v", info.Results)
	}
	if len(info.Blocks) != 3 {
		t.Fatalf("blocks: %+v", info.Blocks)
	}
}

// TestParseChatRequest: role tool closes by tool_call_id.
func TestParseChatRequest(t *testing.T) {
	body := []byte(`{
	  "model": "gpt-test",
	  "messages": [
	    {"role":"user","content":"go"},
	    {"role":"assistant","content":null,"tool_calls":[
	      {"id":"call_7","type":"function","function":{"name":"run","arguments":"{}"}}]},
	    {"role":"tool","tool_call_id":"call_7","content":"result text"}
	  ]
	}`)
	info, err := ParseRequest(EndpointChat, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Results) != 1 || info.Results[0].IntentID != "call_7" {
		t.Fatalf("results: %+v", info.Results)
	}
	if info.Results[0].ContentLen != len("result text") {
		t.Fatalf("content len: %+v", info.Results[0])
	}
	var nCall int
	for _, b := range info.Blocks {
		if b.Kind == "tool_call" {
			nCall++
			if b.IntentID != "call_7" {
				t.Fatalf("tool_call block intent_id: %+v", b)
			}
		}
	}
	if nCall != 1 {
		t.Fatalf("blocks: %+v", info.Blocks)
	}
}

// TestParseRequestGarbage: a non-JSON body is a parse failure.
func TestParseRequestGarbage(t *testing.T) {
	if _, err := ParseRequest(EndpointAnthropic, []byte("{nope")); err == nil {
		t.Fatal("garbage accepted")
	}
}
