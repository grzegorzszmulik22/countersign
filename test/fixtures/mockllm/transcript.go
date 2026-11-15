// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package mockllm

import (
	"encoding/json"
	"fmt"
	"os"
)

// Transcript is a scenario served turn by turn (M0.3). One Transcript is the
// input side of test/vectors/transcripts/reference.scenario.json; the
// reference.<shape>.golden files hold the exact response bytes per shape.
type Transcript struct {
	Version int    `json:"version"`
	Name    string `json:"name"`
	Model   string `json:"model"`
	Turns   []Turn `json:"turns"`
}

// Turn is one model round-trip. Expect describes what the incoming request
// must carry (tool results for calls issued in earlier turns, keyed by the
// call's transcript key); Response is what the server emits.
type Turn struct {
	ExpectUserContains string            `json:"expect_user_contains,omitempty"`
	ExpectResults      map[string]string `json:"expect_results,omitempty"`
	Response           Resp              `json:"response"`
	// ConditionalResponse, when non-empty and the --conditional flag enables
	// it, replaces Response iff the request context contains Marker (M12.5).
	ConditionalResponse *CondResp `json:"conditional_response,omitempty"`
}

// CondResp is a response gated on a context marker.
type CondResp struct {
	Marker   string `json:"marker"`
	Response Resp   `json:"response"`
}

// Resp is a model turn: optional text plus zero or more tool calls, and the
// stop reason mapped per API shape.
type Resp struct {
	Stop  string `json:"stop"` // "tool_use" | "end_turn"
	Text  string `json:"text,omitempty"`
	Calls []Call `json:"calls,omitempty"`
}

// Call is one tool call. Key is the transcript-local identifier; on the wire
// it becomes toolu_<key> (Anthropic) or call_<key>/fc_<key> (OpenAI).
type Call struct {
	Key   string          `json:"key"`
	Tool  string          `json:"tool"`
	Input json.RawMessage `json:"input"`
}

// LoadTranscript parses a scenario file.
func LoadTranscript(path string) (*Transcript, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Transcript
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("transcript %s: %w", path, err)
	}
	if t.Model == "" {
		t.Model = "fixture-model-1"
	}
	for i, tn := range t.Turns {
		for j, c := range tn.Response.Calls {
			if c.Key == "" || c.Tool == "" || len(c.Input) == 0 {
				return nil, fmt.Errorf("transcript %s: turn %d call %d missing key/tool/input", path, i, j)
			}
		}
	}
	return &t, nil
}
