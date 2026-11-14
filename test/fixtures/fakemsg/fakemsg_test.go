// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package fakemsg

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/countersign/countersign/test/fixtures/fxtest"
)

func startMsg(t *testing.T, env *fxtest.Env) string {
	t.Helper()
	addr, err := New().Serve(env.Ctx, "127.0.0.1:0", env.Issue("api.slack.com", "127.0.0.1"))
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	env.Register("fakemsg", addr.String())
	return "https://" + addr.String()
}

func post(t *testing.T, env *fxtest.Env, base, body, key string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequestWithContext(env.Ctx, http.MethodPost, base+"/api/messages", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	res, err := env.Direct().Do(req)
	if err != nil {
		t.Fatalf("POST /api/messages: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	var v map[string]any
	_ = json.NewDecoder(res.Body).Decode(&v)
	return res, v
}

func TestC031Fakemsg(t *testing.T) {
	env := fxtest.NewEnv(t)
	base := startMsg(t, env)

	// Send returns an ID.
	res, v := post(t, env, base, `{"to":"#ops","text":"deploy ok"}`, "")
	if res.StatusCode != 201 || v["id"] == nil {
		t.Fatalf("send: status=%d body=%v", res.StatusCode, v)
	}
	id := v["id"].(string)

	// Reply referencing the parent ID.
	res, v = post(t, env, base, `{"to":"#ops","text":"ack","in_reply_to":"`+id+`"}`, "")
	if res.StatusCode != 201 {
		t.Fatalf("reply: status=%d body=%v", res.StatusCode, v)
	}

	// Bad parent reference is rejected.
	res, _ = post(t, env, base, `{"to":"#ops","text":"orphan","in_reply_to":"msg_9999"}`, "")
	if res.StatusCode != 404 {
		t.Fatalf("bad parent: status=%d", res.StatusCode)
	}

	// Idempotency: the same key twice returns the same ID, deduplicated, and
	// records only one message.
	res, v1 := post(t, env, base, `{"to":"#alerts","text":"once"}`, "key-123")
	if res.StatusCode != 201 {
		t.Fatalf("first keyed send: %d", res.StatusCode)
	}
	res, v2 := post(t, env, base, `{"to":"#alerts","text":"once"}`, "key-123")
	if res.StatusCode != 200 || v2["id"] != v1["id"] || v2["deduplicated"] != true {
		t.Fatalf("idempotent retry: status=%d body=%v", res.StatusCode, v2)
	}
	res, err := env.Direct().Get(base + "/api/messages")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var list struct {
		Messages []Message `json:"messages"`
	}
	_ = json.NewDecoder(res.Body).Decode(&list)
	_ = res.Body.Close()
	count := 0
	for _, m := range list.Messages {
		if m.Key == "key-123" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("deduplicated send recorded %d messages", count)
	}
	if len(list.Messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(list.Messages))
	}

	// Fetch one message by ID.
	res, err = env.Direct().Get(base + "/api/messages/" + id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var m Message
	_ = json.NewDecoder(res.Body).Decode(&m)
	_ = res.Body.Close()
	if m.Text != "deploy ok" {
		t.Fatalf("message body: %+v", m)
	}
}

func TestC035StateFakemsg(t *testing.T) {
	env := fxtest.NewEnv(t)
	base := startMsg(t, env)
	before := env.RequireStateStable(base)
	// Reads don't change state.
	res, err := env.Direct().Get(base + "/api/messages")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	_ = res.Body.Close()
	if got := env.State(base); got != before {
		t.Fatal("__state changed after read")
	}
	// A send does.
	post(t, env, base, `{"to":"#x","text":"y"}`, "")
	env.RequireStateChanged(base, before, "send")
	env.Reset(base)
	if got := env.State(base); got != before {
		t.Fatal("__reset did not restore state")
	}
}
