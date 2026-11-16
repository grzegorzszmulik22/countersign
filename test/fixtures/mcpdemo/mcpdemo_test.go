// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package mcpdemo

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/countersign/countersign/test/fixtures/fakehub"
	"github.com/countersign/countersign/test/fixtures/fxlib"
	"github.com/countersign/countersign/test/fixtures/fxtest"
)

// startStack runs fakehub plus mcpdemo wired to it.
func startStack(t *testing.T, env *fxtest.Env, flags Flags) (mcpBase, hubBase string) {
	t.Helper()
	hub, err := fakehub.New(filepath.Join(env.Dir, "hub"))
	if err != nil {
		t.Fatalf("hub: %v", err)
	}
	hubAddr, err := hub.Serve(env.Ctx, "127.0.0.1:0",
		env.Issue("github.com", "api.github.com", "127.0.0.1"))
	if err != nil {
		t.Fatalf("hub serve: %v", err)
	}
	env.Register("fakehub", hubAddr.String())
	hubBase = "https://" + hubAddr.String()

	s := New(Options{
		HubURL: hubBase, HubRepo: "acme/widgets",
		HubToken: fxlib.Canary("github-agent"), Hub: fxlib.CAClient(env.CA),
		Flags: flags,
	})
	addr, err := s.Serve(env.Ctx, "127.0.0.1:0", env.Issue("mcp.example.com", "127.0.0.1"))
	if err != nil {
		t.Fatalf("mcp serve: %v", err)
	}
	env.Register("mcpdemo", addr.String())
	return "https://" + addr.String(), hubBase
}

// rpc posts one JSON-RPC request with the 2026-07-28 transport headers.
func rpc(t *testing.T, env *fxtest.Env, base, method string, params any) (*http.Response, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
		"_meta": map[string]string{"io.modelcontextprotocol/protocolVersion": ProtocolRev},
	})
	req, _ := http.NewRequestWithContext(env.Ctx, http.MethodPost, base+"/mcp", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", ProtocolRev)
	req.Header.Set("Mcp-Method", method)
	if m, ok := params.(map[string]any); ok {
		if n, ok := m["name"].(string); ok {
			req.Header.Set("Mcp-Name", n)
		}
	}
	res, err := env.Direct().Do(req)
	if err != nil {
		t.Fatalf("rpc %s: %v", method, err)
	}
	defer func() { _ = res.Body.Close() }()
	var v map[string]any
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		t.Fatalf("decode rpc result: %v", err)
	}
	return res, v
}

func toolText(v map[string]any) string {
	res, _ := v["result"].(map[string]any)
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		return ""
	}
	m, _ := content[0].(map[string]any)
	s, _ := m["text"].(string)
	return s
}

func TestC031Mcpdemo(t *testing.T) {
	env := fxtest.NewEnv(t)
	base, hubBase := startStack(t, env, Flags{})

	// server/discover (mandatory in 2026-07-28).
	res, v := rpc(t, env, base, "server/discover", nil)
	if res.StatusCode != 200 {
		t.Fatalf("discover: %d", res.StatusCode)
	}
	info, _ := v["result"].(map[string]any)["serverInfo"].(map[string]any)
	if info["name"] != "mcpdemo" {
		t.Fatalf("discover: %v", v)
	}

	// tools/list: three tools; annotated_reader is readOnlyHint:true.
	_, v = rpc(t, env, base, "tools/list", nil)
	tools, _ := v["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 3 {
		t.Fatalf("tools/list: %d tools", len(tools))
	}
	var sawReader, sawCreate bool
	for _, tv := range tools {
		tm, _ := tv.(map[string]any)
		ann, _ := tm["annotations"].(map[string]any)
		switch tm["name"] {
		case "annotated_reader":
			sawReader = ann["readOnlyHint"] == true
		case "create_record":
			sawCreate = ann["readOnlyHint"] == false
		}
	}
	if !sawReader || !sawCreate {
		t.Fatalf("annotations wrong: reader=%v create=%v", sawReader, sawCreate)
	}

	// create_record POSTs an issue to fakehub.
	_, v = rpc(t, env, base, "tools/call",
		map[string]any{"name": "create_record", "arguments": map[string]any{"title": "from-mcp", "body": "via tool"}})
	if !strings.Contains(toolText(v), "from-mcp") {
		t.Fatalf("create_record: %v", v)
	}
	// The issue is real on fakehub.
	res, err := env.Direct().Get(hubBase + "/__state")
	if err != nil {
		t.Fatalf("hub state: %v", err)
	}
	_ = res.Body.Close()
	req, _ := http.NewRequestWithContext(env.Ctx, http.MethodGet, hubBase+"/repos/acme/widgets/issues", nil)
	req.Header.Set("Authorization", "Bearer "+fxlib.Canary("github-agent"))
	res, err = env.Direct().Do(req)
	if err != nil {
		t.Fatalf("hub issues: %v", err)
	}
	var issues []map[string]any
	if err := json.NewDecoder(res.Body).Decode(&issues); err != nil {
		t.Fatalf("decode issues: %v", err)
	}
	_ = res.Body.Close()
	var found bool
	for _, i := range issues {
		if i["title"] == "from-mcp" {
			found = true
		}
	}
	if !found {
		t.Fatal("create_record did not reach fakehub")
	}

	// search GETs (read-only): returns the issue list.
	_, v = rpc(t, env, base, "tools/call",
		map[string]any{"name": "search", "arguments": map[string]any{"q": "from-mcp"}})
	if !strings.Contains(toolText(v), "from-mcp") {
		t.Fatalf("search: %v", v)
	}

	// annotated_reader GETs one issue.
	_, v = rpc(t, env, base, "tools/call",
		map[string]any{"name": "annotated_reader", "arguments": map[string]any{"number": 1}})
	if !strings.Contains(toolText(v), "Widget flanges") {
		t.Fatalf("annotated_reader: %v", v)
	}

	// Transport strictness: header/method mismatch is rejected.
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 9, "method": "tools/list"})
	req, _ = http.NewRequestWithContext(env.Ctx, http.MethodPost, base+"/mcp", bytes.NewReader(b))
	req.Header.Set("MCP-Protocol-Version", ProtocolRev)
	req.Header.Set("Mcp-Method", "tools/call") // lie
	res, err = env.Direct().Do(req)
	if err != nil {
		t.Fatalf("mismatch: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != 400 {
		t.Fatalf("Mcp-Method mismatch: status %d", res.StatusCode)
	}

	// Malformed tools/call params: the request is well-formed JSON-RPC, so
	// the answer is an invalid-params (-32602) result error at HTTP 200 —
	// and the observation records the rejection, not an empty tool call.
	res, v = rpc(t, env, base, "tools/call", "not-an-object")
	if res.StatusCode != 200 {
		t.Fatalf("bad params: status %d", res.StatusCode)
	}
	e, _ := v["error"].(map[string]any)
	if e["code"] != float64(-32602) {
		t.Fatalf("bad params: want -32602 error, got %v", v)
	}

	// Every mcpdemo observation must equal the request that produced it:
	// rpc method, transport headers, and for tools/call the tool + arguments.
	expectedCalls := []struct {
		name string
		args map[string]any
	}{
		{"create_record", map[string]any{"title": "from-mcp", "body": "via tool"}},
		{"search", map[string]any{"q": "from-mcp"}},
		{"annotated_reader", map[string]any{"number": float64(1)}},
	}
	var sawDiscover, sawList, sawCall, sawMismatch, sawBadParams int
	for _, o := range env.Observed(base) {
		rpcM, isRPC := o.Extra["rpc"].(string)
		if !isRPC {
			continue // admin endpoints, parse failures handled elsewhere
		}
		if o.Method != http.MethodPost || !strings.HasSuffix(o.Path, "/mcp") {
			t.Fatalf("rpc entry records method %q path %q, want POST .../mcp", o.Method, o.Path)
		}
		if hv, _ := o.Extra["hdr_version"].(string); hv != ProtocolRev {
			t.Fatalf("rpc %s recorded hdr_version %q, client sent %q", rpcM, hv, ProtocolRev)
		}
		if hm, _ := o.Extra["hdr_method"].(string); hm != rpcM {
			if o.Extra["rejected"] != "method-mismatch" {
				t.Fatalf("rpc %s recorded hdr_method %q with no rejection", rpcM, hm)
			}
			sawMismatch++
		}
		switch rpcM {
		case "server/discover":
			sawDiscover++
		case "tools/list":
			sawList++
		case "tools/call":
			sawCall++
			if rej, _ := o.Extra["rejected"].(string); rej != "" {
				// A rejected call must carry the reason, and only reasons a
				// client call could actually trigger.
				switch rej {
				case "bad-params":
					sawBadParams++
				case "name-mismatch":
				default:
					t.Fatalf("tools/call rejected with unknown reason %q", rej)
				}
				continue
			}
			tool, _ := o.Extra["tool"].(string)
			if tool == "" {
				t.Fatalf("tools/call entry records no tool: %+v", o.Extra)
			}
			if hn, _ := o.Extra["hdr_name"].(string); hn != tool {
				t.Fatalf("tools/call %s recorded hdr_name %q", tool, hn)
			}
			matched := false
			for _, e := range expectedCalls {
				if e.name == tool && reflect.DeepEqual(e.args, o.Extra["args"]) {
					matched = true
				}
			}
			if !matched {
				t.Fatalf("tools/call entry tool=%q args=%v matches no issued call", tool, o.Extra["args"])
			}
		default:
			t.Fatalf("obs records rpc %q the client never sent", rpcM)
		}
	}
	if sawDiscover == 0 || sawList == 0 || sawCall == 0 || sawMismatch == 0 || sawBadParams == 0 {
		t.Fatalf("missing obs coverage: discover=%d list=%d call=%d mismatch=%d badparams=%d",
			sawDiscover, sawList, sawCall, sawMismatch, sawBadParams)
	}
}

func TestC031McpdemoMisbehave(t *testing.T) {
	// idle-phone-home: every RPC sends an undeclared heartbeat to the hub.
	env := fxtest.NewEnv(t)
	base, hubBase := startStack(t, env, Flags{IdlePhoneHome: true})
	rpc(t, env, base, "tools/list", nil)
	obs := env.Observed(hubBase)
	var beats int
	for _, o := range obs {
		if strings.Contains(o.Path, "/dispatches") {
			beats++
		}
	}
	if beats == 0 {
		t.Fatal("idle-phone-home produced no heartbeat POSTs")
	}

	// extra-post: create_record issues a second, undeclared POST.
	env2 := fxtest.NewEnv(t)
	base2, hubBase2 := startStack(t, env2, Flags{ExtraPost: true})
	var before int
	req, _ := http.NewRequestWithContext(env2.Ctx, http.MethodGet, hubBase2+"/repos/acme/widgets/issues", nil)
	req.Header.Set("Authorization", "Bearer "+fxlib.Canary("github-agent"))
	res, _ := env2.Direct().Do(req)
	var iss []map[string]any
	if err := json.NewDecoder(res.Body).Decode(&iss); err != nil {
		t.Fatalf("decode issue: %v", err)
	}
	_ = res.Body.Close()
	before = len(iss)
	rpc(t, env2, base2, "tools/call",
		map[string]any{"name": "create_record", "arguments": map[string]any{"title": "t1"}})
	res, _ = env2.Direct().Do(req.Clone(env2.Ctx))
	iss = nil
	if err := json.NewDecoder(res.Body).Decode(&iss); err != nil {
		t.Fatalf("decode issue: %v", err)
	}
	_ = res.Body.Close()
	if len(iss) != before+2 {
		t.Fatalf("extra-post created %d issues (want +2)", len(iss)-before)
	}

	// lying-annotation: create_record advertises readOnlyHint:true.
	env3 := fxtest.NewEnv(t)
	base3, _ := startStack(t, env3, Flags{LyingAnnotation: true})
	_, v := rpc(t, env3, base3, "tools/list", nil)
	tools, _ := v["result"].(map[string]any)["tools"].([]any)
	for _, tv := range tools {
		tm, _ := tv.(map[string]any)
		if tm["name"] == "create_record" {
			ann, _ := tm["annotations"].(map[string]any)
			if ann["readOnlyHint"] != true {
				t.Fatal("lying-annotation: readOnlyHint not true")
			}
		}
	}
}

func TestC035StateMcpdemo(t *testing.T) {
	env := fxtest.NewEnv(t)
	base, _ := startStack(t, env, Flags{})
	before := env.RequireStateStable(base)
	// Reads don't change state.
	rpc(t, env, base, "server/discover", nil)
	rpc(t, env, base, "tools/list", nil)
	rpc(t, env, base, "tools/call", map[string]any{"name": "search", "arguments": map[string]any{"q": "x"}})
	if got := env.State(base); got != before {
		t.Fatal("__state changed after read-only RPCs")
	}
	// create_record is a write.
	rpc(t, env, base, "tools/call",
		map[string]any{"name": "create_record", "arguments": map[string]any{"title": "w"}})
	env.RequireStateChanged(base, before, "create_record")
	env.Reset(base)
	if got := env.State(base); got != before {
		t.Fatal("__reset did not restore state")
	}
}
