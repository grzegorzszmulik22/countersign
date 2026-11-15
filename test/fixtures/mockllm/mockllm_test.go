// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package mockllm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/countersign/countersign/test/fixtures/fxlib"
	"github.com/countersign/countersign/test/fixtures/fxtest"
)

const vectorsDir = "../../vectors/transcripts"

func scenario(t *testing.T) *Transcript {
	t.Helper()
	tr, err := LoadTranscript(filepath.Join(vectorsDir, "reference.scenario.json"))
	if err != nil {
		t.Fatalf("load scenario: %v", err)
	}
	return tr
}

func startLLM(t *testing.T, env *fxtest.Env, tr *Transcript, opts Options) string {
	t.Helper()
	addr, err := New(tr, opts).Serve(env.Ctx, "127.0.0.1:0",
		env.Issue("api.anthropic.com", "api.openai.com", "127.0.0.1"))
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	env.Register("mockllm", addr.String())
	return "https://" + addr.String()
}

// requestBodies builds the per-turn client request bodies for each shape. The
// tool results of earlier turns are echoed back with the ids the shape uses.
type driver struct {
	shape       string
	model       string
	texts       []string // user texts per turn (index 0 = initial prompt)
	dropResults bool     // omit tool_result/output items (provokes validation)
	// resultWrong overrides the reported content of the named call's tool
	// result (provokes the "missing expected content" validation path).
	resultWrong map[string]string
}

func (d *driver) resultFor(key string) string {
	if w, ok := d.resultWrong[key]; ok {
		return w
	}
	return turnResults[key]
}

// turnResults maps transcript key -> result content the client reports.
var turnResults = map[string]string{
	"r1": "agent-vpc\n",
	"b1": "",
	"w1": `{"number":1,"title":"Widget flanges stick","state":"open"}`,
}

func (d *driver) body(t *Transcript, turn int, stream bool) []byte {
	switch d.shape {
	case "anthropic":
		var msgs []any
		msgs = append(msgs, map[string]any{"role": "user", "content": d.texts[0]})
		for i := 0; i < turn; i++ {
			resp := t.Turns[i].Response
			var content []any
			if resp.Text != "" {
				content = append(content, map[string]any{"type": "text", "text": resp.Text})
			}
			var results []any
			for _, c := range resp.Calls {
				content = append(content, map[string]any{"type": "tool_use", "id": "toolu_" + c.Key, "name": c.Tool, "input": c.Input})
				if !d.dropResults {
					results = append(results, map[string]any{"type": "tool_result", "tool_use_id": "toolu_" + c.Key, "content": d.resultFor(c.Key)})
				}
			}
			msgs = append(msgs, map[string]any{"role": "assistant", "content": content})
			if len(results) == 0 {
				results = append(results, map[string]any{"type": "text", "text": "(results omitted)"})
			}
			msgs = append(msgs, map[string]any{"role": "user", "content": results})
		}
		b, _ := json.Marshal(map[string]any{"model": d.model, "max_tokens": 1024, "stream": stream, "messages": msgs})
		return b
	case "responses":
		var input []any
		input = append(input, map[string]any{"type": "message", "role": "user", "content": d.texts[0]})
		for i := 0; i < turn; i++ {
			for _, c := range t.Turns[i].Response.Calls {
				input = append(input, map[string]any{"type": "function_call", "id": "fc_" + c.Key, "call_id": "call_" + c.Key, "name": c.Tool, "arguments": string(c.Input), "status": "completed"})
				if !d.dropResults {
					input = append(input, map[string]any{"type": "function_call_output", "call_id": "call_" + c.Key, "output": d.resultFor(c.Key)})
				}
			}
		}
		b, _ := json.Marshal(map[string]any{"model": d.model, "stream": stream, "input": input})
		return b
	case "chat":
		var msgs []any
		msgs = append(msgs, map[string]any{"role": "user", "content": d.texts[0]})
		for i := 0; i < turn; i++ {
			resp := t.Turns[i].Response
			msg := map[string]any{"role": "assistant"}
			if resp.Text != "" {
				msg["content"] = resp.Text
			}
			if len(resp.Calls) > 0 {
				var tcs []any
				for j, c := range resp.Calls {
					tcs = append(tcs, map[string]any{"id": "call_" + c.Key, "type": "function", "index": j,
						"function": map[string]any{"name": c.Tool, "arguments": string(c.Input)}})
				}
				msg["tool_calls"] = tcs
			}
			msgs = append(msgs, msg)
			if !d.dropResults {
				for _, c := range resp.Calls {
					msgs = append(msgs, map[string]any{"role": "tool", "tool_call_id": "call_" + c.Key, "content": d.resultFor(c.Key)})
				}
			}
		}
		b, _ := json.Marshal(map[string]any{"model": d.model, "stream": stream, "messages": msgs})
		return b
	}
	panic("bad shape " + d.shape)
}

func (d *driver) path() string {
	switch d.shape {
	case "anthropic":
		return "/v1/messages"
	case "responses":
		return "/v1/responses"
	case "chat":
		return "/v1/chat/completions"
	}
	return ""
}

func (d *driver) post(t *testing.T, env *fxtest.Env, base string, body []byte) []byte {
	t.Helper()
	req, _ := http.NewRequestWithContext(env.Ctx, http.MethodPost, base+d.path(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+fxlib.Canary("model"))
	res, err := env.Direct().Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", d.path(), err)
	}
	defer func() { _ = res.Body.Close() }()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(res.Body)
	if res.StatusCode != 200 {
		t.Fatalf("%s: status %d: %s", d.path(), res.StatusCode, buf.String())
	}
	return buf.Bytes()
}

// postInvalid posts a body that must be rejected with 400 and returns the
// response body for reason inspection.
func (d *driver) postInvalid(t *testing.T, env *fxtest.Env, base string, body []byte) string {
	t.Helper()
	req, _ := http.NewRequestWithContext(env.Ctx, http.MethodPost, base+d.path(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res, err := env.Direct().Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", d.path(), err)
	}
	defer func() { _ = res.Body.Close() }()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(res.Body)
	if res.StatusCode != 400 {
		t.Fatalf("%s: invalid request accepted: status %d: %s", d.path(), res.StatusCode, buf.String())
	}
	return buf.String()
}

func TestC031Mockllm(t *testing.T) {
	env := fxtest.NewEnv(t)
	tr := scenario(t)
	base := startLLM(t, env, tr, Options{})

	d := &driver{shape: "anthropic", model: tr.Model,
		texts: []string{"Please report the hostname of this machine."}}
	// Turn 0: streamed response carries the Read call with toolu_r1.
	out := d.post(t, env, base, d.body(tr, 0, true))
	s := string(out)
	for _, want := range []string{"message_start", "content_block_start", "input_json_delta", "toolu_r1", "message_stop"} {
		if !strings.Contains(s, want) {
			t.Fatalf("anthropic stream missing %q\n%s", want, s)
		}
	}
	// Turn 1: non-streamed; two parallel calls; needs r1's result.
	out = d.post(t, env, base, d.body(tr, 1, false))
	s = string(out)
	for _, want := range []string{"toolu_b1", "toolu_w1", `"stop_reason":"tool_use"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("anthropic turn2 missing %q\n%s", want, s)
		}
	}
	// Turn 2: end_turn text.
	out = d.post(t, env, base, d.body(tr, 2, false))
	if !strings.Contains(string(out), `"stop_reason":"end_turn"`) {
		t.Fatalf("final turn: %s", out)
	}

	// OpenAI shapes on fresh servers (cursor is per-server).
	for _, shape := range []string{"responses", "chat"} {
		env2 := fxtest.NewEnv(t)
		base2 := startLLM(t, env2, tr, Options{})
		d2 := &driver{shape: shape, model: tr.Model, texts: d.texts}
		out := d2.post(t, env2, base2, d2.body(tr, 0, true))
		marker := "call_r1"
		if !strings.Contains(string(out), marker) {
			t.Fatalf("%s stream missing %s\n%s", shape, marker, out)
		}
		out = d2.post(t, env2, base2, d2.body(tr, 1, false))
		if !strings.Contains(string(out), "call_b1") || !strings.Contains(string(out), "call_w1") {
			t.Fatalf("%s turn2 missing calls\n%s", shape, out)
		}
		d2.post(t, env2, base2, d2.body(tr, 2, false))
	}

	// Validation: a turn sent without the expected tool result is rejected
	// with a "missing tool result" error and recorded as invalid.
	env3 := fxtest.NewEnv(t)
	base3 := startLLM(t, env3, tr, Options{})
	d3 := &driver{shape: "anthropic", model: tr.Model, texts: d.texts}
	d3.post(t, env3, base3, d3.body(tr, 0, false))
	// Turn 1 expects r1's tool_result; send a body without it → reject.
	d3.dropResults = true
	badBody := d3.postInvalid(t, env3, base3, d3.body(tr, 1, false))
	if !strings.Contains(badBody, "missing tool result") {
		t.Fatalf("missing-result rejection has wrong reason: %s", badBody)
	}
	var sawInvalid bool
	for _, o := range env3.Observed(base3) {
		if v, _ := o.Extra["valid"].(bool); !v {
			if o.Extra["error"] != nil {
				sawInvalid = true
			}
		}
	}
	if !sawInvalid {
		t.Fatal("rejected turn not recorded as invalid")
	}

	// Validation: a turn carrying the tool result but with content that does
	// not match expect_results is rejected with "missing expected content".
	// Turn 2 wants w1's result to contain "open"; report "closed" instead.
	env5 := fxtest.NewEnv(t)
	base5 := startLLM(t, env5, tr, Options{})
	d5 := &driver{shape: "anthropic", model: tr.Model, texts: d.texts}
	d5.post(t, env5, base5, d5.body(tr, 0, false))
	d5.post(t, env5, base5, d5.body(tr, 1, false))
	d5.resultWrong = map[string]string{"w1": `{"number":1,"title":"Widget flanges stick","state":"closed"}`}
	wrongBody := d5.postInvalid(t, env5, base5, d5.body(tr, 2, false))
	if !strings.Contains(wrongBody, "missing expected content") {
		t.Fatalf("wrong-content rejection has wrong reason: %s", wrongBody)
	}
	// The same wrong content must be rejected in the other two shapes too —
	// validation is shape-agnostic (call_w1 carries the reported output).
	for _, shape := range []string{"responses", "chat"} {
		envS := fxtest.NewEnv(t)
		baseS := startLLM(t, envS, tr, Options{})
		dS := &driver{shape: shape, model: tr.Model, texts: d.texts}
		dS.post(t, envS, baseS, dS.body(tr, 0, false))
		dS.post(t, envS, baseS, dS.body(tr, 1, false))
		dS.resultWrong = d5.resultWrong
		wb := dS.postInvalid(t, envS, baseS, dS.body(tr, 2, false))
		if !strings.Contains(wb, "missing expected content") {
			t.Fatalf("%s wrong-content rejection has wrong reason: %s", shape, wb)
		}
	}

	// /v1/files accepts any key and records which key uploaded what.
	env4 := fxtest.NewEnv(t)
	base4 := startLLM(t, env4, tr, Options{})
	key := fxlib.Canary("file-uploader")
	req, _ := http.NewRequestWithContext(env4.Ctx, http.MethodPost, base4+"/v1/files?name=data.csv&purpose=fine-tune",
		strings.NewReader("a,b\n1,2\n"))
	req.Header.Set("Authorization", "Bearer "+key)
	res, err := env4.Direct().Do(req)
	if err != nil {
		t.Fatalf("files: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("files: status %d", res.StatusCode)
	}
	var sawKey bool
	for _, o := range env4.Observed(base4) {
		if got, _ := o.Extra["key_sha256"].(string); got == fxlib.DigestBytes([]byte(key)) {
			sawKey = true
		}
	}
	if !sawKey {
		t.Fatal("file upload did not record the key")
	}
}

// TestC031MockllmModes covers --variant and --conditional.
func TestC031MockllmModes(t *testing.T) {
	tr := scenario(t)

	// extra-call variant appends a call to the first turn with calls.
	env := fxtest.NewEnv(t)
	v, _ := ParseVariant("extra-call")
	base := startLLM(t, env, tr, Options{Variant: v})
	d := &driver{shape: "anthropic", model: tr.Model, texts: []string{"x hostname"}}
	out := d.post(t, env, base, d.body(tr, 0, false))
	if !strings.Contains(string(out), "toolu_variant-extra") {
		t.Fatalf("variant extra-call missing planted call\n%s", out)
	}

	// conditional: response changes only when the marker is in the context.
	tr2 := scenario(t)
	tr2.Turns[0].ConditionalResponse = &CondResp{
		Marker:   "MARKER-ALPHA",
		Response: Resp{Stop: "end_turn", Text: "conditional path taken"},
	}
	env2 := fxtest.NewEnv(t)
	base2 := startLLM(t, env2, tr2, Options{Conditional: true})
	d2 := &driver{shape: "anthropic", model: tr2.Model, texts: []string{"x hostname"}}
	out = d2.post(t, env2, base2, d2.body(tr2, 0, false))
	if !strings.Contains(string(out), "toolu_r1") {
		t.Fatalf("without marker expected normal turn\n%s", out)
	}
	env3 := fxtest.NewEnv(t)
	base3 := startLLM(t, env3, tr2, Options{Conditional: true})
	d3 := &driver{shape: "anthropic", model: tr2.Model, texts: []string{"x hostname MARKER-ALPHA"}}
	out = d3.post(t, env3, base3, d3.body(tr2, 0, false))
	if !strings.Contains(string(out), "conditional path taken") {
		t.Fatalf("with marker expected conditional response\n%s", out)
	}

	// flaky: p=1 always applies; p=0 (deterministic) never.
	env4 := fxtest.NewEnv(t)
	base4 := startLLM(t, env4, tr, Options{Variant: v, Flaky: &Flaky{P: 0, Rand: rand.New(rand.NewSource(1))}})
	d4 := &driver{shape: "anthropic", model: tr.Model, texts: []string{"x hostname"}}
	out = d4.post(t, env4, base4, d4.body(tr, 0, false))
	if strings.Contains(string(out), "variant-extra") {
		t.Fatal("flaky p=0 applied the variant")
	}
}

// TestC033MockllmGolden replays the reference scenario in each shape and
// compares streamed response bytes against test/vectors/transcripts/reference.*.
// CS_WRITE_GOLDENS=1 regenerates the vectors instead of comparing.
func TestC033MockllmGolden(t *testing.T) {
	tr := scenario(t)
	write := os.Getenv("CS_WRITE_GOLDENS") == "1"
	for _, shape := range []string{"anthropic", "responses", "chat"} {
		env := fxtest.NewEnv(t)
		base := startLLM(t, env, tr, Options{})
		d := &driver{shape: shape, model: tr.Model,
			texts: []string{"Please report the hostname of this machine."}}
		var bodies []string
		for turn := 0; turn < len(tr.Turns); turn++ {
			bodies = append(bodies, base64.StdEncoding.EncodeToString(d.post(t, env, base, d.body(tr, turn, true))))
		}
		golden, _ := json.MarshalIndent(bodies, "", "  ")
		path := filepath.Join(vectorsDir, "reference."+shape+".golden")
		if write {
			if err := os.WriteFile(path, append(golden, '\n'), 0o644); err != nil {
				t.Fatalf("write golden: %v", err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read golden %s: %v (run with CS_WRITE_GOLDENS=1 to create)", path, err)
		}
		if !bytes.Equal(bytes.TrimSpace(want), golden) {
			t.Fatalf("%s output not byte-identical to %s", shape, path)
		}
	}
}

func TestC035StateMockllm(t *testing.T) {
	env := fxtest.NewEnv(t)
	tr := scenario(t)
	base := startLLM(t, env, tr, Options{})
	d := &driver{shape: "anthropic", model: tr.Model, texts: []string{"x hostname"}}

	before := env.RequireStateStable(base)
	// Admin reads don't change state.
	env.Observed(base)
	if got := env.State(base); got != before {
		t.Fatal("__state changed after read")
	}
	// A turn advances the cursor → write.
	d.post(t, env, base, d.body(tr, 0, false))
	env.RequireStateChanged(base, before, "turn")
	// A file upload is another write kind.
	s2 := env.State(base)
	req, _ := http.NewRequestWithContext(env.Ctx, http.MethodPost, base+"/v1/files?name=f.txt",
		strings.NewReader("x"))
	req.Header.Set("x-api-key", fxlib.Canary("model"))
	res, err := env.Direct().Do(req)
	if err != nil {
		t.Fatalf("files: %v", err)
	}
	_ = res.Body.Close()
	env.RequireStateChanged(base, s2, "file upload")
	env.Reset(base)
	if got := env.State(base); got != before {
		t.Fatal("__reset did not restore state")
	}
}
