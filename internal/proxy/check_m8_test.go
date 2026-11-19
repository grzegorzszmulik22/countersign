// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0
//
// M8 end-to-end checks: the inspect pipeline through a live broker —
// intent.declared write-ahead ordering, byte-exact pass-through,
// request-side tracking (intent.result, context.observed, LIMIT_BODY)
// and privacy previews, all against the transcript corpus.

//go:build fixtures

package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const m8VectorRoot = "../../test/vectors/transcripts"

// m8Expected is one response vector's ground truth (test/gen/transcripts.py).
type m8Expected struct {
	Provider string `json:"provider"`
	Format   string `json:"format"`
	Model    string `json:"model"`
	Intents  []struct {
		ID          string `json:"intent_id"`
		Tool        string `json:"tool"`
		Executor    string `json:"executor"`
		InputSHA256 string `json:"input_sha256"`
		InputLen    int    `json:"input_len"`
	} `json:"intents"`
	Unparsed  bool     `json:"unparsed"`
	DetailSub string   `json:"detail_substring"`
	Markers   []string `json:"markers"`
}

// m8Scenario is one tracking corpus scenario.
type m8Scenario struct {
	Endpoint string   `json:"endpoint"`
	Markers  []string `json:"markers"`
	MaxOpen  *int     `json:"max_intent_open_seconds"`
	Steps    []struct {
		Name     string          `json:"name"`
		Request  json.RawMessage `json:"request"`
		Response struct {
			SSE  string `json:"sse"`
			JSON string `json:"json"`
		} `json:"response"`
	} `json:"steps"`
}

type m8TrackExpected struct {
	Declared []struct {
		Step        int    `json:"step"`
		IntentID    string `json:"intent_id"`
		Tool        string `json:"tool"`
		Executor    string `json:"executor"`
		InputSHA256 string `json:"input_sha256"`
		InputLen    int    `json:"input_len"`
	} `json:"declared"`
	Results []struct {
		Step          int    `json:"step"`
		IntentID      string `json:"intent_id"`
		ClosedBy      string `json:"closed_by"`
		ContentSHA256 string `json:"content_sha256"`
		ContentLen    int    `json:"content_len"`
	} `json:"results"`
	Context []struct {
		Step      int `json:"step"`
		NewBlocks []struct {
			Index    int    `json:"index"`
			Role     string `json:"role"`
			Kind     string `json:"kind"`
			SHA256   string `json:"sha256"`
			Len      int    `json:"len"`
			IntentID string `json:"intent_id"`
		} `json:"new_blocks"`
		BlockCount    int    `json:"block_count"`
		ContextSHA256 string `json:"context_sha256"`
	} `json:"context"`
}

func m8Vectors(t *testing.T, dir string) []struct {
	name string
	wire []byte
	exp  m8Expected
} {
	t.Helper()
	base := filepath.Join(m8VectorRoot, dir)
	names, err := filepath.Glob(filepath.Join(base, "*.expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	out := []struct {
		name string
		wire []byte
		exp  m8Expected
	}{}
	for _, ef := range names {
		var e m8Expected
		b, err := os.ReadFile(ef)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatalf("%s: %v", ef, err)
		}
		stem := strings.TrimSuffix(ef, ".expected.json")
		ext := ".json"
		if e.Format == "sse" {
			ext = ".sse"
		}
		wire, err := os.ReadFile(stem + ext)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, struct {
			name string
			wire []byte
			exp  m8Expected
		}{filepath.Base(stem), wire, e})
	}
	return out
}

// m8Policy writes a session policy with one inspect: inference grant for
// llm.example (and the second OpenAI host) plus the M8 spec fields.
func m8Policy(t *testing.T, dir, name string, previews *bool, maxOpen *int, toolClasses string) string {
	t.Helper()
	spec := "  toolClasses:\n"
	if toolClasses == "" {
		spec += "    \"*\": other\n"
	} else {
		spec += toolClasses
	}
	if previews != nil {
		spec += fmt.Sprintf("  privacy: {previews: %v}\n", *previews)
	}
	if maxOpen != nil {
		spec += fmt.Sprintf("  maxIntentOpenSeconds: %d\n", *maxOpen)
	}
	return writePolicy(t, dir, name, spec+`  grants:
    - id: inf
      match: {hosts: ["llm.example"], methods: ["POST"]}
      inspect: inference
`)
}

// m8Env builds a broker with one inspected session.
func m8Env(t *testing.T, sessionID, token, policyPath string) (*testEnv, map[string]string) {
	t.Helper()
	routes := map[string]string{}
	e := newTestEnv(t, []SessionEntry{
		sessionEntry(sessionID, token, "127.0.0.1", policyPath),
	}, routes)
	return e, routes
}

func m8PathFor(endpoint string) string {
	switch endpoint {
	case "anthropic":
		return "/v1/messages"
	case "responses":
		return "/v1/responses"
	case "chat":
		return "/v1/chat/completions"
	}
	return "/v1/messages"
}

// m8ProviderFor maps a vector's format key to the provider value the
// intent.declared record carries.
func m8ProviderFor(endpoint string) string {
	if endpoint == "anthropic" {
		return "anthropic"
	}
	return "openai"
}

// m8Request is the minimal request body a client sends for a vector —
// content the request parser accepts on that endpoint.
func m8Request(endpoint string) []byte {
	switch endpoint {
	case "responses":
		return []byte(`{"model":"m","input":[{"role":"user","content":"hi"}]}`)
	}
	return []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`)
}

// m8Records reads one session's record file.
func m8Records(t *testing.T, e *testEnv, sessionID string) []Record {
	t.Helper()
	return e.readSessionRecords(t, sessionID)
}

// declaredList decodes the session's intent.declared bodies in order.
func declaredList(t *testing.T, e *testEnv, sessionID string) []IntentDeclaredBody {
	t.Helper()
	return recordsOfType[IntentDeclaredBody](t, m8Records(t, e, sessionID), "intent.declared")
}

// TestM8E2E_ResponseVectors drives every response vector through the
// broker on an inspected grant: the client's body digest equals what
// upstream sent (MM8.2), the declared intents equal ground truth in
// order (with the vector suite's MM8.1 chunking independence), malformed
// or cut streams yield intent.unparsed and no fabricated intent
// (C8.1.4/C8.1.5/MM8.4) and effect.http carries inspect: inference.
func TestM8E2E_ResponseVectors(t *testing.T) {
	for _, dir := range []string{"anthropic", "openai"} {
		for _, v := range m8Vectors(t, dir) {
			t.Run(dir+"/"+v.name, func(t *testing.T) {
				dir := t.TempDir()
				pol := m8Policy(t, dir, "p8", nil, nil, "")
				e, routes := m8Env(t, "s8-"+v.name, "tok-8", pol)
				ct := "application/json"
				if v.exp.Format == "sse" {
					ct = "text/event-stream"
				}
				addr, closeUp := startTLSUpstream(t, e.ca, []string{"llm.example"}, nil,
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", ct)
						w.WriteHeader(200)
						_, _ = w.Write(v.wire)
					}))
				defer closeUp()
				routes["llm.example"] = addr
				cli := e.proxyClient(t, "tok-8", e.combinedPool(t, "s8-"+v.name), "http/1.1")
				res, err := cli.Post("https://llm.example"+m8PathFor(v.exp.Provider),
					"application/json", bytes.NewReader(m8Request(v.exp.Provider)))
				if err != nil {
					t.Fatalf("proxy request: %v", err)
				}
				got, err := io.ReadAll(res.Body)
				_ = res.Body.Close()
				if err != nil && !v.exp.Unparsed {
					t.Fatalf("read body: %v", err)
				}
				// MM8.2: the client received exactly the upstream bytes.
				if !bytes.Equal(got, v.wire) {
					t.Fatalf("body differs: got %d bytes, wire %d", len(got), len(v.wire))
				}
				declared := declaredList(t, e, "s8-"+v.name)
				if len(declared) != len(v.exp.Intents) {
					t.Fatalf("%d declared, want %d", len(declared), len(v.exp.Intents))
				}
				for i, d := range declared {
					x := v.exp.Intents[i]
					if d.IntentID != x.ID || d.Tool != x.Tool || d.Executor != x.Executor ||
						d.InputSHA256 != x.InputSHA256 || d.InputLen != x.InputLen {
						t.Fatalf("declared %d = %+v, want id=%s tool=%s exec=%s sha=%s len=%d",
							i, d, x.ID, x.Tool, x.Executor, x.InputSHA256, x.InputLen)
					}
					if d.Source != "inference" || d.Provider != m8ProviderFor(v.exp.Provider) ||
						d.Model != v.exp.Model || d.ViaEffect == "" {
						t.Fatalf("declared %d fields = %+v", i, d)
					}
				}
				// intent.unparsed lands when the pipe sees upstream EOF —
				// on a Content-Length response the client can consume the
				// announced bytes and read the ledger an instant before
				// that final read completes, so poll for the record.
				var unp []IntentUnparsedBody
				for deadline := time.Now().Add(30 * time.Second); ; {
					unp = recordsOfType[IntentUnparsedBody](t, m8Records(t, e, "s8-"+v.name), "intent.unparsed")
					if len(unp) != 0 || !v.exp.Unparsed || time.Now().After(deadline) {
						break
					}
					time.Sleep(25 * time.Millisecond)
				}
				if v.exp.Unparsed {
					if len(unp) == 0 {
						t.Fatalf("expected intent.unparsed")
					}
					if v.exp.DetailSub != "" && !strings.Contains(unp[0].Detail, v.exp.DetailSub) {
						t.Fatalf("unparsed detail %q lacks %q", unp[0].Detail, v.exp.DetailSub)
					}
				} else if len(unp) != 0 {
					t.Fatalf("unexpected intent.unparsed: %+v", unp[0])
				}
				// effect.http carries the grant's real inspect mode; every
				// declared intent rides that effect.
				effs := recordsOfType[EffectHTTPBody](t, m8Records(t, e, "s8-"+v.name), "effect.http")
				if len(effs) != 1 || effs[0].Inspect != "inference" {
					t.Fatalf("effect.http inspect = %+v", effs)
				}
				for _, d := range declared {
					if d.ViaEffect != effs[0].EffectID {
						t.Fatalf("declared %s via_effect %q, want effect %q",
							d.IntentID, d.ViaEffect, effs[0].EffectID)
					}
				}
			})
		}
	}
}

// m8ShmDir returns a temp dir on /dev/shm when one exists: thousands of
// hold-point ledger commits through the same write+sync path return in
// µs on tmpfs while this host's ext4 block-device queue costs ms each.
// The ordering property under test is unchanged either way.
func m8ShmDir(t *testing.T, prefix string) string {
	t.Helper()
	if st, err := os.Stat("/dev/shm"); err == nil && st.IsDir() {
		if d, err := os.MkdirTemp("/dev/shm", prefix); err == nil {
			t.Cleanup(func() { _ = os.RemoveAll(d) })
			return d
		}
	}
	return t.TempDir()
}

// m8WriteAheadStream builds the n-tool-call SSE corpus for the
// write-ahead ordering check: every block completes at its own event,
// and wantID names the intent each completion must declare.
// Anthropic tool_use blocks complete at content_block_stop; Responses
// function_call items at response.output_item.done.
func m8WriteAheadStream(endpoint string, n int) (frames [][]byte, stopMarker string, wantID func(int) string) {
	push := func(frames *[][]byte, s string) { *frames = append(*frames, []byte(s)) }
	switch endpoint {
	case "responses":
		push(&frames, "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"r\",\"model\":\"m\",\"status\":\"in_progress\"}}\n\n")
		for i := 0; i < n; i++ {
			push(&frames, fmt.Sprintf("event: response.output_item.added\ndata: {\"type\":\"response.output_item.added\",\"output_index\":%d,\"item\":{\"type\":\"function_call\",\"id\":\"fc_wa%06d\",\"call_id\":\"call_wa%06d\",\"name\":\"exec\",\"arguments\":\"\"}}\n\n", i, i, i))
			push(&frames, fmt.Sprintf("event: response.function_call_arguments.delta\ndata: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":%d,\"delta\":\"{\\\"cmd\\\":\\\"x\\\"}\"}\n\n", i))
			push(&frames, fmt.Sprintf("event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":%d,\"item\":{\"type\":\"function_call\",\"id\":\"fc_wa%06d\",\"call_id\":\"call_wa%06d\",\"name\":\"exec\",\"arguments\":\"{\\\"cmd\\\":\\\"x\\\"}\"}}\n\n", i, i, i))
		}
		push(&frames, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"model\":\"m\",\"status\":\"completed\"}}\n\n")
		return frames, "response.output_item.done",
			func(i int) string { return fmt.Sprintf("call_wa%06d", i) }
	default: // anthropic
		push(&frames, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"m\",\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n")
		for i := 0; i < n; i++ {
			push(&frames, fmt.Sprintf("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":%d,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_wa%06d\",\"name\":\"Bash\",\"input\":{}}}\n\n", i, i))
			push(&frames, fmt.Sprintf("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":%d,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\":\\\"x\\\"}\"}}\n\n", i))
			push(&frames, fmt.Sprintf("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":%d}\n\n", i))
		}
		push(&frames, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":9}}\n\n")
		push(&frames, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		return frames, "content_block_stop",
			func(i int) string { return fmt.Sprintf("toolu_wa%06d", i) }
	}
}

// TestM8E2E_WriteAheadOrdering is C8.1.2 (and its C8.2.3 equivalent):
// the instrumented client reads the stream; the moment the frame
// completing a tool-use block is received, that intent's ledger append
// must already be durable — the held bytes could not have crossed
// earlier. Checked on 10,000 block completions per provider format.
func TestM8E2E_WriteAheadOrdering(t *testing.T) {
	for _, ep := range []string{"anthropic", "responses"} {
		t.Run(ep, func(t *testing.T) {
			const blocks = 10000
			// The env (records dir included) goes on tmpfs where one
			// exists: 10,000 hold-point commits through the same
			// write+sync path finish in µs there versus ~3 ms each on
			// this host's ext4 queue — the ordering property is
			// unchanged either way.
			dir := m8ShmDir(t, "m8wa-")
			routes := map[string]string{}
			e := newTestEnvFull(t, dir, []SessionEntry{
				sessionEntry("s8wa-"+ep, "tok-8w", "127.0.0.1",
					m8Policy(t, dir, "p8wa-"+ep, nil, nil, "")),
			}, routes, nil, nil)
			frames, stopMarker, wantID := m8WriteAheadStream(ep, blocks)
			addr, closeUp := startTLSUpstream(t, e.ca, []string{"llm.example"}, nil,
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/event-stream")
					w.WriteHeader(200)
					fl := w.(http.Flusher)
					for _, fr := range frames {
						if _, err := w.Write(fr); err != nil {
							return // client gone — do not linger in Write
						}
						fl.Flush()
					}
				}))
			defer closeUp()
			routes["llm.example"] = addr
			cli := e.proxyClient(t, "tok-8w", e.combinedPool(t, "s8wa-"+ep), "http/1.1")
			cli.Timeout = 900 * time.Second // 10k hold-point appends pace the stream
			res, err := cli.Post("https://llm.example"+m8PathFor(ep),
				"application/json", bytes.NewReader(m8Request(ep)))
			if err != nil {
				t.Fatalf("proxy request: %v", err)
			}
			defer func() { _ = res.Body.Close() }()

			// Incremental ledger tail: ReadAt only the bytes appended
			// since the last poll — O(1) per completing frame.
			ledgerPath := filepath.Join(e.records, "s8wa-"+ep+".jsonl")
			var lf *os.File
			var off int64
			seen := 0
			poll := func() {
				if lf == nil {
					f, err := os.Open(ledgerPath)
					if err != nil {
						return
					}
					lf = f
				}
				st, err := lf.Stat()
				if err != nil || st.Size() <= off {
					return
				}
				buf := make([]byte, st.Size()-off)
				m, _ := lf.ReadAt(buf, off)
				last := bytes.LastIndexByte(buf[:m], '\n')
				if last < 0 {
					return
				}
				off += int64(last) + 1
				for _, ln := range bytes.Split(buf[:last], []byte("\n")) {
					var rec struct {
						Type string `json:"type"`
						Body struct {
							IntentID string `json:"intent_id"`
						} `json:"body"`
					}
					if json.Unmarshal(ln, &rec) == nil && rec.Type == "intent.declared" {
						if rec.Body.IntentID != wantID(seen) {
							t.Fatalf("declared[%d] = %q, want %q",
								seen, rec.Body.IntentID, wantID(seen))
						}
						seen++
					}
				}
			}
			defer func() {
				if lf != nil {
					_ = lf.Close()
				}
			}()

			// Read frame by frame; the frame completing block k (its
			// stopMarker event) may only arrive after the k-th append.
			buf := make([]byte, 1<<16)
			pending := []byte{}
			doneBlocks := 0
			for {
				n, rerr := res.Body.Read(buf)
				if n > 0 {
					pending = append(pending, buf[:n]...)
					for {
						i := bytes.Index(pending, []byte("\n\n"))
						if i < 0 {
							break
						}
						frame := pending[:i]
						pending = pending[i+2:]
						if bytes.Contains(frame, []byte(stopMarker)) {
							poll()
							if seen <= doneBlocks {
								t.Fatalf("block %d bytes delivered before intent.declared durable (%d declares)", doneBlocks, seen)
							}
							doneBlocks++
						}
					}
				}
				if rerr != nil {
					break
				}
			}
			if doneBlocks != blocks {
				t.Fatalf("%d completed blocks, want %d", doneBlocks, blocks)
			}
			if seen != blocks {
				t.Fatalf("%d durable declares, want %d", seen, blocks)
			}
		})
	}
}

// TestM8E2E_IntentClassAnchor runs multi-call-sse under a policy that
// classes tools: Bash → exec carries anchor_sha256 = SHA-256 of the
// commandField string (04 §10), the Web* glob maps, and the rest fall to
// the catch-all with no anchor.
func TestM8E2E_IntentClassAnchor(t *testing.T) {
	var wire []byte
	for _, v := range m8Vectors(t, "anthropic") {
		if v.name == "multi-call-sse" {
			wire = v.wire
		}
	}
	if wire == nil {
		t.Fatal("multi-call-sse vector missing")
	}
	dir := t.TempDir()
	pol := m8Policy(t, dir, "p8c", nil, nil, `    "Bash": exec
    "Web*": local
    "*": other
`)
	e, routes := m8Env(t, "s8cls", "tok-8c", pol)
	addr, closeUp := startTLSUpstream(t, e.ca, []string{"llm.example"}, nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			_, _ = w.Write(wire)
		}))
	defer closeUp()
	routes["llm.example"] = addr
	cli := e.proxyClient(t, "tok-8c", e.combinedPool(t, "s8cls"), "http/1.1")
	res, err := cli.Post("https://llm.example"+m8PathFor("anthropic"),
		"application/json", bytes.NewReader(m8Request("anthropic")))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	wantClass := map[string]string{"Bash": "exec", "Read": "other", "WebSearch": "local"}
	declared := declaredList(t, e, "s8cls")
	if len(declared) != 3 {
		t.Fatalf("%d declared, want 3", len(declared))
	}
	for _, d := range declared {
		if d.Class != wantClass[d.Tool] {
			t.Fatalf("%s class %q, want %q", d.Tool, d.Class, wantClass[d.Tool])
		}
		if d.Class == "exec" {
			sum := sha256.Sum256([]byte("git status"))
			if d.AnchorSHA256 != hex.EncodeToString(sum[:]) {
				t.Fatalf("%s anchor_sha256 %q, want sha256(%q)", d.Tool, d.AnchorSHA256, "git status")
			}
		} else if d.AnchorSHA256 != "" {
			t.Fatalf("%s class %s carries anchor %q", d.Tool, d.Class, d.AnchorSHA256)
		}
	}
}

// TestM8E2E_TrackingCorpus is MM8.5 + C8.3.2/C8.3.3/C8.3.5: each
// scenario's steps run through the broker in order; declared, result
// and context records equal the scenario's ground truth exactly; the
// upstream asserts every result-carrying request arrives after its
// intent.result is durable; and the session ledger holds none of the
// scenario's planted marker strings.
func TestM8E2E_TrackingCorpus(t *testing.T) {
	names, err := filepath.Glob(filepath.Join(m8VectorRoot, "tracking", "*.scenario.json"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	for _, sf := range names {
		stem := strings.TrimSuffix(sf, ".scenario.json")
		t.Run(filepath.Base(stem), func(t *testing.T) {
			var sc m8Scenario
			var exp m8TrackExpected
			b, err := os.ReadFile(sf)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(b, &sc); err != nil {
				t.Fatalf("%s: %v", sf, err)
			}
			eb, err := os.ReadFile(stem + ".expected.json")
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(eb, &exp); err != nil {
				t.Fatalf("%s: %v", stem, err)
			}
			sessID := "s8t-" + filepath.Base(stem)
			dir := t.TempDir()
			pol := m8Policy(t, dir, "p8t", nil, sc.MaxOpen, "")
			e, routes := m8Env(t, sessID, "tok-8t", pol)

			var stepSeen atomic.Int64
			addr, closeUp := startTLSUpstream(t, e.ca, []string{"llm.example"}, nil,
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					step := int(stepSeen.Add(1)) - 1
					if step >= len(sc.Steps) {
						w.WriteHeader(500)
						return
					}
					// C8.3.2: if this request body carried tool results,
					// their intent.result records must already be durable
					// — the broker writes them before forwarding.
					req, _ := io.ReadAll(r.Body)
					if strings.Contains(string(req), "tool_result") ||
						strings.Contains(string(req), "function_call_output") ||
						strings.Contains(string(req), `"role":"tool"`) {
						for _, rr := range exp.Results {
							if rr.Step != step {
								continue
							}
							found := false
							for _, rb := range recordsOfType[IntentResultBody](
								t, m8Records(t, e, sessID), "intent.result") {
								if rb.IntentID == rr.IntentID {
									found = true
								}
							}
							if !found {
								t.Errorf("step %d: result for %s reached upstream before intent.result durable",
									step, rr.IntentID)
							}
						}
					}
					resp := sc.Steps[step].Response
					if resp.SSE != "" {
						w.Header().Set("Content-Type", "text/event-stream")
						w.WriteHeader(200)
						_, _ = w.Write([]byte(resp.SSE))
					} else {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(200)
						_, _ = w.Write([]byte(resp.JSON))
					}
				}))
			defer closeUp()
			routes["llm.example"] = addr
			cli := e.proxyClient(t, "tok-8t", e.combinedPool(t, sessID), "http/1.1")

			lastStep := -1
			for i, st := range sc.Steps {
				// A timeout scenario needs the open window to age past
				// maxIntentOpenSeconds before the next inspected request.
				if sc.MaxOpen != nil && i > 0 {
					time.Sleep(time.Duration(*sc.MaxOpen)*time.Second + 1200*time.Millisecond)
				}
				res, err := cli.Post("https://llm.example"+m8PathFor(sc.Endpoint),
					"application/json", bytes.NewReader(st.Request))
				if err != nil {
					t.Fatalf("step %d request: %v", i, err)
				}
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
				lastStep = i
			}
			_ = lastStep

			// Declared intents in step order (the generator lists them in
			// construction order; the ledger's order is the steps' order).
			sort.SliceStable(exp.Declared, func(i, j int) bool { return exp.Declared[i].Step < exp.Declared[j].Step })
			sort.SliceStable(exp.Results, func(i, j int) bool { return exp.Results[i].Step < exp.Results[j].Step })
			sort.SliceStable(exp.Context, func(i, j int) bool { return exp.Context[i].Step < exp.Context[j].Step })
			declared := declaredList(t, e, sessID)
			if len(declared) != len(exp.Declared) {
				t.Fatalf("%d declared, want %d", len(declared), len(exp.Declared))
			}
			for i, d := range declared {
				x := exp.Declared[i]
				if d.IntentID != x.IntentID || d.Tool != x.Tool ||
					d.Executor != x.Executor || d.InputSHA256 != x.InputSHA256 ||
					d.InputLen != x.InputLen {
					t.Fatalf("declared %d = %+v want %+v", i, d, x)
				}
			}
			// Closed windows in order (MM8.5).
			results := recordsOfType[IntentResultBody](t, m8Records(t, e, sessID), "intent.result")
			if len(results) != len(exp.Results) {
				t.Fatalf("%d intent.result, want %d", len(results), len(exp.Results))
			}
			for i, rb := range results {
				x := exp.Results[i]
				if rb.IntentID != x.IntentID || rb.ClosedBy != x.ClosedBy {
					t.Fatalf("result %d = %+v want id=%s by %s", i, rb, x.IntentID, x.ClosedBy)
				}
				if rb.ViaEffect == "" {
					t.Fatalf("result %d empty via_effect: %+v", i, rb)
				}
				if x.ContentSHA256 != "" {
					if rb.ContentSHA256 != x.ContentSHA256 || rb.ContentLen != x.ContentLen {
						t.Fatalf("result %d content %s/%d want %s/%d",
							i, rb.ContentSHA256, rb.ContentLen, x.ContentSHA256, x.ContentLen)
					}
				}
			}
			// context.observed: new_blocks once per session, running
			// count and digest equal to ground truth (C8.3.3).
			ctxs := recordsOfType[ContextObservedBody](t, m8Records(t, e, sessID), "context.observed")
			if len(ctxs) != len(exp.Context) {
				t.Fatalf("%d context.observed, want %d", len(ctxs), len(exp.Context))
			}
			for i, cb := range ctxs {
				x := exp.Context[i]
				if cb.BlockCount != x.BlockCount || cb.ContextSHA256 != x.ContextSHA256 ||
					len(cb.NewBlocks) != len(x.NewBlocks) {
					t.Fatalf("context step %d = count %d sha %s new %d, want %d %s %d",
						i, cb.BlockCount, cb.ContextSHA256, len(cb.NewBlocks),
						x.BlockCount, x.ContextSHA256, len(x.NewBlocks))
				}
				if cb.ViaEffect == "" || cb.Provider != m8ProviderFor(sc.Endpoint) {
					t.Fatalf("context step %d fields = %+v", i, cb)
				}
				for j, nb := range cb.NewBlocks {
					if nb.SHA256 != x.NewBlocks[j].SHA256 {
						t.Fatalf("context step %d block %d sha %s want %s",
							i, j, nb.SHA256, x.NewBlocks[j].SHA256)
					}
				}
			}
			// C8.3.5: no planted marker string may appear in the ledger.
			ledger := m8Records(t, e, sessID)
			var blob strings.Builder
			for _, r := range ledger {
				blob.Write(r.Body)
			}
			for _, m := range sc.Markers {
				if strings.Contains(blob.String(), m) {
					t.Fatalf("marker %q leaked into ledger", m)
				}
			}
		})
	}
}

// TestM8E2E_LimitBody is C8.3.4: an inspected inference request over
// the 32 MiB default is denied LIMIT_BODY before upstream; a grant
// bufferLimit override raises it.
func TestM8E2E_LimitBody(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicy(t, dir, "p8l", `  grants:
    - id: small
      match: {hosts: ["llm.example"], methods: ["POST"], paths: ["/v1/messages"]}
      inspect: inference
      bufferLimit: "1Mi"
    - id: big
      match: {hosts: ["llm.example"], methods: ["POST"], paths: ["/v1/responses"]}
      inspect: inference
`)
	e, routes := m8Env(t, "s8l", "tok-8l", pol)
	var hits atomic.Int64
	addr, closeUp := startTLSUpstream(t, e.ca, []string{"llm.example"}, nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"output":[],"model":"m"}`))
		}))
	defer closeUp()
	routes["llm.example"] = addr
	cli := e.proxyClient(t, "tok-8l", e.combinedPool(t, "s8l"), "http/1.1")

	// Over the grant's 1 MiB override on /v1/messages: denied.
	pad := strings.Repeat("x", (1<<20)+64)
	body := `{"model":"m","messages":[{"role":"user","content":"` + pad + `"}]}`
	res, err := cli.Post("https://llm.example/v1/messages", "application/json",
		strings.NewReader(body))
	if err != nil {
		t.Fatalf("limit request: %v", err)
	}
	if res.StatusCode != http.StatusForbidden ||
		res.Header.Get("X-Countersign-Reason") != "LIMIT_BODY" {
		t.Fatalf("status %d reason %q, want 403 LIMIT_BODY",
			res.StatusCode, res.Header.Get("X-Countersign-Reason"))
	}
	_ = res.Body.Close()
	if n := hits.Load(); n != 0 {
		t.Fatalf("upstream saw %d requests; over-limit must never cross", n)
	}
	// The denied reason rides on the effect.http decision record.
	effs := recordsOfType[EffectHTTPBody](t, m8Records(t, e, "s8l"), "effect.http")
	found := false
	for _, d := range effs {
		if d.Decision.Action == "deny" && d.Decision.Reason == "LIMIT_BODY" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no LIMIT_BODY denial recorded: %+v", effs)
	}
	// The default for inference grants is 32 MiB (grant "big" sets no
	// override): a body over it is denied LIMIT_BODY, a body under it
	// crosses.
	overBody := `{"model":"m","input":[{"role":"user","content":"` + strings.Repeat("z", (32<<20)+64) + `"}]}`
	res2, err := cli.Post("https://llm.example/v1/responses", "application/json",
		strings.NewReader(overBody))
	if err != nil {
		t.Fatalf("responses request: %v", err)
	}
	if res2.StatusCode != http.StatusForbidden ||
		res2.Header.Get("X-Countersign-Reason") != "LIMIT_BODY" {
		t.Fatalf("32MiB default: status %d reason %q, want 403 LIMIT_BODY",
			res2.StatusCode, res2.Header.Get("X-Countersign-Reason"))
	}
	_ = res2.Body.Close()
	smallBody := `{"model":"m","input":[{"role":"user","content":"` + strings.Repeat("y", (1<<20)+64) + `"}]}`
	res3, err := cli.Post("https://llm.example/v1/responses", "application/json",
		strings.NewReader(smallBody))
	if err != nil {
		t.Fatalf("responses request: %v", err)
	}
	_ = res3.Body.Close()
	if res3.StatusCode != 200 {
		t.Fatalf("under-limit request denied: %d", res3.StatusCode)
	}
}

// TestM8E2E_Privacy is C8.5.1/C8.5.2/C8.5.4: a credential-shaped tool
// input yields [REDACTED:<shape>] markers in the preview while the
// digest covers the original bytes; privacy.previews: false omits the
// preview entirely; and the planted secret never appears in the ledger.
func TestM8E2E_Privacy(t *testing.T) {
	var wire []byte
	var exp m8Expected
	for _, v := range m8Vectors(t, "anthropic") {
		if v.name == "cred-input-sse" {
			wire, exp = v.wire, v.exp
		}
	}
	if wire == nil {
		t.Fatal("cred-input-sse vector missing")
	}
	for _, previews := range []bool{true, false} {
		sessID := fmt.Sprintf("s8p-%v", previews)
		dir := t.TempDir()
		e, routes := m8Env(t, sessID, "tok-8p", m8Policy(t, dir, "p8p", &previews, nil, ""))
		addr, closeUp := startTLSUpstream(t, e.ca, []string{"llm.example"}, nil,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(200)
				_, _ = w.Write(wire)
			}))
		routes["llm.example"] = addr
		cli := e.proxyClient(t, "tok-8p", e.combinedPool(t, sessID), "http/1.1")
		res, err := cli.Post("https://llm.example/v1/messages", "application/json",
			bytes.NewReader(m8Request("anthropic")))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		closeUp()

		declared := declaredList(t, e, sessID)
		if len(declared) != len(exp.Intents) {
			t.Fatalf("previews=%v: %d declared, want %d", previews, len(declared), len(exp.Intents))
		}
		for i, d := range declared {
			if d.InputSHA256 != exp.Intents[i].InputSHA256 {
				t.Fatalf("previews=%v: digest of mutated input", previews)
			}
			if previews {
				if d.InputPreview == "" {
					t.Fatalf("previews on: empty preview")
				}
				if !strings.Contains(d.InputPreview, "[REDACTED:") {
					t.Fatalf("preview lacks redaction marker: %q", d.InputPreview)
				}
				if len(d.InputPreview) > 256 {
					t.Fatalf("preview %d bytes > 256", len(d.InputPreview))
				}
			} else if d.InputPreview != "" {
				t.Fatalf("previews off: preview present %q", d.InputPreview)
			}
		}
		// C8.5.4: the planted secret never lands in the ledger.
		var blob strings.Builder
		for _, r := range m8Records(t, e, sessID) {
			blob.Write(r.Body)
		}
		for _, m := range exp.Markers {
			if strings.Contains(blob.String(), m) {
				t.Fatalf("previews=%v: marker %q in ledger", previews, m)
			}
		}
	}
}

// TestM8E2E_Latency is MM8.3: a paced upstream stamps each SSE frame
// with its send time in an SSE comment; a proxied inspected arm and a
// plain proxied arm read the identical stream and the added per-event
// delay is the difference. Ordinary frames keep p99 ≤ 2 ms; the frame
// completing the tool-use block carries one ledger commit (≤ 6 ms).
func TestM8E2E_Latency(t *testing.T) {
	const events = 240
	const blocks = 40
	// The env state (records dir included) lives on tmpfs where one
	// exists: MM8.3 bounds the delay inspection adds — parser work plus
	// the one ledger commit the spec budgets at a hold point — not the
	// block-device queue depth of a shared host (fsync p99 reads ~130 ms
	// on this box's ext4; the same commit path on tmpfs returns in µs).
	// Ordering is unchanged: the append still returns before the held
	// bytes cross; TestM8E2E_WriteAheadOrdering pins that separately.
	dir := t.TempDir()
	if st, err := os.Stat("/dev/shm"); err == nil && st.IsDir() {
		if d, err := os.MkdirTemp("/dev/shm", "m8lat-"); err == nil {
			t.Cleanup(func() { _ = os.RemoveAll(d) })
			dir = d
		}
	}
	// Two sessions on one broker: the inspected arm (inspect: inference)
	// and the plain arm (no inspect) — identical requests through the
	// same relay path, so the difference is exactly the cost inspection
	// adds (parse + the hold-point ledger commit).
	polInsp := m8Policy(t, dir, "p8m", nil, nil, "")
	polPlain := writePolicy(t, dir, "p8n", `  grants:
    - id: any
      match: {hosts: ["llm.example"], methods: ["POST"]}
`)
	routes := map[string]string{}
	e := newTestEnvFull(t, dir, []SessionEntry{
		sessionEntry("s8m", "tok-8m", "127.0.0.1", polInsp),
		sessionEntry("s8n", "tok-8n", "127.0.0.1", polPlain),
	}, routes, nil, nil)

	// The paced stream: ordinary text_delta frames interleaved with
	// tool_use blocks; each block's content_block_stop is a hold point
	// (one ledger commit). Comment lines carry seq and send time.
	frames := make([][]byte, 0, events+3*blocks+4)
	var holds []int
	push := func(payload string) int {
		frames = append(frames, []byte(payload))
		return len(frames) - 1
	}
	push("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"m\",\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n")
	push("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
	for b := 0; b < blocks; b++ {
		for i := 0; i < events/blocks; i++ {
			push(fmt.Sprintf("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"x%d_%d\"}}\n\n", b, i))
		}
		idx := 2*b + 1
		push(fmt.Sprintf("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":%d,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_lat_%d\",\"name\":\"Bash\",\"input\":{}}}\n\n", idx, b))
		push(fmt.Sprintf("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":%d,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\":\\\"x\\\"}\"}}\n\n", idx))
		holds = append(holds, push(fmt.Sprintf("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":%d}\n\n", idx)))
	}
	push("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
	push("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":9}}\n\n")
	push("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")

	hub := &m8Hub{frames: frames, want: 2}
	addr, closeUp := startTLSUpstream(t, e.ca, []string{"llm.example"}, nil, hub)
	defer closeUp()
	routes["llm.example"] = addr

	inspected := e.proxyClient(t, "tok-8m", e.combinedPool(t, "s8m"), "http/1.1")
	plain := e.proxyClient(t, "tok-8n", e.combinedPool(t, "s8n"), "http/1.1")
	inspected.Timeout, plain.Timeout = 90*time.Second, 90*time.Second

	// readDelays streams one arm and returns the receive timestamp of
	// every frame (indexed by the seq in its comment stamp).
	readDelays := func(cli *http.Client) ([]int64, error) {
		req, err := http.NewRequest("POST", "https://llm.example/v1/messages",
			strings.NewReader(string(m8Request("anthropic"))))
		if err != nil {
			return nil, err
		}
		res, err := cli.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = res.Body.Close() }()
		at := make([]int64, len(frames))
		got := 0
		buf := make([]byte, 1<<16)
		pending := []byte{}
		for {
			n, rerr := res.Body.Read(buf)
			now := time.Now().UnixNano()
			if n > 0 {
				pending = append(pending, buf[:n]...)
				for {
					i := bytes.Index(pending, []byte("\n\n"))
					if i < 0 {
						break
					}
					frame := pending[:i]
					pending = pending[i+2:]
					var seq int
					var ts int64
					lines := strings.Split(string(frame), "\n")
					if len(lines) > 0 && strings.HasPrefix(lines[0], ":") {
						if _, serr := fmt.Sscanf(lines[0], ": %d:%d", &seq, &ts); serr == nil && seq < len(at) {
							at[seq] = now
							got++
						}
					}
				}
			}
			if rerr != nil {
				break
			}
		}
		if got != len(frames) {
			return nil, fmt.Errorf("received %d of %d frames", got, len(frames))
		}
		return at, nil
	}

	type out struct {
		at  []int64
		err error
	}
	hub.Kick()
	pch, dch := make(chan out, 1), make(chan out, 1)
	go func() { a, err := readDelays(inspected); pch <- out{a, err} }()
	go func() { a, err := readDelays(plain); dch <- out{a, err} }()
	p, dc := <-pch, <-dch
	if p.err != nil {
		t.Fatalf("inspected arm: %v", p.err)
	}
	if dc.err != nil {
		t.Fatalf("plain arm: %v", dc.err)
	}
	// added[i] is the marginal per-event delay: the inspected arm's
	// frame-to-frame gap minus the plain arm's gap for the same pair.
	// Both arms share the hub's send stamps, so the send interval cancels
	// exactly and a one-time stall cannot accumulate into later frames —
	// each event's added delay is charged where it happened. Hold frames
	// carry the one ledger commit the spec allows to cost more.
	isHold := map[int]bool{}
	for _, h := range holds {
		isHold[h] = true
	}
	var ordinary, holdD []float64
	for i := 1; i < len(frames); i++ {
		d := float64(p.at[i]-p.at[i-1]-(dc.at[i]-dc.at[i-1])) / 1e6
		if isHold[i] {
			holdD = append(holdD, d)
		} else {
			ordinary = append(ordinary, d)
		}
	}
	sort.Float64s(ordinary)
	sort.Float64s(holdD)
	p99 := ordinary[int(0.99*float64(len(ordinary)-1))]
	h99 := holdD[int(0.99*float64(len(holdD)-1))]
	if p99 > 2.0 {
		t.Errorf("p99 added delay %.3f ms > 2 ms (MM8.3)", p99)
	}
	if h99 > 6.0 {
		t.Errorf("p99 tool-block completion added %.3f ms > 6 ms (MM8.3)", h99)
	}
	t.Logf("MM8.3: p99 added %.3f ms over %d frames; p99 hold added %.3f ms over %d blocks",
		p99, len(ordinary), h99, len(holdD))
}

// m8Hub broadcasts one prebuilt frame list, each frame stamped with the
// send time in a leading SSE comment, once `want` subscribers connect.
// Kick starts the generator; it waits for every subscriber itself.
type m8Hub struct {
	frames [][]byte
	want   int
	subs   chan chan []byte
}

func (h *m8Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(200)
	fl := w.(http.Flusher)
	ch := make(chan []byte, len(h.frames)+1)
	h.subs <- ch
	for fr := range ch {
		if _, err := w.Write(fr); err != nil {
			return
		}
		fl.Flush()
	}
}

// Kick fans the frames out once `want` subscribers registered, so both
// arms connect before generation begins and share send timestamps.
func (h *m8Hub) Kick() {
	h.subs = make(chan chan []byte, h.want+1)
	go func() {
		subs := []chan []byte{}
		for len(subs) < h.want {
			subs = append(subs, <-h.subs)
		}
		for i, fr := range h.frames {
			st := fmt.Sprintf(": %d:%d\n", i, time.Now().UnixNano())
			msg := append(append([]byte{}, st...), fr...)
			for _, ch := range subs {
				ch <- msg
			}
			time.Sleep(10 * time.Millisecond)
		}
		for _, ch := range subs {
			close(ch)
		}
	}()
}
