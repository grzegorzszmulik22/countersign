// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/countersign/countersign/internal/policy"
	"github.com/countersign/countersign/test/fixtures/fakehub"
	"github.com/countersign/countersign/test/fixtures/fxlib"
	"github.com/countersign/countersign/test/fixtures/fxres"
	"github.com/countersign/countersign/test/fixtures/fxtest"
)

// m3 policy: credentialed grants for the three §4 inject forms plus
// non-credentialed grants for scope and pass-through checks. Test secrets
// are generated canaries (06 §11: CANARY_[A-Z0-9]{32}), never real keys.
const m3Grants = `  grants:
    - id: anthropic
      match: {hosts: [api.anthropic.com], methods: [POST], paths: [/v1/messages]}
      credential:
        ref: {secret: anthropic, key: api-key}
        inject: {header: x-api-key, format: "{secret}"}
        placeholderEnv: ANTHROPIC_API_KEY
    - id: anthropic-files
      match: {hosts: [api.anthropic.com], methods: [POST], paths: [/v1/files]}
    - id: github
      match: {hosts: [github.com]}
      credential:
        ref: {secret: github-token, key: value}
        inject: {basic: {username: x-access-token}}
        placeholderEnv: GITHUB_TOKEN
    - id: hub-api
      match: {hosts: [api.github.com]}
      credential:
        ref: {secret: github-token, key: value}
        inject: {header: Authorization, format: "Bearer {secret}"}
        placeholderEnv: GITHUB_TOKEN
    - id: pypi
      match: {hosts: [pypi.org, files.pythonhosted.org], methods: [GET, HEAD]}
    - id: plain
      match: {hosts: [h1.example], scheme: http}
`

func m3Secrets() map[string]map[string]string {
	return map[string]map[string]string{
		"anthropic":    {"api-key": fxlib.Canary("anthropic")},
		"github-token": {"value": fxlib.Canary("github-agent")},
	}
}

// m3Policy writes the shared M3 policy and secrets files; returns paths.
func m3PolicySecrets(t *testing.T, dir, grants string) (pol, sec string) {
	t.Helper()
	pol = writePolicy(t, dir, "m3", grants)
	sec = writeSecrets(t, dir, m3Secrets())
	return pol, sec
}

// headerSink is a recording upstream: it captures every request's
// (normalized) headers and body length, then answers 200 with a small
// JSON echo. It never inspects credential material itself — assertions
// live in the tests.
type headerSink struct {
	mu           sync.Mutex
	seen         []http.Header
	bodies       int64
	secretInResp string // when set, the response body carries it (leak oracle)
}

func (h *headerSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/scrub/") || r.URL.Path == "/redir" {
		h.scrubEP(w, r)
		return
	}
	body, _ := io.ReadAll(r.Body)
	hdr := http.Header{}
	for k, v := range r.Header {
		cp := make([]string, len(v))
		copy(cp, v)
		hdr[k] = cp
	}
	h.mu.Lock()
	h.seen = append(h.seen, hdr)
	h.bodies += int64(len(body))
	h.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{"ok": true}
	if h.secretInResp != "" {
		resp["leak"] = h.secretInResp
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// inboundKey returns the credential material this request carried — the
// injected real value for a credentialed grant, or whatever the client
// put in the header otherwise. Scrub endpoints reflect it in different
// wire positions so the broker's response scrubber has something to find.
func inboundKey(r *http.Request) string {
	if v := r.Header.Get("X-Api-Key"); v != "" {
		return v
	}
	return r.Header.Get("Authorization")
}

// scrubEP serves the M3.4 leak oracle endpoints (04 §4.5): every variant
// places the inbound credential somewhere in the response.
func (h *headerSink) scrubEP(w http.ResponseWriter, r *http.Request) {
	k := inboundKey(r)
	hdr := http.Header{}
	for kk, v := range r.Header {
		cp := make([]string, len(v))
		copy(cp, v)
		hdr[kk] = cp
	}
	h.mu.Lock()
	h.seen = append(h.seen, hdr)
	h.bodies += int64(len(k))
	h.mu.Unlock()
	switch {
	case r.URL.Path == "/scrub/raw":
		_, _ = fmt.Fprintf(w, "start %s mid %s end", k, k)
	case r.URL.Path == "/scrub/forms":
		// All three §4.5 wire forms of an x-api-key-style secret.
		_, _ = fmt.Fprintf(w, "raw=%s b64=%s enc=%s", k,
			base64.StdEncoding.EncodeToString([]byte(k)), url.QueryEscape(k))
	case r.URL.Path == "/scrub/gzip":
		gz := &bytes.Buffer{}
		gw := gzip.NewWriter(gz)
		_, _ = fmt.Fprintf(gw, "zipped %s payload", k)
		_ = gw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(gz.Bytes())
	case r.URL.Path == "/scrub/trailer":
		w.Header().Set("Trailer", "X-Leak-Key")
		_, _ = fmt.Fprint(w, "trailer body")
		w.Header().Set("X-Leak-Key", k)
	case r.URL.Path == "/scrub/hdr":
		w.Header().Set("X-Leak-Key", k)
		_, _ = fmt.Fprint(w, "header body")
	case strings.HasPrefix(r.URL.Path, "/scrub/big"):
		n, _ := strconv.ParseInt(r.URL.Query().Get("n"), 10, 64)
		if n <= 0 {
			n = 1 << 20
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		zero := bytes.Repeat([]byte{'0'}, 64<<10)
		var sent int64
		insertAt := n - int64(len(k)) - 16
		for sent < insertAt {
			m := int64(len(zero))
			if insertAt-sent < m {
				m = insertAt - sent
			}
			_, _ = w.Write(zero[:m])
			sent += m
		}
		_, _ = w.Write([]byte(k))
		sent += int64(len(k))
		for sent < n {
			m := int64(len(zero))
			if n-sent < m {
				m = n - sent
			}
			_, _ = w.Write(zero[:m])
			sent += m
		}
	case r.URL.Path == "/redir":
		w.Header().Set("Location", r.URL.Query().Get("to"))
		w.WriteHeader(http.StatusFound)
		_, _ = fmt.Fprint(w, "redirect")
	case r.URL.Path == "/scrub/basic":
		// The Basic wire form: Authorization arrives as
		// "Basic base64(user:secret)" upstream-side; reflect it whole.
		_, _ = fmt.Fprintf(w, "auth=%s", k)
	case r.URL.Path == "/scrub/badenc":
		w.Header().Set("Content-Encoding", "br")
		_, _ = fmt.Fprintf(w, "unverifiable %s", k)
	default:
		http.Error(w, "unknown scrub endpoint", http.StatusNotFound)
	}
}

func (h *headerSink) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.seen)
}

func (h *headerSink) last() http.Header {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.seen) == 0 {
		return nil
	}
	return h.seen[len(h.seen)-1]
}

func (h *headerSink) bodyBytes() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.bodies
}

// credEnv is the shared M3 test rig: one credentialed session, fakehub on
// the GitHub names (through fxres), and recording upstreams for the
// Anthropic/PyPI names (through the route map).
type credEnv struct {
	env    *testEnv
	hub    *fakehub.Server
	hubObs *fxlib.Obs

	anthro *headerSink
	pypi   *headerSink
	files  *headerSink
	h2     *headerSink
}

// startCredEnv builds the credentialed session rig. sinkFn, when non-nil,
// builds the record sink on the env dir (e.g. a failableSink wrapping
// NewFileRecordSink) so broker.log and the sink share the directory.
func startCredEnv(t *testing.T, grants string, sinkFn func(dir string) RecordSink) *credEnv {
	t.Helper()
	dir := t.TempDir()
	pol, sec := m3PolicySecrets(t, dir, grants)
	ca, err := fxlib.EnsureCA(dir)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	var sink RecordSink
	if sinkFn != nil {
		sink = sinkFn(dir)
	}

	ce := &credEnv{anthro: &headerSink{}, pypi: &headerSink{}, files: &headerSink{}, h2: &headerSink{}}
	// h1 for the Anthropic upstream: big streamed bodies stay off h2's
	// flow-control edge cases (the h2 path is exercised on its own host).
	anthroAddr, _ := startTLSUpstream(t, ca, []string{"api.anthropic.com"},
		[]string{"http/1.1"}, ce.anthro)
	pypiAddr, _ := startTLSUpstream(t, ca, []string{"pypi.org"}, nil, ce.pypi)
	filesAddr, _ := startTLSUpstream(t, ca, []string{"files.pythonhosted.org"}, nil, ce.files)
	h2Addr, _ := startTLSUpstream(t, ca, []string{"h2.anthropic.example"},
		[]string{"h2"}, ce.h2)

	routes := map[string]string{
		"api.anthropic.com":      anthroAddr,
		"pypi.org":               pypiAddr,
		"files.pythonhosted.org": filesAddr,
		"h2.anthropic.example":   h2Addr,
	}
	e := newTestEnvFull(t, dir, []SessionEntry{
		sessionEntryCreds("s1", "tok-one", "127.0.0.1", pol, sec),
		sessionEntryCreds("s2", "tok-two", "127.0.0.1", pol, sec),
	}, routes, nil, sink)
	ce.env = e

	hub, err := fakehub.New(filepath.Join(dir, "hub"))
	if err != nil {
		t.Fatalf("fakehub: %v", err)
	}
	cert, err := e.ca.Issue([]string{"github.com", "api.github.com", "127.0.0.1"})
	if err != nil {
		t.Fatalf("hub cert: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addr, err := hub.Serve(ctx, "127.0.0.1:0", cert)
	if err != nil {
		t.Fatalf("hub serve: %v", err)
	}
	fxres.RegisterLocal("fakehub", addr.String())
	ce.hub = hub
	ce.hubObs = hub.Obs
	return ce
}

// ph returns the session's placeholder for a grant.
func ph(t *testing.T, e *testEnv, sessID, grantID string) string {
	t.Helper()
	s := e.broker.Session(sessID)
	if s == nil {
		t.Fatalf("no session %q", sessID)
	}
	p := s.placeholders[grantID]
	if p == "" {
		t.Fatalf("session %q grant %q: no placeholder", sessID, grantID)
	}
	return p
}

// doCred requests through the proxy with optional header overrides.
func doCred(t *testing.T, e *testEnv, token, method, rawURL string, hdr map[string]string, body []byte) (*http.Response, []byte) {
	t.Helper()
	sess := "s1"
	if token == "tok-two" {
		sess = "s2"
	}
	client := e.proxyClient(t, token, e.combinedPool(t, sess))
	req, err := http.NewRequest(method, rawURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxy request %s %s: %v", method, rawURL, err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return res, b
}

// canaryFree asserts that b carries no real secret — only the fixture
// canaries are secrets in tests, and none may reach client-visible bytes,
// records or logs (04 §4.4: real secrets never appear in client-visible
// bytes or the ledger).
func canaryFree(t *testing.T, what string, b []byte) {
	t.Helper()
	for name, keys := range m3Secrets() {
		for k, v := range keys {
			if bytes.Contains(b, []byte(v)) {
				t.Fatalf("%s contains real secret %s:%s", what, name, k)
			}
		}
	}
}

// --- C3.2.1 -------------------------------------------------------------
// A request carrying the session's placeholder in the inject slot reaches
// upstream with the real credential; the client-visible response carries
// none of the secret, and the record carries only the credential ID.
func TestC321InjectHeaderPlaceholder(t *testing.T) {
	ce := startCredEnv(t, m3Grants, nil)
	e := ce.env
	p := ph(t, e, "s1", "hub-api")

	// fakehub requires a valid token — a 200 proves injection produced
	// the real credential; /debug/echo reflects it for the scrub path.
	res, body := doCred(t, e, "tok-one", "GET", "https://api.github.com/debug/echo",
		map[string]string{"Authorization": "Bearer " + p}, nil)
	if res.StatusCode != 200 {
		t.Fatalf("status %d body %s", res.StatusCode, body)
	}
	// Upstream saw the real credential (fakehub records the token used).
	var tokSeen bool
	for _, o := range ce.hubObs.List() {
		if o.Extra["token"] == fxlib.Canary("github-agent") {
			tokSeen = true
		}
	}
	if !tokSeen {
		t.Fatal("fakehub never observed the real credential")
	}
	// The client-visible echo carries the placeholder, not the secret:
	// scrubbing (M3.4) replaced the reflected credential.
	canaryFree(t, "client response", body)
	if !bytes.Contains(body, []byte(p)) {
		t.Fatalf("client echo missing placeholder: %s", body)
	}
	// The effect record names the credential ID, never the value.
	recs := e.readSessionRecords(t, "s1")
	effects := recordsOfType[EffectHTTPBody](t, recs, "effect.http")
	if len(effects) == 0 {
		t.Fatal("no effect.http recorded")
	}
	last := effects[len(effects)-1]
	if len(last.Decision.Creds) != 1 || last.Decision.Creds[0] != "github-token:value" {
		t.Fatalf("decision.credentials = %v", last.Decision.Creds)
	}
	raw, _ := os.ReadFile(filepath.Join(e.records, "s1.jsonl"))
	canaryFree(t, "record file", raw)
	canaryFree(t, "broker log", []byte(e.brokerLogText(t)))
}

// --- C3.2.2 -------------------------------------------------------------
// Injection also fires when the inject slot is absent; non-credentialed
// grants never gain a credential. The placeholder value is never in the
// client environment as a secret (it IS the client-side form).
func TestC322InjectAbsentAndScope(t *testing.T) {
	ce := startCredEnv(t, m3Grants, nil)
	e := ce.env
	p := ph(t, e, "s1", "anthropic")

	// No x-api-key: the broker adds the real one upstream.
	res, _ := doCred(t, e, "tok-one", "POST", "https://api.anthropic.com/v1/messages", nil, []byte("{}"))
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	got := ce.anthro.last().Get("X-Api-Key")
	if got != fxlib.Canary("anthropic") {
		t.Fatalf("upstream x-api-key = %q (want injected canary)", redactForLog(got))
	}

	// With the placeholder: same outcome (replace, not add).
	res, _ = doCred(t, e, "tok-one", "POST", "https://api.anthropic.com/v1/messages",
		map[string]string{"X-Api-Key": p}, []byte("{}"))
	if res.StatusCode != 200 {
		t.Fatalf("placeholder request status %d", res.StatusCode)
	}
	if got := ce.anthro.last().Get("X-Api-Key"); got != fxlib.Canary("anthropic") {
		t.Fatalf("upstream x-api-key after placeholder = %q", redactForLog(got))
	}

	// Non-credentialed grant: a client header passes through verbatim;
	// nothing is injected for the broker's credentials.
	res, _ = doCred(t, e, "tok-one", "GET", "https://pypi.org/simple/", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("pypi status %d", res.StatusCode)
	}
	l := ce.pypi.last()
	if l.Get("X-Api-Key") != "" || l.Get("Authorization") != "" {
		t.Fatalf("credential material appeared on non-credentialed grant: %v", l)
	}
}

// redactForLog keeps secret values out of test output as well — a failing
// message names the header, never the credential it carried.
func redactForLog(v string) string {
	for name, keys := range m3Secrets() {
		for _, sec := range keys {
			v = strings.ReplaceAll(v, sec, "<secret:"+name+">")
		}
	}
	return v
}

// --- C3.2.3 -------------------------------------------------------------
// Scope: requests outside the grant's host/method/path never receive
// credentials — a different grant on the same host, and NO_GRANT outside
// every grant.
func TestC323Scope(t *testing.T) {
	ce := startCredEnv(t, m3Grants, nil)
	e := ce.env

	// Same host, different grant (anthropic-files has no credential).
	res, _ := doCred(t, e, "tok-one", "POST", "https://api.anthropic.com/v1/files", nil, []byte("data"))
	if res.StatusCode != 200 {
		t.Fatalf("files status %d", res.StatusCode)
	}
	if got := ce.anthro.last().Get("X-Api-Key"); got != "" {
		t.Fatalf("x-api-key on non-credentialed grant: %q", redactForLog(got))
	}
	if recs := recordsOfType[EffectHTTPBody](t, e.readSessionRecords(t, "s1"), "effect.http"); len(recs) > 0 {
		if c := recs[len(recs)-1].Decision.Creds; len(c) != 0 {
			t.Fatalf("non-credentialed grant recorded creds %v", c)
		}
	}

	// Same host, path outside every grant: NO_GRANT, no upstream touch.
	before := ce.anthro.count()
	res, _ = doCred(t, e, "tok-one", "POST", "https://api.anthropic.com/v1/other", nil, []byte("{}"))
	if res.StatusCode != 403 {
		t.Fatalf("outside-path status %d", res.StatusCode)
	}
	if got := res.Header.Get("X-Countersign-Reason"); got != "NO_GRANT" {
		t.Fatalf("reason %q want NO_GRANT", got)
	}
	if ce.anthro.count() != before {
		t.Fatal("denied request reached upstream")
	}
}

// --- C3.2.4 -------------------------------------------------------------
// A real git client clones through the broker using its GITHUB_TOKEN
// placeholder; the wire carries the Basic real credential and fakehub's
// observation never sees the placeholder.
func TestC324GitCloneBasic(t *testing.T) {
	ce := startCredEnv(t, m3Grants, nil)
	e := ce.env
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not on PATH")
	}
	p := ph(t, e, "s1", "github")

	// CA bundle for git: session CA (the broker's MITM issuer) + test root.
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	sess := e.broker.Session("s1")
	var pemBuf bytes.Buffer
	_ = pem.Encode(&pemBuf, &pem.Block{Type: "CERTIFICATE", Bytes: sess.CACert().Raw})
	pemBuf.Write(e.ca.CertPEM())
	if err := os.WriteFile(bundle, pemBuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	cloneDir := filepath.Join(t.TempDir(), "clone")
	proxy := "http://cs:tok-one@" + e.proxyURL.Host
	// The environment carries the placeholder — the only client-side
	// form of the credential (04 §4.1). No real secret appears in it.
	env := []string{
		"HOME=" + t.TempDir(),
		"PATH=" + filepath.Dir(git) + string(os.PathListSeparator) + "/usr/bin:/bin",
		"HTTPS_PROXY=" + proxy, "https_proxy=" + proxy,
		"HTTP_PROXY=" + proxy, "http_proxy=" + proxy,
		"GIT_SSL_CAINFO=" + bundle,
		"GIT_CONFIG_NOSYSTEM=1", "NO_PROXY=", "no_proxy=",
		"GIT_TERMINAL_PROMPT=0",
		"GITHUB_TOKEN=" + p, // the placeholder env of the policy
	}
	for _, kv := range env {
		canaryFree(t, "git env "+strings.SplitN(kv, "=", 2)[0], []byte(kv))
	}

	// The placeholder sits in the credential position git knows: URL
	// userinfo, which libcurl turns into the Basic Authorization header.
	cloneURL := "https://x-access-token:" + url.QueryEscape(p) + "@github.com/acme/widgets.git"
	cmd := exec.CommandContext(e.timeoutCtx(t, 60*time.Second), git, "-c", "credential.helper=",
		"clone", cloneURL, cloneDir)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git clone: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(cloneDir, "README.md")); err != nil {
		t.Fatalf("clone produced no checkout: %v", err)
	}

	// fakehub's log shows the real token, never the placeholder.
	var sawReal, sawPH bool
	for _, o := range ce.hubObs.List() {
		tok, _ := o.Extra["token"].(string)
		if tok == fxlib.Canary("github-agent") {
			sawReal = true
		}
		if strings.Contains(tok, "csph_") {
			sawPH = true
		}
	}
	if !sawReal {
		t.Fatal("fakehub never saw the real credential")
	}
	if sawPH {
		t.Fatal("fakehub saw a placeholder upstream")
	}
}

// timeoutCtx bounds a subprocess run.
func (e *testEnv) timeoutCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// --- C3.2.5 -------------------------------------------------------------
// Injection invariant: over generated requests, every injection happens
// only for a request whose 04 §2 checks all passed — asserted here by the
// Python reference matcher for steps 1-2 (grant identity and no
// NO_GRANT/DENY_GRANT/SMUGGLING_SUSPECT) and by construction for the
// credential checks (they produced the inject plan being logged).
func TestC325InjectionInvariant(t *testing.T) {
	dir := t.TempDir()
	pol, sec := m3PolicySecrets(t, dir, m3Grants)
	sessionsFile := filepath.Join(dir, "sessions.yaml")
	table := fmt.Sprintf("sessions:\n  - id: s1\n    token: t1\n    client_ip: 127.0.0.1\n    policy: %s\n    credentials: %s\n  - id: s2\n    token: t2\n    client_ip: 127.0.0.1\n    policy: %s\n    credentials: %s\n",
		pol, sec, pol, sec)
	if err := os.WriteFile(sessionsFile, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	sessions, err := loadSessions(sessionsFile, nil)
	if err != nil {
		t.Fatalf("loadSessions: %v", err)
	}
	sess1, sess2 := sessions["t1"], sessions["t2"]

	// specJSON is the policy document the Python matcher reads.
	var specDoc struct {
		Grants []json.RawMessage `json:"grants"`
	}
	specBytes, _ := json.Marshal(struct {
		Grants []policy.Grant `json:"grants"`
	}{Grants: sess1.Policy.Spec.Grants})
	if err := json.Unmarshal(specBytes, &specDoc); err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewSource(32025))
	type ev struct {
		Grant string          `json:"grant"`
		Req   json.RawMessage `json:"req"`
	}
	var events []ev
	var batch []map[string]any
	denyN := map[string]int{}

	hosts := []string{"api.anthropic.com", "github.com", "api.github.com",
		"pypi.org", "files.pythonhosted.org", "evil.example.com", "h1.example"}
	paths := map[string][]string{
		"api.anthropic.com":      {"/v1/messages", "/v1/files", "/v1/other", "/"},
		"github.com":             {"/acme/widgets.git/info/refs", "/acme/widgets.git/git-upload-pack", "/", "/other/repo.git/info/refs"},
		"api.github.com":         {"/repos/acme/widgets/issues", "/debug/echo", "/"},
		"pypi.org":               {"/simple/", "/simple/requests/", "/x"},
		"files.pythonhosted.org": {"/packages/a.whl", "/"},
		"evil.example.com":       {"/v1/messages", "/"},
		"h1.example":             {"/", "/x"},
	}
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD"}

	placeholders := []string{
		sess1.placeholders["anthropic"], sess1.placeholders["github"], sess1.placeholders["hub-api"],
		sess2.placeholders["anthropic"], sess2.placeholders["github"], sess2.placeholders["hub-api"],
		"csph_ffffffff_fake_0123456789abcdefghij", "csph_", "csph_short",
	}
	credLike := []string{
		"Bearer " + fxlib.Canary("github-agent"), "Basic " + b64("x-access-token:"+fxlib.Canary("github-agent")),
		"Bearer " + sess1.placeholders["hub-api"],
		"Basic " + b64("x-access-token:"+sess1.placeholders["github"]),
		"Basic " + b64(sess1.placeholders["github"]+":whatever"),
		"token abc", "Basic " + b64("other:cred"), "",
	}
	bodies := []string{
		"", "{}", "hello", "key=" + sess1.placeholders["anthropic"],
		"api_key=sk-ant-0123456789abcdefghij0123456789",
		"nested%3Dcsph_", "data=" + url.QueryEscape(sess1.placeholders["github"]),
	}

	// Targeted shapes: half the requests aim at a credentialed grant's
	// match with mostly-injectable headers (absent or own placeholder in
	// the slot) plus a dose of misuse shapes; the rest roam free.
	targets := []struct {
		grant, host, path, method string
	}{
		{"anthropic", "api.anthropic.com", "/v1/messages", "POST"},
		{"github", "github.com", "/acme/widgets.git/info/refs", "GET"},
		{"hub-api", "api.github.com", "/repos/acme/widgets/issues", "GET"},
	}

	N := 50000
	for i := 0; i < N; i++ {
		var host, method, path string
		targeted := rng.Intn(2) == 0
		var tg *struct{ grant, host, path, method string }
		if targeted {
			t := targets[rng.Intn(len(targets))]
			tg = &t
			host, method, path = t.host, t.method, t.path
		} else {
			host = hosts[rng.Intn(len(hosts))]
			method = methods[rng.Intn(len(methods))]
			path = paths[host][rng.Intn(len(paths[host]))]
		}
		scheme := "https"
		if host == "h1.example" || (host == "evil.example.com" && rng.Intn(4) == 0) {
			scheme = "http"
		}
		port := 443
		if scheme == "http" {
			port = 80
		}
		query := ""
		if rng.Intn(6) == 0 {
			query = "service=git-upload-pack"
		} else if rng.Intn(11) == 0 {
			query = "k=" + placeholders[rng.Intn(len(placeholders))]
		}
		hdr := http.Header{}
		if rng.Intn(3) == 0 {
			hdr.Set("X-Api-Key", placeholders[rng.Intn(len(placeholders))])
		} else if targeted && tg.grant == "anthropic" && rng.Intn(2) == 0 {
			hdr.Set("X-Api-Key", sess1.placeholders["anthropic"])
		}
		if !targeted {
			if rng.Intn(2) == 0 {
				hdr.Set("Authorization", credLike[rng.Intn(len(credLike))])
			}
		} else if tg.grant == "github" && rng.Intn(2) == 0 {
			hdr.Set("Authorization", "Basic "+b64("x-access-token:"+sess1.placeholders["github"]))
		} else if tg.grant == "hub-api" && rng.Intn(2) == 0 {
			hdr.Set("Authorization", "Bearer "+sess1.placeholders["hub-api"])
		} else if rng.Intn(6) == 0 {
			hdr.Set("Authorization", credLike[rng.Intn(len(credLike))])
		}
		if rng.Intn(7) == 0 {
			hdr.Set("Cookie", "session="+placeholders[rng.Intn(len(placeholders))])
		}
		if rng.Intn(9) == 0 {
			hdr.Set("X-Other", "note "+placeholders[rng.Intn(len(placeholders))])
		}
		body := []byte(bodies[rng.Intn(len(bodies))])
		if rng.Intn(13) == 0 {
			body = append(body, []byte(" "+placeholders[rng.Intn(len(placeholders))])...)
		}

		// The decision chain forward() runs, in order (04 §2).
		preq := &policy.Request{Method: method, Scheme: scheme, Host: host, Port: port,
			Path: path, Query: query}
		res := sess1.Policy.Match(preq)
		if res.Reason != "" {
			denyN["match:"+res.Reason]++
			continue
		}
		grant := grantByID(sess1.Policy, res.Grant)
		u := &url.URL{Path: path, RawQuery: query}
		if rng.Intn(17) == 0 {
			u.User = url.UserPassword("u", placeholders[rng.Intn(len(placeholders))])
		}
		r := &http.Request{Method: method, URL: u, Header: hdr, ContentLength: int64(len(body))}
		tgt := forwardTarget{scheme: scheme, authority: host, host: host, port: port, path: path, rawQuery: query}
		if checkLimits(grant, r, tgt) != "" {
			continue
		}
		h := stripHopByHop(hdr)
		var plan *credPlan
		var deny string
		if strings.HasPrefix(host, "s2-") {
			_ = sess2
		}
		plan, deny = evalCreds(sess1, grant, r, h, tgt, body)
		if deny != "" {
			denyN[deny]++
			continue
		}
		if plan == nil || plan.spec == nil {
			denyN["noncredentialed"]++
			continue
		}
		// Injection point: log the event with the request as the matcher
		// sees it (04 §3 record fields).
		reqJSON, _ := json.Marshal(map[string]any{
			"method": method, "scheme": scheme, "host": host, "port": port,
			"path": path, "query": query, "sni": "", "connect": "",
		})
		events = append(events, ev{Grant: res.Grant, Req: reqJSON})
		batch = append(batch, map[string]any{
			"policy":  specDoc,
			"request": json.RawMessage(reqJSON),
		})
	}
	t.Logf("%d/%d requests produced injection events; deny reasons %v", len(events), N, denyN)
	if len(events) < N/20 {
		t.Fatalf("only %d/%d requests injected — generator coverage too thin", len(events), N)
	}

	// Batch through the Python reference matcher.
	batchJSON, _ := json.Marshal(map[string]any{"cases": batch})
	casesFile := filepath.Join(dir, "cases.json")
	if err := os.WriteFile(casesFile, batchJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	pyBin := filepath.Join(fxtest.ToolsDir(), "bin", "python3")
	ref := filepath.Join(repoRoot(), "ref", "python", "refreconcile", "match.py")
	cmd := exec.Command(pyBin, ref)
	cmd.Stdin = mustOpen(t, casesFile)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("reference matcher: %v", err)
	}
	var results []struct {
		Grant  *string `json:"grant"`
		Reason *string `json:"reason"`
	}
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("matcher output: %v (%s)", err, out[:min(len(out), 200)])
	}
	if len(results) != len(events) {
		t.Fatalf("matcher returned %d results for %d events", len(results), len(events))
	}
	for i, r := range results {
		if r.Reason != nil || r.Grant == nil || *r.Grant != events[i].Grant {
			var evMap map[string]any
			_ = json.Unmarshal(events[i].Req, &evMap)
			t.Fatalf("event %d: injected under grant %q but reference says grant=%v reason=%v req=%v",
				i, events[i].Grant, r.Grant, r.Reason, evMap)
		}
	}
}

func mustOpen(t *testing.T, p string) *os.File {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func repoRoot() string {
	// internal/proxy -> repo root is ../..
	wd, _ := os.Getwd()
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// --- C3.2.6 -------------------------------------------------------------
// Write-ahead: a credential is injected only after the effect.http record
// is durable. A failing sink must surface LEDGER_UNAVAILABLE with zero
// upstream contact (C2.4.1, M2.4).
func TestC326InjectAfterAck(t *testing.T) {
	var fs *failableSink
	var injected atomic.Int32
	prev := injectHook
	injectHook = func(sessID, grantID, ref string) { injected.Add(1) }
	defer func() { injectHook = prev }()

	ce := startCredEnv(t, m3Grants, func(dir string) RecordSink {
		inner, err := NewFileRecordSink(filepath.Join(dir, "records"))
		if err != nil {
			t.Fatal(err)
		}
		fs = &failableSink{inner: inner, rejected: make(chan string, 16)}
		return fs
	})
	e := ce.env
	p := ph(t, e, "s1", "anthropic")

	fs.fail.Store(true)
	res, _ := doCred(t, e, "tok-one", "POST", "https://api.anthropic.com/v1/messages",
		map[string]string{"X-Api-Key": p}, []byte("{}"))
	if res.StatusCode != 502 {
		t.Fatalf("failing sink: status %d want 502", res.StatusCode)
	}
	if got := res.Header.Get("X-Countersign-Reason"); got != "LEDGER_UNAVAILABLE" {
		t.Fatalf("reason %q want LEDGER_UNAVAILABLE", got)
	}
	if injected.Load() != 0 {
		t.Fatal("credential injected before the record was durable")
	}
	if ce.anthro.count() != 0 {
		t.Fatal("upstream saw a request under a failing sink")
	}

	// Healthy path: injection happens (and only once the record landed).
	fs.fail.Store(false)
	res, _ = doCred(t, e, "tok-one", "POST", "https://api.anthropic.com/v1/messages",
		map[string]string{"X-Api-Key": p}, []byte("{}"))
	if res.StatusCode != 200 {
		t.Fatalf("healthy: status %d", res.StatusCode)
	}
	if injected.Load() != 1 {
		t.Fatalf("expected 1 injection, got %d", injected.Load())
	}
	recs := e.readSessionRecords(t, "s1")
	effs := recordsOfType[EffectHTTPBody](t, recs, "effect.http")
	var allow *EffectHTTPBody
	for i := range effs {
		if effs[i].Decision.Action == "allow" {
			allow = &effs[i]
		}
	}
	if allow == nil || len(allow.Decision.Creds) != 1 {
		t.Fatal("no allowed effect with credentials recorded")
	}
}

// --- MM3.3 ----------------------------------------------------------------
// Added p50 latency of policy evaluation + injection over M2's pipeline:
// the grant match, the §4.3–4.4 credential rules, and the header write —
// timed in-process on the same session/policy the wire tests use. The
// round-trip number is dominated by CONNECT/TLS/records and cannot see
// the added cost; this measures exactly the hot path M3 adds.
func TestM32InjectLatency(t *testing.T) {
	ce := startCredEnv(t, m3Grants, nil)
	e := ce.env
	sess := e.broker.Session("s1")
	if sess == nil {
		t.Fatal("no session s1")
	}
	grant := grantByID(sess.Policy, "anthropic")
	if grant == nil {
		t.Fatal("no grant")
	}
	p := ph(t, e, "s1", "anthropic")
	mk := func() (*http.Request, http.Header, forwardTarget, []byte) {
		r, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
		h := http.Header{"X-Api-Key": {p}, "Content-Type": {"application/json"}}
		tgt := forwardTarget{scheme: "https", host: "api.anthropic.com",
			port: 443, authority: "api.anthropic.com:443", path: "/v1/messages"}
		return r, h, tgt, []byte("{}")
	}

	const N = 4000
	durs := make([]float64, 0, N)
	for i := 0; i < N; i++ {
		r, h, tgt, body := mk()
		st := time.Now()
		res := sess.Policy.Match(&policy.Request{
			Method: r.Method, Scheme: tgt.scheme, Host: tgt.host,
			Port: tgt.port, Path: tgt.path, Query: tgt.rawQuery,
			Connect: "", SNI: tgt.host,
		})
		plan, reason := evalCreds(sess, grant, r, h, tgt, body)
		if reason != "" || plan == nil || plan.spec == nil || res.Grant != "anthropic" {
			t.Fatalf("eval failed: res=%+v reason=%q", res, reason)
		}
		plan.spec.Apply(h)
		durs = append(durs, float64(time.Since(st).Nanoseconds())/1e6)
	}
	sort.Float64s(durs)
	p50 := durs[len(durs)/2]
	p99 := durs[len(durs)*99/100]
	fmt.Printf("MEASUREMENT eval_inject_p50_ms %.4f eval_inject_p99_ms %.4f\n", p50, p99)
	if p50 > 0.3 {
		t.Fatalf("policy eval + credential rules + inject p50 %.4f ms > 0.3 ms", p50)
	}
}
