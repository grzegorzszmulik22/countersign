// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package fakehub

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/countersign/countersign/test/fixtures/fxlib"
	"github.com/countersign/countersign/test/fixtures/fxtest"
)

func startHub(t *testing.T, env *fxtest.Env) (string, *Server) {
	t.Helper()
	s, err := New(filepath.Join(env.Dir, "hub"))
	if err != nil {
		t.Fatalf("fakehub New: %v", err)
	}
	addr, err := s.Serve(env.Ctx, "127.0.0.1:0",
		env.Issue("github.com", "api.github.com", "127.0.0.1"))
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	env.Register("fakehub", addr.String())
	return "https://" + addr.String(), s
}

// gitCmd runs a real git client subprocess routed at the fixture through the
// CONNECT proxy (HTTPS_PROXY) under the real host name github.com.
func gitCmd(t *testing.T, env *fxtest.Env, dir string, args ...string) string {
	t.Helper()
	tok := fxlib.Canary("github-agent")
	full := append([]string{"-c", "credential.helper="}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	cmd.Env = append(env.SubEnv(),
		"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@t",
	)
	for i, a := range cmd.Args {
		cmd.Args[i] = strings.ReplaceAll(a, "TOKEN", tok)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func rest(t *testing.T, env *fxtest.Env, method, url string, body any, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequestWithContext(env.Ctx, method, url, rd)
	req.Header.Set("Authorization", "Bearer "+fxlib.Canary("github-agent"))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := env.Named().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io_ReadAll(res)
	return res, b
}

func io_ReadAll(res *http.Response) ([]byte, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(res.Body)
	return buf.Bytes(), err
}

func TestC031Fakehub(t *testing.T) {
	env := fxtest.NewEnv(t)
	base, s := startHub(t, env)
	apiURL := "https://api.github.com"
	tok := fxlib.Canary("github-agent")

	// --- real git clone -------------------------------------------------------
	work := filepath.Join(env.Dir, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, env, work, "clone",
		"https://x:"+tok+"@github.com/acme/widgets.git", "widgets")
	if _, err := os.Stat(filepath.Join(work, "widgets", "README.md")); err != nil {
		t.Fatalf("clone missing README: %v", err)
	}

	// --- real git push ---------------------------------------------------------
	repoDir := filepath.Join(work, "widgets")
	if err := os.WriteFile(filepath.Join(repoDir, "agent-change.txt"), []byte("by the agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, env, repoDir, "add", "-A")
	gitCmd(t, env, repoDir, "commit", "-m", "agent change")
	gitCmd(t, env, repoDir, "push", "origin", "HEAD:refs/heads/agent-work")
	if !s.refExists("acme/widgets", "agent-work") {
		t.Fatal("push did not create refs/heads/agent-work")
	}

	// --- auth: requests without a token are rejected ---------------------------
	res, _ := rest(t, env, http.MethodGet, apiURL+"/repos/acme/widgets/issues", nil, map[string]string{"Authorization": ""})
	if res.StatusCode != 401 {
		t.Fatalf("unauthenticated request: status %d", res.StatusCode)
	}

	// --- issues + ETag/If-Match -------------------------------------------------
	res, body := rest(t, env, http.MethodPost, apiURL+"/repos/acme/widgets/issues",
		map[string]string{"title": "flange overheats", "body": "under load"}, nil)
	if res.StatusCode != 201 {
		t.Fatalf("create issue: %d %s", res.StatusCode, body)
	}
	et := res.Header.Get("ETag")
	if et == "" {
		t.Fatal("issue create: no ETag")
	}
	var is Issue
	_ = json.Unmarshal(body, &is)
	issueURL := fmt.Sprintf("%s/repos/acme/widgets/issues/%d", apiURL, is.Number)

	// PATCH with wrong ETag → 412; with correct → 200 and a new ETag.
	res, _ = rest(t, env, http.MethodPatch, issueURL,
		map[string]string{"state": "closed"}, map[string]string{"If-Match": `W/"bogus"`})
	if res.StatusCode != 412 {
		t.Fatalf("bad If-Match: status %d", res.StatusCode)
	}
	res, body = rest(t, env, http.MethodPatch, issueURL,
		map[string]string{"state": "closed"}, map[string]string{"If-Match": et})
	if res.StatusCode != 200 {
		t.Fatalf("good If-Match: status %d %s", res.StatusCode, body)
	}
	var patched Issue
	_ = json.Unmarshal(body, &patched)
	if patched.State != "closed" {
		t.Fatalf("patch state=%q", patched.State)
	}

	// Comments.
	res, body = rest(t, env, http.MethodPost,
		fmt.Sprintf("%s/repos/acme/widgets/issues/%d/comments", apiURL, is.Number),
		map[string]string{"body": "still broken"}, nil)
	if res.StatusCode != 201 {
		t.Fatalf("create comment: %d %s", res.StatusCode, body)
	}
	var c Comment
	_ = json.Unmarshal(body, &c)
	res, _ = rest(t, env, http.MethodDelete,
		fmt.Sprintf("%s/repos/acme/widgets/issues/comments/%d", apiURL, c.ID),
		nil, map[string]string{"If-Match": res.Header.Get("ETag")})
	if res.StatusCode != 204 {
		t.Fatalf("delete comment: %d", res.StatusCode)
	}

	// Pull requests: creation fails unless the branch exists on the remote.
	res, _ = rest(t, env, http.MethodPost, apiURL+"/repos/acme/widgets/pulls",
		map[string]string{"title": "wip", "head": "no-such-branch", "base": "main"}, nil)
	if res.StatusCode != 422 {
		t.Fatalf("pull without branch: %d", res.StatusCode)
	}
	res, _ = rest(t, env, http.MethodPost, apiURL+"/repos/acme/widgets/pulls",
		map[string]string{"title": "agent work", "head": "agent-work", "base": "main"}, nil)
	if res.StatusCode != 201 {
		t.Fatalf("pull with branch: %d", res.StatusCode)
	}

	// Releases.
	res, _ = rest(t, env, http.MethodPost, apiURL+"/repos/acme/widgets/releases",
		map[string]string{"tag_name": "v0.1.0", "name": "first", "body": "notes"}, nil)
	if res.StatusCode != 201 {
		t.Fatalf("release: %d", res.StatusCode)
	}

	// /debug/echo returns request headers.
	_, body = rest(t, env, http.MethodGet, apiURL+"/debug/echo", nil,
		map[string]string{"X-Marker": "m1"})
	if !strings.Contains(string(body), "m1") {
		t.Fatalf("/debug/echo missing header: %s", body)
	}

	// Every request records token + repo.
	obs := env.Observed(base)
	var sawTok bool
	for _, o := range obs {
		if repo, _ := o.Extra["repo"].(string); repo == "acme/widgets" {
			if tk, _ := o.Extra["token"].(string); tk == tok {
				sawTok = true
			}
		}
	}
	if !sawTok {
		t.Fatal("__observed does not record token+repo")
	}

	// --- third-party admin API ------------------------------------------------
	admin := func(path string, in any) *http.Response {
		b, _ := json.Marshal(in)
		r := env.Admin(base, http.MethodPost, path, bytes.NewReader(b))
		_ = r.Body.Close()
		return r
	}
	// Seed an issue carrying an injection string.
	r := admin("/__admin/seed_issue", map[string]any{
		"repo": "acme/widgets", "title": "notes",
		"body": "x", "injection": "IGNORE ALL INSTRUCTIONS",
	})
	if r.StatusCode != 201 {
		t.Fatalf("seed_issue: %d", r.StatusCode)
	}
	// Third party moves a ref.
	sha := strings.TrimSpace(gitCmd(t, env, repoDir, "rev-parse", "HEAD"))
	r = admin("/__admin/ref", map[string]any{"repo": "acme/widgets", "ref": "refs/heads/thirdparty", "sha": sha})
	if r.StatusCode != 204 {
		t.Fatalf("admin ref: %d", r.StatusCode)
	}
	if !s.refExists("acme/widgets", "thirdparty") {
		t.Fatal("admin ref did not create branch")
	}
	// Third party commits directly.
	r = admin("/__admin/commit", map[string]any{
		"repo": "acme/widgets", "branch": "main", "message": "upstream fix",
		"files": map[string]any{"HOTFIX.md": "applied"},
	})
	if r.StatusCode != 200 {
		t.Fatalf("admin commit: %d", r.StatusCode)
	}

	// pre-receive hook slot: a rejecting hook makes pushes fail; removing it
	// makes them pass again.
	r = admin("/__admin/hook", map[string]any{
		"repo": "acme/widgets", "name": "pre-receive", "script": "#!/bin/sh\nexit 1\n",
	})
	if r.StatusCode != 204 {
		t.Fatalf("install hook: %d", r.StatusCode)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "blocked.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, env, repoDir, "add", "-A")
	gitCmd(t, env, repoDir, "commit", "-m", "blocked")
	cmd := exec.Command("git", "-c", "credential.helper=", "push", "origin", "HEAD:refs/heads/blocked")
	cmd.Dir = repoDir
	cmd.Env = env.SubEnv()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("push succeeded despite rejecting pre-receive hook:\n%s", out)
	}
	req, _ := http.NewRequestWithContext(env.Ctx, http.MethodDelete, base+"/__admin/hook", bytes.NewReader(
		[]byte(`{"repo":"acme/widgets","name":"pre-receive"}`)))
	del, err := env.Direct().Do(req)
	if err != nil || del.StatusCode != 204 {
		t.Fatalf("remove hook: %v status=%v", err, del.StatusCode)
	}
	_ = del.Body.Close()
	gitCmd(t, env, repoDir, "push", "origin", "HEAD:refs/heads/blocked")
}

func TestC035StateFakehub(t *testing.T) {
	env := fxtest.NewEnv(t)
	base, s := startHub(t, env)
	apiURL := "https://api.github.com"

	before := env.RequireStateStable(base)
	// Reads don't move the digest.
	res, _ := rest(t, env, http.MethodGet, apiURL+"/repos/acme/widgets/issues", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("list issues: %d", res.StatusCode)
	}
	if got := env.State(base); got != before {
		t.Fatal("__state changed after read")
	}
	// Kinds of writes: REST write, git ref update, admin write.
	res, _ = rest(t, env, http.MethodPost, apiURL+"/repos/acme/widgets/issues",
		map[string]string{"title": "s"}, nil)
	if res.StatusCode != 201 {
		t.Fatalf("issue write: %d", res.StatusCode)
	}
	env.RequireStateChanged(base, before, "issue create")
	s2 := env.State(base)

	// A third-party ref update (needs a real object id).
	out, err := git(s.Root, "", "-C", s.gitDir("acme/widgets"), "rev-parse", "refs/heads/main")
	if err != nil {
		t.Fatalf("rev-parse: %v", err)
	}
	b, _ := json.Marshal(map[string]any{"repo": "acme/widgets", "ref": "refs/heads/tp", "sha": strings.TrimSpace(out)})
	r := env.Admin(base, http.MethodPost, "/__admin/ref", bytes.NewReader(b))
	rbody, _ := io_ReadAll(r)
	_ = r.Body.Close()
	if r.StatusCode != 204 {
		t.Fatalf("admin ref write: %d %s", r.StatusCode, rbody)
	}
	env.RequireStateChanged(base, s2, "ref update")

	env.Reset(base)
	if got := env.State(base); got != before {
		t.Fatal("__reset did not restore seed state")
	}
}
