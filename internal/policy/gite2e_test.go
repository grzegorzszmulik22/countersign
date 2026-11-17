// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package policy_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/countersign/countersign/internal/names"
	"github.com/countersign/countersign/internal/policy"
	"github.com/countersign/countersign/test/fixtures/fakehub"
	"github.com/countersign/countersign/test/fixtures/fxlib"
	"github.com/countersign/countersign/test/fixtures/fxtest"
	"github.com/countersign/countersign/test/gateproxy"
)

// e2ePolicy is the SessionPolicy the gate enforces in these tests: one
// matcher grant on github.com scoped to acme/widgets.
func e2ePolicy(t *testing.T, access string) *policy.SessionPolicy {
	t.Helper()
	src := `apiVersion: "` + names.APIGroup + `/v1alpha1"
kind: "SessionPolicy"
metadata: {name: "git-e2e"}
spec:
  mode: "enforce"
  scenario: "agent"
  grants:
    - {id: "repo", match: {hosts: ["github.com"], matcher: {git-smart-http: {repos: ["acme/widgets"], access: "` + access + `"}}}}
`
	p, err := policy.Load([]byte(src))
	if err != nil {
		t.Fatalf("load e2e policy: %v", err)
	}
	return p
}

// startHub serves fakehub on its real host names, registered for fxres.
func startHub(t *testing.T, env *fxtest.Env) (string, *fakehub.Server) {
	t.Helper()
	s, err := fakehub.New(filepath.Join(env.Dir, "hub"))
	if err != nil {
		t.Fatalf("fakehub New: %v", err)
	}
	addr, err := s.Serve(env.Ctx, "127.0.0.1:0",
		env.Issue("github.com", "api.github.com", "127.0.0.1"))
	if err != nil {
		t.Fatalf("serve fakehub: %v", err)
	}
	env.Register("fakehub", addr.String())
	return "https://" + addr.String(), s
}

// gitEnv is the subprocess environment for a real git client routed through
// the gate (not the plain fxres proxy) and trusting the fixture CA.
func gitEnv(env *fxtest.Env, gate *gateproxy.Proxy) []string {
	out := env.SubEnv()
	for i, kv := range out {
		if strings.HasPrefix(kv, "HTTPS_PROXY=") || strings.HasPrefix(kv, "https_proxy=") ||
			strings.HasPrefix(kv, "HTTP_PROXY=") || strings.HasPrefix(kv, "http_proxy=") {
			out[i] = strings.SplitN(kv, "=", 2)[0] + "=http://" + gate.Addr()
		}
	}
	return out
}

// gitRun runs one git command through the gate; it reports (output, error)
// so denials are assertable without failing the test.
func gitRun(t *testing.T, env *fxtest.Env, gate *gateproxy.Proxy, dir string, args ...string) (string, error) {
	t.Helper()
	tok := fxlib.Canary("github-agent")
	full := append([]string{"-c", "credential.helper="}, args...)
	ctx, cancel := context.WithTimeout(env.Ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = dir
	cmd.Env = append(gitEnv(env, gate),
		"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@t",
	)
	for i, a := range cmd.Args {
		cmd.Args[i] = strings.ReplaceAll(a, "TOKEN", tok)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func gitOK(t *testing.T, env *fxtest.Env, gate *gateproxy.Proxy, dir string, args ...string) string {
	t.Helper()
	out, err := gitRun(t, env, gate, dir, args...)
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// denied finds a recorded gate decision with a non-empty reason matching
// wantSubstr in the request target (path?query).
func denied(decs []gateproxy.Decision, wantSubstr string) *gateproxy.Decision {
	for i := range decs {
		d := &decs[i]
		target := d.Path + "?" + d.Query
		if d.Reason != "" && strings.Contains(target, wantSubstr) {
			return d
		}
	}
	return nil
}

func obsForRepo(obs []fxlib.Observation, repo, service string) int {
	n := 0
	for _, o := range obs {
		r, _ := o.Extra["repo"].(string)
		s, _ := o.Extra["service"].(string)
		if r == repo && s == service {
			n++
		}
	}
	return n
}

// TestC361GitSmartHTTP is C3.6.1: a real git client against fakehub through
// the policy gate. access:read permits clone and fetch but refuses the push
// at the git-receive-pack advertisement; access:write lets the same push
// through. (The broker data plane is M2; the gate runs the same §2 decision
// function the broker calls per request.)
func TestC361GitSmartHTTP(t *testing.T) {
	env := fxtest.NewEnv(t)
	base, _ := startHub(t, env)
	tok := fxlib.Canary("github-agent")

	read := gateproxy.New(t, env.CA, e2ePolicy(t, "read"))
	write := gateproxy.New(t, env.CA, e2ePolicy(t, "write"))

	work := filepath.Join(env.Dir, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}

	// access: read — clone and fetch succeed (info/refs?service=git-upload-pack
	// plus POST git-upload-pack are inside the read set).
	gitOK(t, env, read, work, "clone",
		"https://x:"+tok+"@github.com/acme/widgets.git", "widgets")
	repoDir := filepath.Join(work, "widgets")
	if _, err := os.Stat(filepath.Join(repoDir, "README.md")); err != nil {
		t.Fatalf("clone missing README: %v", err)
	}
	gitOK(t, env, read, repoDir, "fetch", "origin")

	// access: read — push is refused: the receive-pack advertisement gets
	// NO_GRANT and git never reaches POST git-receive-pack.
	if err := os.WriteFile(filepath.Join(repoDir, "change.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitOK(t, env, read, repoDir, "add", "-A")
	gitOK(t, env, read, repoDir, "commit", "-m", "agent change")
	out, err := gitRun(t, env, read, repoDir, "push", "origin", "HEAD:refs/heads/denied-read")
	if err == nil {
		t.Fatalf("push under access:read unexpectedly succeeded:\n%s", out)
	}
	d := denied(read.Decisions(), "git-receive-pack")
	if d == nil || d.Reason != policy.ReasonNoGrant {
		t.Fatalf("no NO_GRANT recorded for a git-receive-pack request; decisions: %+v",
			read.Decisions())
	}
	if obsForRepo(env.Observed(base), "acme/widgets", "git-receive-pack") != 0 {
		t.Fatal("fakehub saw a git-receive-pack request under access:read")
	}
	// The denied ref does not exist: ls-remote (a read) shows nothing.
	if out := gitOK(t, env, read, repoDir, "ls-remote", "origin", "refs/heads/denied-read"); out != "" {
		t.Fatalf("denied push created a ref: %s", out)
	}

	// access: write — the same push goes through end to end.
	stateBefore := env.State(base)
	gitOK(t, env, write, repoDir, "push", "origin", "HEAD:refs/heads/agent-work")
	if out := gitOK(t, env, write, repoDir, "ls-remote", "origin", "refs/heads/agent-work"); out == "" {
		t.Fatal("push under access:write did not create refs/heads/agent-work")
	}
	if obsForRepo(env.Observed(base), "acme/widgets", "git-receive-pack") == 0 {
		t.Fatal("fakehub recorded no git-receive-pack under access:write")
	}
	env.RequireStateChanged(base, stateBefore, "git push agent-work")
	gitOK(t, env, write, repoDir, "fetch", "origin")
}

// TestC362CrossRepoPush is C3.6.2: a grant scoped to acme/widgets does not
// authorize a push to attacker/loot on the same host — NO_GRANT, and the
// fixture records no write (scenario A2/B3 in miniature).
func TestC362CrossRepoPush(t *testing.T) {
	env := fxtest.NewEnv(t)
	base, _ := startHub(t, env)
	tok := fxlib.Canary("github-agent")
	write := gateproxy.New(t, env.CA, e2ePolicy(t, "write"))

	work := filepath.Join(env.Dir, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	gitOK(t, env, write, work, "clone",
		"https://x:"+tok+"@github.com/acme/widgets.git", "widgets")
	repoDir := filepath.Join(work, "widgets")
	if err := os.WriteFile(filepath.Join(repoDir, "loot.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitOK(t, env, write, repoDir, "add", "-A")
	gitOK(t, env, write, repoDir, "commit", "-m", "loot")

	before := env.State(base)
	out, err := gitRun(t, env, write, repoDir, "push",
		"https://x:"+tok+"@github.com/attacker/loot.git", "HEAD:refs/heads/stolen")
	if err == nil {
		t.Fatalf("push to attacker/loot unexpectedly succeeded:\n%s", out)
	}
	d := denied(write.Decisions(), "/attacker/loot")
	if d == nil || d.Reason != policy.ReasonNoGrant {
		t.Fatalf("no NO_GRANT recorded for the attacker/loot request; decisions: %+v",
			write.Decisions())
	}
	obs := env.Observed(base)
	if obsForRepo(obs, "attacker/loot", "git-receive-pack") != 0 {
		t.Fatal("fakehub saw a git-receive-pack request for attacker/loot")
	}
	if obsForRepo(obs, "attacker/loot", "") != 0 {
		t.Fatal("fakehub saw any request for attacker/loot")
	}
	if after := env.State(base); after != before {
		t.Fatal("fakehub state changed after the denied push")
	}
}
