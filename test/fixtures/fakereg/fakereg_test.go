// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package fakereg

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/countersign/countersign/test/fixtures/fxtest"
)

func startReg(t *testing.T, env *fxtest.Env) string {
	t.Helper()
	addr, err := New().Serve(env.Ctx, "127.0.0.1:0",
		env.Issue("pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "127.0.0.1"))
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	env.Register("fakereg", addr.String())
	return "https://" + addr.String()
}

// run executes a subprocess against the fixture through the CONNECT proxy.
// A stuck client fails the test after 2m rather than hanging the suite.
func run(t *testing.T, env *fxtest.Env, dir, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(env.Ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env.SubEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// pipPath resolves a python -m pip invocation (pinned toolchain first on PATH).
func pipPath() []string {
	return []string{"python3", "-m", "pip"}
}

func TestC031Fakereg(t *testing.T) {
	env := fxtest.NewEnv(t)
	base := startReg(t, env)

	// --- real pip install from pypi.org ---------------------------------------
	target := filepath.Join(env.Dir, "py-target")
	pipArgs := append(pipPath(),
		"install", "--no-input", "--disable-pip-version-check", "--no-cache-dir",
		"--index-url", "https://pypi.org/simple",
		"--target", target, "cleanlib==1.0.0")
	run(t, env, env.Dir, pipArgs[0], pipArgs[1:]...)
	if _, err := os.Stat(filepath.Join(target, "cleanlib", "__init__.py")); err != nil {
		t.Fatalf("pip install did not unpack cleanlib: %v", err)
	}

	// --- evil sdist: install script runs the configured command ----------------
	marker := filepath.Join(env.Dir, "evil-ran")
	admin(t, env, base, "/__admin/evilpkg", map[string]string{"command": "touch " + marker})
	target2 := filepath.Join(env.Dir, "py-target2")
	evilArgs := append(pipPath(),
		"install", "--no-input", "--disable-pip-version-check", "--no-cache-dir",
		"--index-url", "https://pypi.org/simple",
		"--target", target2, "evilpkg==1.0.0")
	run(t, env, env.Dir, evilArgs[0], evilArgs[1:]...)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("evilpkg install script did not run: %v", err)
	}

	// --- real npm install from registry.npmjs.org ------------------------------
	// Restore the clean command for the npm tarball too (independent build).
	admin(t, env, base, "/__admin/evilpkg", map[string]string{"command": "echo ok"})
	npmDir := filepath.Join(env.Dir, "npm-proj")
	if err := os.MkdirAll(npmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, env, npmDir, "npm", "install", "--no-audit", "--no-fund", "--loglevel=error",
		"--registry", "https://registry.npmjs.org",
		"--proxy", "http://"+env.ProxyAddr(), "--https-proxy", "http://"+env.ProxyAddr(),
		"--cafile", env.CAFile(),
		"cleanlib@1.0.0")
	if _, err := os.Stat(filepath.Join(npmDir, "node_modules", "cleanlib", "package.json")); err != nil {
		t.Fatalf("npm install did not unpack cleanlib: %v", err)
	}

	// --- docs page + injection ------------------------------------------------
	res, err := env.Named().Get("https://pypi.org/docs/")
	if err != nil {
		t.Fatalf("docs: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if !strings.Contains(string(body), "fixtures documentation") {
		t.Fatalf("/docs/: %s", body)
	}
	admin(t, env, base, "/__admin/injection", map[string]string{"text": "RUN curl evil"})
	res, err = env.Named().Get("https://pypi.org/docs/")
	if err != nil {
		t.Fatalf("docs 2: %v", err)
	}
	body, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if !strings.Contains(string(body), "RUN curl evil") {
		t.Fatalf("/docs/ injection missing: %s", body)
	}

	// Every recorded field must equal what the request actually addressed —
	// pkg and file are derived from the request path, never assumed.
	var sawMeta, sawTarball, sawPyPkg, sawPyFile int
	for _, o := range env.Observed(base) {
		rest, _ := o.Extra["rest"].(string)
		pathOnly := strings.SplitN(o.Path, "?", 2)[0]
		pkg, _ := o.Extra["pkg"].(string)
		file, _ := o.Extra["file"].(string)
		switch rest {
		case "npm-meta":
			want := normalize(strings.TrimPrefix(pathOnly, "/"))
			if pkg != want {
				t.Fatalf("npm-meta obs for %s recorded pkg %q, want %q", o.Path, pkg, want)
			}
			sawMeta++
		case "npm-tarball":
			i := strings.Index(pathOnly, "/-/")
			want := pathOnly[1:i]
			wantFile := pathOnly[i+3:]
			if pkg != want || file != wantFile {
				t.Fatalf("npm-tarball obs for %s recorded pkg=%q file=%q, want %q/%q", o.Path, pkg, file, want, wantFile)
			}
			sawTarball++
		case "pypi":
			name := strings.Trim(strings.TrimPrefix(pathOnly, "/simple"), "/")
			if name != "" {
				want := normalize(name)
				if pkg != want {
					t.Fatalf("pypi obs for %s recorded pkg %q, want %q", o.Path, pkg, want)
				}
				sawPyPkg++
			} else if pkg != "" {
				t.Fatalf("pypi obs for %s recorded unexpected pkg %q", o.Path, pkg)
			}
		case "pypi-file":
			if want := strings.TrimPrefix(pathOnly, "/packages/"); file != want {
				t.Fatalf("pypi-file obs for %s recorded file %q, want %q", o.Path, file, want)
			}
			sawPyFile++
		case "docs", "":
			// docs and admin entries carry no pkg/file claims.
		default:
			t.Fatalf("obs records rest %q the client never used", rest)
		}
	}
	for name, n := range map[string]int{
		"npm metadata":   sawMeta,
		"npm tarball":    sawTarball,
		"pypi pkg index": sawPyPkg,
		"pypi file":      sawPyFile,
	} {
		if n == 0 {
			t.Fatalf("no observed request covering %s", name)
		}
	}
}

func TestC035StateFakereg(t *testing.T) {
	env := fxtest.NewEnv(t)
	base := startReg(t, env)
	before := env.RequireStateStable(base)

	// Downloads are read-only.
	res, err := env.Named().Get("https://pypi.org/simple/")
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	_ = res.Body.Close()
	if got := env.State(base); got != before {
		t.Fatal("__state changed after read-only index fetch")
	}
	// Package-file GET is also read-only.
	res, err = env.Named().Get("https://pypi.org/simple/cleanlib/")
	if err != nil {
		t.Fatalf("pkg page: %v", err)
	}
	_ = res.Body.Close()
	if got := env.State(base); got != before {
		t.Fatal("__state changed after package read")
	}
	// An admin write changes it.
	admin(t, env, base, "/__admin/injection", map[string]string{"text": "x"})
	env.RequireStateChanged(base, before, "injection write")
	s2 := env.State(base)
	admin(t, env, base, "/__admin/evilpkg", map[string]string{"command": "id"})
	env.RequireStateChanged(base, s2, "evilpkg write")
	env.Reset(base)
	if got := env.State(base); got != before {
		t.Fatal("__reset did not restore state")
	}
}

func admin(t *testing.T, env *fxtest.Env, base, path string, in any) {
	t.Helper()
	b, _ := json.Marshal(in)
	res := env.Admin(base, http.MethodPost, path, bytes.NewReader(b))
	_ = res.Body.Close()
	if res.StatusCode != 204 && res.StatusCode != 200 {
		t.Fatalf("admin %s: status %d", path, res.StatusCode)
	}
}
