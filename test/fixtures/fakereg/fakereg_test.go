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
	// Resolve against the SubEnv PATH, not the test's ambient PATH — that is
	// what makes python3/npm land on the pinned toolchain on any host.
	path, err := env.LookPath(name)
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	cmd := exec.CommandContext(ctx, path, args...)
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

	// --- pinned-toolchain proof ------------------------------------------------
	// The clients above must have run the pinned binaries under .tools — a
	// SubEnv that falls back to ambient PATH would silently use (or fail to
	// find) the host's python3/npm. Prove it two ways: PATH resolution and
	// the executable each interpreter reports it is running.
	toolsDir := fxtest.ToolsDir()
	for _, line := range strings.Split(strings.TrimSpace(
		run(t, env, env.Dir, "sh", "-c", "command -v python3; command -v node; command -v npm")), "\n") {
		p, _ := filepath.EvalSymlinks(strings.TrimSpace(line))
		if !strings.HasPrefix(p, toolsDir+string(os.PathSeparator)) {
			t.Fatalf("client tool resolved outside .tools: %q (tools under %s)", line, toolsDir)
		}
	}
	exe := strings.TrimSpace(run(t, env, env.Dir, "python3", "-c", "import sys; print(sys.executable)"))
	if !strings.HasPrefix(exe, toolsDir+string(os.PathSeparator)) {
		t.Fatalf("pip ran %q, want an interpreter under %s", exe, toolsDir)
	}
	exe = strings.TrimSpace(run(t, env, env.Dir, "node", "-p", "process.execPath"))
	if !strings.HasPrefix(exe, toolsDir+string(os.PathSeparator)) {
		t.Fatalf("node ran %q, want a binary under %s", exe, toolsDir)
	}
	// npm is a node script: it reports its install prefix, which must be the
	// pinned node tree. An ambient npm — or one that picks up an ambient node
	// from PATH — reports /usr or similar instead.
	exe = strings.TrimSpace(run(t, env, env.Dir, "npm", "config", "get", "prefix"))
	if !strings.HasPrefix(exe, toolsDir+string(os.PathSeparator)) {
		t.Fatalf("npm reports prefix %q, want a tree under %s", exe, toolsDir)
	}

	// The pinned node links libatomic.so.1, which a minimal host may not ship
	// — the toolchain must provide it (.tools/lib + wrapper). Prove the full
	// path works where the library is absent: bind /dev/null over every
	// libatomic the host loader would find, inside a mount namespace.
	if _, err := os.Stat(filepath.Join(toolsDir, "lib", "libatomic.so.1.2.0")); err != nil {
		t.Fatalf("toolchain does not ship libatomic: %v", err)
	}
	envBin, _ := env.LookPath("env")
	if out, err := exec.Command(envBin, "LD_LIBRARY_PATH="+filepath.Join(toolsDir, "lib"),
		"ldd", filepath.Join(toolsDir, "node", "bin", "node")).CombinedOutput(); err != nil ||
		!strings.Contains(string(out), "libatomic.so.1 => "+filepath.Join(toolsDir, "lib")) {
		t.Fatalf("ldd does not resolve libatomic from .tools/lib:\n%s", out)
	}
	unshare, unshareErr := env.LookPath("unshare")
	if unshareErr == nil {
		unshareErr = exec.Command(unshare, "-rm", "true").Run()
	}
	if unshareErr == nil {
		script := `for f in /usr/lib64/libatomic* /lib64/libatomic* \
			/usr/lib/aarch64-linux-gnu/libatomic* /lib/aarch64-linux-gnu/libatomic* \
			/usr/lib/x86_64-linux-gnu/libatomic* /lib/x86_64-linux-gnu/libatomic*; do
			[ -e "$f" ] && mount --bind /dev/null "$f" 2>/dev/null
		done
		node --version && npm --version`
		ctx, cancel := context.WithTimeout(env.Ctx, time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, unshare, "-rm", "sh", "-c", script)
		cmd.Env = env.SubEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("node/npm fail without system libatomic: %v\n%s", err, out)
		}
	} else {
		t.Log("unshare -rm unavailable; relying on ldd resolution check")
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
