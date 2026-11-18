// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package runner_test

// M2.7 check suite. These tests orchestrate the real binaries built by
// test/checks/check-M2.7.sh: cs (the runner), csverify, m27helper and
// the pinned python. Fixtures (echo TLS) run in-process; the cs
// subprocess reaches them through CS_FIXTURE_RESOLVE / CS_FIXTURE_CA,
// exactly the env wiring the broker's fixtures build already supports.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/ledger"
	"github.com/countersign/countersign/test/fixtures/echo"
	"github.com/countersign/countersign/test/fixtures/fxlib"
)

type m27 struct {
	t        *testing.T
	bin      string // cs binary
	ver      string // csverify binary
	helper   string // m27helper binary
	py       string // pinned python
	refpy    string // refcheck.py
	work     string
	cancel   context.CancelFunc
	obs      *fxlib.Obs
	echoAddr string
	caFile   string
	policy   string
	seq      int
}

func newM27(t *testing.T) *m27 {
	t.Helper()
	bindir := os.Getenv("M27_BIN")
	if bindir == "" {
		t.Fatal("M27_BIN not set (run via test/checks/check-M2.7.sh)")
	}
	root, err := filepath.Abs(os.Getenv("M27_ROOT"))
	if err != nil || root == "" {
		root, _ = filepath.Abs("../..")
	}
	m := &m27{t: t, work: t.TempDir()}
	m.bin = filepath.Join(bindir, "cs")
	m.ver = filepath.Join(bindir, "csverify")
	m.helper = filepath.Join(bindir, "m27helper")
	m.py = filepath.Join(root, ".tools/bin/python3")
	m.refpy = filepath.Join(root, "test/runner/refcheck.py")
	for _, p := range []string{m.bin, m.ver, m.helper, m.py, m.refpy} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("missing %s: %v", p, err)
		}
	}
	ca, err := fxlib.EnsureCA(m.work)
	if err != nil {
		t.Fatal(err)
	}
	m.caFile = filepath.Join(m.work, "ca.crt")
	cert, err := ca.Issue([]string{"echo.example.com", "httpbin.org", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	srv := echo.New()
	m.obs = srv.Obs
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	t.Cleanup(cancel)
	addr, err := srv.Serve(ctx, "127.0.0.1:0", cert)
	if err != nil {
		t.Fatal(err)
	}
	m.echoAddr = addr.String()

	m.policy = filepath.Join(m.work, "policy.yaml")
	pol := `apiVersion: countersign.dev/v1alpha1
kind: SessionPolicy
metadata: {name: m27-check}
spec:
  mode: enforce
  grants:
    - id: echo
      action: allow
      match: {hosts: [echo.example.com, httpbin.org]}
    - id: gh
      action: allow
      match: {hosts: [api.anthropic.com]}
      credential:
        ref: {secret: anthropic, key: token}
        inject: {header: Authorization}
        placeholderEnv: GH_TOKEN
`
	if err := os.WriteFile(m.policy, []byte(pol), 0o644); err != nil {
		t.Fatal(err)
	}
	return m
}

// baseEnv is the environment every `cs run` subprocess gets: ambient
// plus the fixture resolver wiring.
func (m *m27) baseEnv() []string {
	return append(os.Environ(),
		"CS_FIXTURE_RESOLVE=echo.example.com="+m.echoAddr+",httpbin.org="+m.echoAddr,
		"CS_FIXTURE_CA="+m.caFile,
		"M27_HELPER="+m.helper)
}

type runOut struct {
	stdout, stderr  string
	code            int
	sid, bundle, rd string
	dd              string
}

// run executes `cs run -- <cmdline>` and returns captured output plus
// the runner's reported session fields. A nonzero command status is NOT
// a test failure here; callers assert what they need.
func (m *m27) run(t *testing.T, extraEnv []string, opts []string, cmdline ...string) runOut {
	t.Helper()
	dd := filepath.Join(m.work, fmt.Sprintf("dd%d", m.seq))
	rd := filepath.Join(m.work, fmt.Sprintf("rd%d", m.seq))
	m.seq++
	args := []string{"run", "--data-dir", dd, "--run-dir", rd, "--policy", m.policy}
	args = append(args, opts...)
	args = append(args, "--")
	for _, a := range cmdline {
		args = append(args, strings.ReplaceAll(a, "%RUNDIR%", rd))
	}
	cmd := exec.Command(m.bin, args...)
	cmd.Env = append(m.baseEnv(), extraEnv...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	out := runOut{stdout: so.String(), stderr: se.String(), dd: dd, rd: rd}
	out.code = exitOf(err)
	for _, l := range strings.Split(out.stderr, "\n") {
		switch {
		case strings.HasPrefix(l, "cs: session "):
			out.sid = strings.TrimSpace(strings.TrimPrefix(l, "cs: session "))
		case strings.HasPrefix(l, "cs: bundle "):
			out.bundle = strings.TrimSpace(strings.TrimPrefix(l, "cs: bundle "))
		case strings.HasPrefix(l, "cs: run-dir "):
			out.rd = strings.TrimSpace(strings.TrimPrefix(l, "cs: run-dir "))
		}
	}
	return out
}

func exitOf(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

// verify runs csverify on a bundle and parses the verdict JSON.
func (m *m27) verify(t *testing.T, bundle, keys string) map[string]any {
	t.Helper()
	keysArg := keys
	if keysArg == "" {
		// The data dir holds keys.json beside bundles/.
		keysArg = filepath.Join(filepath.Dir(filepath.Dir(bundle)), "keys.json")
	}
	cmd := exec.Command(m.ver, bundle, "--keys", keysArg)
	out, err := cmd.CombinedOutput()
	res := map[string]any{}
	if jerr := json.Unmarshal(bytes.TrimSpace(out), &res); jerr != nil {
		t.Fatalf("csverify output not JSON: %v\n%s", jerr, out)
	}
	if err != nil {
		t.Fatalf("csverify failed (%v):\n%s", err, out)
	}
	return res
}

// records decodes the bundle's records.jsonl into evidence records.
func (m *m27) records(t *testing.T, bundle string) []*evidence.Record {
	t.Helper()
	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	members, err := ledger.ReadBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	var recs []*evidence.Record
	for _, line := range bytes.Split(bytes.TrimSpace(members["records.jsonl"]), []byte("\n")) {
		_, _, r, err := evidence.DecodeRecordLine(line)
		if err != nil {
			t.Fatalf("record decode: %v", err)
		}
		recs = append(recs, r)
	}
	return recs
}

func (m *m27) refcheck(t *testing.T, bundle string) {
	t.Helper()
	keys := filepath.Join(filepath.Dir(filepath.Dir(bundle)), "keys.json")
	cmd := exec.Command(m.py, m.refpy, bundle, keys)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("refcheck: %v\n%s", err, out)
	}
}

// sink starts m27helper in sink mode and returns its bound addresses.
func (m *m27) sink(t *testing.T, log string) (addrs map[string]string, stop func()) {
	t.Helper()
	sock := filepath.Join(m.work, fmt.Sprintf("sink%d.sock", m.seq))
	cmd := exec.Command(m.helper, "-mode", "sink",
		"-tcp", "127.0.0.1:0", "-tcp6", "[::1]:0",
		"-udp", "127.0.0.1:0", "-unix", sock, "-out", log)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	addrs = map[string]string{}
	if f, ok := stdout.(*os.File); ok {
		_ = f.SetReadDeadline(time.Now().Add(8 * time.Second))
	}
	scan := bufio.NewScanner(stdout)
	for len(addrs) < 4 && scan.Scan() {
		k, v, ok := strings.Cut(scan.Text(), "=")
		if ok {
			addrs[k] = v
		}
	}
	if len(addrs) < 4 {
		_ = cmd.Process.Kill()
		t.Fatalf("sink did not bind all listeners: got %v", addrs)
	}
	return addrs, func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }
}

// node returns the pinned node binary.
func (m *m27) node(t *testing.T) string {
	if p, err := exec.LookPath("node"); err == nil {
		abs, _ := filepath.Abs(p)
		return abs
	}
	p := filepath.Join(filepath.Dir(m.py), "node")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("node not found: %v", err)
	}
	return p
}

// hostIPv4 returns a non-loopback address of this host for the
// "the real interface is unreachable too" probe.
func hostIPv4(t *testing.T) string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.IsGlobalUnicast() && ipn.IP.To4() != nil {
			return ipn.IP.String()
		}
	}
	t.Skip("no non-loopback IPv4 on host")
	return ""
}

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}
