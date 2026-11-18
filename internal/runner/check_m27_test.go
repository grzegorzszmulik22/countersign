// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package runner_test

// M2.7 check suite. These tests orchestrate the real binaries: cs (the
// runner), csverify, m27helper and the pinned python. When M27_BIN is
// unset (plain `go test`), TestMain builds them first — with -race on
// cs when the test binary itself is race-enabled, so `go test -race
// -tags fixtures ./internal/runner` covers the runner end to end.
// Fixtures (echo TLS) run in-process; the cs subprocess reaches them
// through CS_FIXTURE_RESOLVE / CS_FIXTURE_CA, exactly the env wiring
// the broker's fixtures build already supports.

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
	"github.com/countersign/countersign/internal/names"
	"github.com/countersign/countersign/test/fixtures/echo"
	"github.com/countersign/countersign/test/fixtures/fxlib"
)

func TestMain(m *testing.M) {
	if os.Getenv("M27_BIN") != "" {
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "m27bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mktemp:", err)
		os.Exit(1)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintln(os.Stderr, "cleanup:", err)
		}
	}()
	if err := buildBins(dir); err != nil {
		fmt.Fprintln(os.Stderr, "build:", err)
		os.Exit(1)
	}
	if err := os.Setenv("M27_BIN", dir); err != nil {
		fmt.Fprintln(os.Stderr, "M27_BIN:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// buildBins compiles the binaries the suite needs into dir. cs is
// built -race when the test binary is, so the spawned runner process
// reports its own data races on stderr (run() then fails the test).
func buildBins(dir string) error {
	gob, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("go toolchain: %w", err)
	}
	builds := []struct{ out, pkg string }{
		{"cs", "./cmd/cs"},
		{"csverify", "./cmd/csverify"},
		{"m27helper", "./test/runner/m27helper"},
	}
	for _, b := range builds {
		args := []string{"build", "-tags", "fixtures"}
		if b.out == "cs" && raceEnabled {
			args = append(args, "-race")
		}
		args = append(args, "-o", filepath.Join(dir, b.out), b.pkg)
		cmd := exec.Command(gob, args...)
		cmd.Dir = repoRoot()
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("go %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	return nil
}

func repoRoot() string {
	if root := os.Getenv("M27_ROOT"); root != "" {
		if abs, err := filepath.Abs(root); err == nil {
			return abs
		}
	}
	root, _ := filepath.Abs("../..")
	return root
}

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
		t.Fatal("M27_BIN not set (TestMain builds it; run via test/checks/check-M2.7.sh)")
	}
	root := repoRoot()
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
	pol := `apiVersion: ` + names.APIGroup + `/v1alpha1
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

// fixtureEnv is the broker-side fixture wiring: the cs process's
// resolver and CA, never meant to cross into the sandbox.
func (m *m27) fixtureEnv() []string {
	return []string{
		"CS_FIXTURE_RESOLVE=echo.example.com=" + m.echoAddr + ",httpbin.org=" + m.echoAddr,
		"CS_FIXTURE_CA=" + m.caFile,
	}
}

// baseEnv is the environment every `cs run` subprocess gets: the test
// process's ambient env plus the fixture resolver wiring.
func (m *m27) baseEnv() []string {
	return append(os.Environ(), m.fixtureEnv()...)
}

type runOut struct {
	stdout, stderr  string
	code            int
	sid, bundle, rd string
	dd              string
}

// run executes `cs run -- <cmdline>` under baseEnv()+extraEnv and
// returns captured output plus the runner's reported session fields.
// A nonzero command status is NOT a test failure here; callers assert
// what they need. A race warning from an instrumented cs is.
func (m *m27) run(t *testing.T, extraEnv []string, opts []string, cmdline ...string) runOut {
	t.Helper()
	return m.runEnv(t, append(m.baseEnv(), extraEnv...), opts, cmdline...)
}

// runEnv is run with a fully test-controlled environment — the ambient
// list goes to cs verbatim, so duplicates and hostile values survive to
// exercise the boundary's env construction.
func (m *m27) runEnv(t *testing.T, ambient []string, opts []string, cmdline ...string) runOut {
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
	cmd.Env = ambient
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	out := runOut{stdout: so.String(), stderr: se.String(), dd: dd, rd: rd}
	out.code = exitOf(err)
	if strings.Contains(out.stderr, "WARNING: DATA RACE") {
		t.Fatalf("data race in cs subprocess:\n%s", out.stderr)
	}
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

// sealBody returns the bundle's session.seal body.
func (m *m27) sealBody(t *testing.T, bundle string) *evidence.SessionSealBody {
	t.Helper()
	for _, r := range m.records(t, bundle) {
		if r.Type == "session.seal" {
			if b, ok := r.Body.(*evidence.SessionSealBody); ok {
				return b
			}
			t.Fatalf("session.seal body is %T", r.Body)
		}
	}
	t.Fatal("no session.seal record")
	return nil
}

// assertCleanSeal checks a seal's recorded fields against the session's
// emitters: a reason, all three emitter heads named, each clean.
func (m *m27) assertCleanSeal(t *testing.T, bundle, wantReason string) {
	t.Helper()
	seal := m.sealBody(t, bundle)
	if seal.Reason != wantReason {
		t.Fatalf("seal reason %q, want %q", seal.Reason, wantReason)
	}
	if len(seal.Emitters) != 3 {
		t.Fatalf("seal lists %d emitters, want 3", len(seal.Emitters))
	}
	seen := map[string]bool{}
	for _, e := range seal.Emitters {
		role, _, _ := strings.Cut(e.Emitter, "/")
		seen[role] = true
		if e.HeadHash == "" || e.HeadHash == evidence.ZeroHash {
			t.Fatalf("emitter %s sealed with empty head %q", e.Emitter, e.HeadHash)
		}
		if !e.Clean {
			t.Fatalf("emitter %s recorded unclean", e.Emitter)
		}
	}
	for _, want := range []string{"controller", "broker", "world"} {
		if !seen[want] {
			t.Fatalf("seal missing emitter %s", want)
		}
	}
	t.Logf("seal: reason=%s emitters=%v counts=%+v", seal.Reason, seen, seal.Counts)
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
		if err := f.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	scan := bufio.NewScanner(stdout)
	for len(addrs) < 4 && scan.Scan() {
		k, v, ok := strings.Cut(scan.Text(), "=")
		if ok {
			addrs[k] = v
		}
	}
	if len(addrs) < 4 {
		// The sink is being abandoned; kill errors just mean it
		// already exited.
		_ = cmd.Process.Kill()
		t.Fatalf("sink did not bind all listeners: got %v", addrs)
	}
	return addrs, func() {
		// Teardown: ESRCH is fine, anything else leaves a stray
		// listener only the process itself can release.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
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
