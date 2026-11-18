// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package runner_test

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/countersign/countersign/internal/evidence"
)

// TestC2_7_1: anything ignoring the proxy vars fails inside the enforced
// boundary — direct TCP (loopback and real-IP targets), UDP, IPv6, the
// relay-spoof protocol — while the fixture's observation log stays
// empty. The identical probe in cooperative mode reaches everything,
// which is exactly what boundary: cooperative means.
func TestC2_7_1(t *testing.T) {
	m := newM27(t)
	sinkLog := filepath.Join(m.work, "sink.log")
	addrs, stop := m.sink(t, sinkLog)
	defer stop()
	m.obs.Reset()

	host := hostIPv4(t)
	out := m.run(t, nil, nil, m.helper, "-mode", "leak",
		"-tcp", m.echoAddr+","+addrs["tcp"]+","+host+":1",
		"-tcp6", addrs["tcp6"],
		"-udp", addrs["udp"],
		"-unix", addrs["unix"],
		"-spoof-target", addrs["tcp"],
		"-rundir", "%RUNDIR%")
	t.Log(out.stdout, out.stderr)
	if out.code != 0 {
		t.Fatalf("leak probe run exited %d", out.code)
	}
	// Every TCP/IPv6 attempt must fail; "sent" is the best a UDP probe
	// can say — the sink log below is what proves silence. Unix sockets
	// are out of scope: they live on the shared filesystem, not in the
	// network namespace.
	for _, l := range strings.Split(out.stdout, "\n") {
		if strings.Contains(l, " reach ") && !strings.HasPrefix(l, "unix ") {
			t.Fatalf("escape succeeded: %s", l)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if data, err := os.ReadFile(sinkLog); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if l != "" && !strings.HasPrefix(l, "unix-arrival") {
				t.Fatalf("sandbox traffic reached host sinks:\n%s", data)
			}
		}
	}
	if n := m.obs.Len(); n != 0 {
		t.Fatalf("fixture observed %d requests during enforced leak probe", n)
	}

	// Sanity: a brokered request lands in the same observation log.
	out = m.run(t, nil, nil, "curl", "-sf", "https://echo.example.com/c271")
	if out.code != 0 {
		t.Fatalf("brokered curl exited %d\n%s", out.code, out.stderr)
	}
	if m.obs.Len() == 0 {
		t.Fatal("brokered request missing from fixture observations")
	}

	// Cooperative: the same probes reach the world — observability.
	_ = os.Remove(sinkLog)
	coop := m.run(t, nil, []string{"--cooperative"}, m.helper, "-mode", "leak",
		"-tcp", addrs["tcp"], "-tcp6", addrs["tcp6"], "-udp", addrs["udp"],
		"-unix", addrs["unix"], "-rundir", "%RUNDIR%")
	t.Log(coop.stdout, coop.stderr)
	time.Sleep(300 * time.Millisecond)
	data, err := os.ReadFile(sinkLog)
	if err != nil || len(data) == 0 {
		t.Fatalf("cooperative probe did not reach sinks:\n%s", coop.stdout)
	}
	if !strings.Contains(coop.stdout, " reach ") {
		t.Fatalf("cooperative leak probe reached nothing:\n%s", coop.stdout)
	}
}

// TestC2_7_2: a grandchild spawned with env -i — no proxy vars, no PATH,
// nothing — still cannot reach anything but the broker. It recovers the
// advertised boundary from the sandbox-visible proxy.env to prove the
// broker itself remains reachable.
func TestC2_7_2(t *testing.T) {
	m := newM27(t)
	m.obs.Reset()
	script := filepath.Join(m.work, "gc.sh")
	writeFile(t, script, `#!/bin/sh
# $1 is the run dir visible inside the sandbox.
"$M27_HELPER" -mode leak -tcp "$2" -udp "$3" -rundir "$1" -spoof-target "$2"
set -a
. "$1/proxy.env"
set +a
curl -sf https://echo.example.com/gc-envi >/dev/null
`)
	out := m.run(t, nil, nil, "/usr/bin/env", "-i",
		"M27_HELPER="+m.helper, "PATH="+os.Getenv("PATH"),
		"/bin/sh", script, "%RUNDIR%", m.echoAddr, "127.0.0.1:1")
	t.Log(out.stdout, out.stderr)
	if out.code != 0 {
		t.Fatalf("grandchild run exited %d", out.code)
	}
	if strings.Contains(out.stdout, " reach ") {
		t.Fatalf("env -i grandchild escaped:\n%s", out.stdout)
	}
	found := false
	for _, o := range m.obs.List() {
		if o.Path == "/gc-envi" {
			found = true
		}
	}
	if !found {
		t.Fatalf("grandchild could not reach the broker either; observations: %+v", m.obs.List())
	}
}

// TestC2_7_3: curl, git smart HTTP, Python urllib and a Node env-aware
// proxy client each reach the echo fixture through the broker under the
// session CA; every observed request has a ledger record.
func TestC2_7_3(t *testing.T) {
	m := newM27(t)
	m.obs.Reset()
	script := filepath.Join(m.work, "clients.sh")
	writeFile(t, script, `#!/bin/sh
set -x
curl -sf https://echo.example.com/c-curl >/dev/null || echo "curl rc=$?"
GIT_TERMINAL_PROMPT=0 git ls-remote https://echo.example.com/acme/widgets.git >/dev/null 2>&1 || echo "git rc=$?"
"$M27_PY" - <<'PYEOF'
try:
    import requests
    print("py:", requests.get("https://echo.example.com/c-py", timeout=15).status_code)
except ImportError:
    import urllib.request
    print("py:", urllib.request.urlopen("https://echo.example.com/c-py").status)
PYEOF
NODE_USE_ENV_PROXY=1 "$M27_NODE" -e 'fetch("https://echo.example.com/c-node").then(r=>console.log("node:",r.status))'
`)
	out := m.run(t, []string{"M27_PY=" + m.py, "M27_NODE=" + m.node(t)}, nil,
		"/bin/sh", script)
	t.Log(out.stdout, out.stderr)
	if out.code != 0 {
		t.Fatalf("clients run exited %d", out.code)
	}
	want := map[string]bool{
		"/c-curl": false,
		"/acme/widgets.git/info/refs?service=git-upload-pack": false,
		"/c-py":   false,
		"/c-node": false,
	}
	for _, o := range m.obs.List() {
		if _, ok := want[o.Path]; ok {
			want[o.Path] = true
		}
	}
	for p, seen := range want {
		if !seen {
			t.Fatalf("fixture did not observe %s; got %+v", p, m.obs.List())
		}
	}
	// Every observed request has a ledger record.
	var httpPaths []string
	for _, r := range m.records(t, out.bundle) {
		if r.Type == "effect.http" {
			if b, ok := r.Body.(*evidence.EffectHTTPBody); ok {
				httpPaths = append(httpPaths, b.Request.Path)
			}
		}
	}
	for p := range want {
		hit := false
		for _, rp := range httpPaths {
			if strings.Contains(p, rp) || strings.Contains(rp, strings.SplitN(p, "?", 2)[0]) {
				hit = true
			}
		}
		if !hit {
			t.Fatalf("no ledger record for %s; records: %v", p, httpPaths)
		}
	}
	// The finished session verifies.
	res := m.verify(t, out.bundle, "")
	if res["verdict"] != "CLEAN" && res["verdict"] != "CLEAN_WITH_DENIALS" {
		t.Fatalf("verdict %v\n%s", res["verdict"], out.stderr)
	}
	if res["boundary"] != "enforced" {
		t.Fatalf("boundary %v, want enforced", res["boundary"])
	}
}

// TestC2_7_4: the canary scan finds no real credential, no signing key,
// no session CA key inside the enforced boundary: the declared
// credential arrives only as a csph_ placeholder, the covered data
// directory is empty, and /proc shows only sandbox processes.
func TestC2_7_4(t *testing.T) {
	m := newM27(t)
	cred := "CANARY_GH_3KJ7D9XQ2W8N5M4P1R6T0V2B"
	filecan := "CANARY_FILE_9QZ8X7W6V5U4T3S2R1"

	// Bootstrap the data dir once so its keys exist to hunt for.
	boot := m.run(t, nil, nil, "/bin/true")
	if boot.code != 0 {
		t.Fatalf("bootstrap run: %s", boot.stderr)
	}
	// Plant a canary file inside the data dir; the tmpfs must hide it.
	writeFile(t, filepath.Join(boot.dd, "keys", "planted-canary.txt"), filecan+"\n")

	var needles []string
	keyDir := filepath.Join(boot.dd, "keys")
	ents, err := os.ReadDir(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		data, err := os.ReadFile(filepath.Join(keyDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		// PKCS8 PEM: the base64 DER line is what any copy contains.
		if blk, _ := pem.Decode(data); blk != nil {
			needles = append(needles, base64.StdEncoding.EncodeToString(blk.Bytes))
		}
	}
	needles = append(needles, cred, filecan, "PRIVATE KEY-----")

	workdir := filepath.Join(m.work, "sandbox-home")
	_ = os.MkdirAll(workdir, 0o755)
	// Needles travel in a file outside the scanned dirs: carrying them
	// on the scan's own argv would be a self-inflicted hit in
	// /proc/*/cmdline.
	needleFile := filepath.Join(m.work, "needles.txt")
	writeFile(t, needleFile, strings.Join(needles, "\n")+"\n")
	scan := fmt.Sprintf(
		`"$H" -mode env | grep '^GH_TOKEN='
"$H" -mode scan -findfile "%s" -dir "%s,%s" -empty "%s"`,
		needleFile, workdir, "%RUNDIR%", boot.dd)
	out := m.run(t,
		[]string{"GH_TOKEN=" + cred, "H=" + m.helper, "M27_HELPER=" + m.helper},
		[]string{"--data-dir", boot.dd}, "/bin/sh", "-c", scan)
	t.Log(out.stdout, out.stderr)
	if out.code != 0 {
		t.Fatalf("canary scan run exited %d", out.code)
	}
	if !strings.Contains(out.stdout, "GH_TOKEN=csph_") {
		t.Fatalf("credential is not a placeholder inside:\n%s", out.stdout)
	}
	if strings.Contains(out.stdout, cred) {
		t.Fatalf("real credential visible inside:\n%s", out.stdout)
	}
	if !strings.Contains(out.stdout, "clean") {
		t.Fatalf("canary scan found secret material inside:\n%s", out.stdout)
	}

	// The same scan under --cooperative is reported, not counted: with
	// no mount namespace the data dir is genuinely visible inside.
	cscan := fmt.Sprintf(`"$H" -mode scan -findfile "%s" -dir "%s,%s"`,
		needleFile, workdir, "%RUNDIR%")
	coop := m.run(t,
		[]string{"GH_TOKEN=" + cred, "H=" + m.helper, "M27_HELPER=" + m.helper},
		[]string{"--cooperative", "--data-dir", boot.dd},
		"/bin/sh", "-c", cscan)
	t.Logf("cooperative scan (informational): %s", coop.stdout)
}

// TestC2_7_5: with the namespace probe forced to fail, enforced mode
// refuses with a nonzero exit and the one-sentence message naming
// --cooperative; cooperative mode records boundary: cooperative and
// csverify prints it.
func TestC2_7_5(t *testing.T) {
	m := newM27(t)
	out := m.run(t, []string{"CS_RUN_PROBE_OVERRIDE=unavailable"}, nil, "/bin/true")
	t.Log(out.stdout, out.stderr)
	if out.code == 0 {
		t.Fatal("enforced run with forced probe failure succeeded")
	}
	msg := strings.TrimSpace(out.stderr)
	if !strings.Contains(msg, "--cooperative") {
		t.Fatalf("refusal does not name --cooperative: %q", msg)
	}
	line := ""
	for _, l := range strings.Split(msg, "\n") {
		if strings.Contains(l, "cs run:") {
			line = l
		}
	}
	if !strings.Contains(line, "unavailable") || !strings.Contains(line, "--cooperative") {
		t.Fatalf("refusal line malformed: %q", line)
	}
	if data, err := os.ReadFile(filepath.Join(out.dd, "probe.json")); err != nil {
		t.Fatalf("probe result not recorded: %v", err)
	} else if strings.Contains(string(data), `"ok": true`) {
		t.Fatalf("probe recorded success under override: %s", data)
	}

	coop := m.run(t, nil, []string{"--cooperative"}, "/bin/true")
	if coop.code != 0 {
		t.Fatalf("cooperative run: %s", coop.stderr)
	}
	res := m.verify(t, coop.bundle, "")
	if res["boundary"] != "cooperative" {
		t.Fatalf("cooperative boundary = %v", res["boundary"])
	}
	if res["verdict"] != "CLEAN" && res["verdict"] != "CLEAN_WITH_DENIALS" {
		t.Fatalf("cooperative verdict %v", res["verdict"])
	}
}

// TestC2_7_6: SIGINT terminates the command and its descendants — a
// trapped SIGINT marker fires, a heartbeat stops, a setsid stray inside
// the pid namespace dies with it — then the session seals into a bundle
// both verifiers accept.
func TestC2_7_6(t *testing.T) {
	m := newM27(t)
	heart := filepath.Join(m.work, "heart")
	stray := filepath.Join(m.work, "stray")
	intm := filepath.Join(m.work, "int-seen")
	dd := filepath.Join(m.work, "ddsig")
	rd := filepath.Join(m.work, "rdsig")

	agent := filepath.Join(m.work, "agent.sh")
	writeFile(t, agent, `#!/bin/sh
trap 'echo seen >> "'`+intm+`'"' INT
{ while :; do echo b >> "`+heart+`"; sleep 0.2; done; } &
setsid sh -c 'while :; do echo s >> "`+stray+`"; sleep 0.2; done' &
wait
`)
	args := []string{"run", "--data-dir", dd, "--run-dir", rd,
		"--policy", m.policy, "--", "/bin/sh", agent}
	cmd := exec.Command(m.bin, args...)
	cmd.Env = m.baseEnv()
	var se strings.Builder
	cmd.Stderr = &se
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Wait for the agent's heartbeat to be alive.
	alive := false
	for i := 0; i < 50; i++ {
		if sz := fileSize(heart); sz > 0 && fileSize(stray) > 0 {
			alive = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !alive {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("agent heartbeats never started:\n%s", se.String())
	}
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	waitErr := cmd.Wait()
	code := exitOf(waitErr)
	if code == 0 {
		t.Fatal("cs run exited 0 after SIGINT")
	}
	t.Logf("cs exit %d", code)

	// The forwarded SIGINT reached the agent (trap wrote the marker).
	if fileSize(intm) == 0 {
		t.Fatalf("SIGINT never reached the agent:\n%s", se.String())
	}
	// Command and all descendants are dead: both heartbeat files flat.
	s1a, s1b := fileSize(heart), fileSize(stray)
	time.Sleep(900 * time.Millisecond)
	if s2a, s2b := fileSize(heart), fileSize(stray); s2a != s1a || s2b != s1b {
		t.Fatalf("descendants still running: %d→%d %d→%d", s1a, s2a, s1b, s2b)
	}

	// The interrupted session sealed into a verifiable bundle.
	stderr := se.String()
	bundle := ""
	for _, l := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(l, "cs: bundle ") {
			bundle = strings.TrimSpace(strings.TrimPrefix(l, "cs: bundle "))
		}
	}
	if bundle == "" {
		t.Fatalf("no bundle reported:\n%s", stderr)
	}
	var sealed bool
	for _, r := range m.records(t, bundle) {
		if r.Type == "session.seal" {
			sealed = true
		}
	}
	if !sealed {
		t.Fatal("interrupted session never sealed")
	}
	res := m.verify(t, bundle, "")
	if res["verdict"] != "CLEAN" && res["verdict"] != "CLEAN_WITH_DENIALS" {
		t.Fatalf("verdict %v\n%s", res["verdict"], stderr)
	}
	if res["boundary"] != "enforced" {
		t.Fatalf("boundary %v", res["boundary"])
	}
	m.refcheck(t, bundle)
}

func fileSize(p string) int64 {
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return fi.Size()
}
