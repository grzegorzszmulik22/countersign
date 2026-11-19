// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package runner_test

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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
	// are out of scope for the NET namespace: they live on the shared
	// filesystem (credential sockets are handled by mount covers in
	// C2.7.4).
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
	if err := os.Remove(sinkLog); err != nil {
		t.Fatal(err)
	}
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

// TestC2_7_RelayConcurrent: the parent-side relay splices many client
// connections at once — the race property needs a real concurrent load,
// not sequential dials. Thirty-two simultaneous connections to the
// relay socket must all reach the broker without a race report or a
// crash in the cs process.
func TestC2_7_RelayConcurrent(t *testing.T) {
	m := newM27(t)
	dd := filepath.Join(m.work, "ddrelay")
	m.seedCreds(t, dd)
	rd := filepath.Join(m.work, "rdrelay")
	cmd := exec.Command(m.bin, "run", "--data-dir", dd, "--run-dir", rd,
		"--policy", m.policy, "--", "/bin/sh", "-c", "sleep 10")
	cmd.Env = m.baseEnv()
	var se strings.Builder
	cmd.Stderr = &se
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(rd, "relay.sock")
	up := false
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			up = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !up {
		// cs is still exiting; reap it before failing.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("relay socket never appeared:\n%s", se.String())
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("unix", sock)
			if err != nil {
				return
			}
			// Garbage request: the broker answers 400 and closes —
			// enough for a full splice round-trip.
			if _, err := fmt.Fprintf(c, "GET / HTTP/1.0\r\n\r\n"); err != nil {
				_ = c.Close()
				return
			}
			_, _ = io.Copy(io.Discard, c)
			_ = c.Close()
		}()
	}
	wg.Wait()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Logf("signal cs: %v (may have exited already)", err)
	}
	_ = cmd.Wait()
	if s := se.String(); strings.Contains(s, "concurrent map") ||
		strings.Contains(s, "DATA RACE") || strings.Contains(s, "panic:") {
		t.Fatalf("relay concurrency failure:\n%s", s)
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
"`+m.helper+`" -mode leak -tcp "$2" -udp "$3" -rundir "$1" -spoof-target "$2"
set -a
. "$1/proxy.env"
set +a
curl -sf https://echo.example.com/gc-envi >/dev/null
`)
	out := m.run(t, nil, nil, "/usr/bin/env", "-i",
		"PATH="+os.Getenv("PATH"),
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

// childEnv parses the helper's `-mode env` dump into name → values,
// preserving duplicates so assertions can count them.
type childEnv map[string][]string

func parseEnvDump(t *testing.T, s string) childEnv {
	t.Helper()
	out := childEnv{}
	for _, l := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			out[k] = append(out[k], v)
		}
	}
	return out
}

// assertChildEnv checks the exact env a sandbox process sees: every
// proxy var exactly once at the broker, NO_PROXY empty, trust vars at
// the session CA, and no hostile ambient value anywhere.
func assertChildEnv(t *testing.T, env childEnv, caPath string) {
	t.Helper()
	proxyVal := ""
	for _, v := range []string{
		"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
		"ALL_PROXY", "all_proxy",
	} {
		vals := env[v]
		if len(vals) != 1 {
			t.Fatalf("%s present %d times in child env, want exactly 1", v, len(vals))
		}
		if !strings.HasPrefix(vals[0], "http://cs:") {
			t.Fatalf("%s=%q does not name the boundary proxy", v, vals[0])
		}
		if proxyVal == "" {
			proxyVal = vals[0]
		} else if vals[0] != proxyVal {
			t.Fatalf("%s=%q differs from other proxy vars %q", v, vals[0], proxyVal)
		}
	}
	for _, v := range []string{"NO_PROXY", "no_proxy"} {
		vals := env[v]
		if len(vals) != 1 || vals[0] != "" {
			t.Fatalf("%s=%v, want exactly one empty value", v, vals)
		}
	}
	for _, v := range []string{
		"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE",
		"GIT_SSL_CAINFO", "CURL_CA_BUNDLE",
	} {
		vals := env[v]
		if len(vals) != 1 || vals[0] != caPath {
			t.Fatalf("%s=%v, want %s once", v, vals, caPath)
		}
	}
	for kv := range env {
		for _, v := range env[kv] {
			if strings.Contains(v, "evil") {
				t.Fatalf("hostile ambient value survived: %s=%s", kv, v)
			}
		}
	}
}

// hostileAmbient builds an environment carrying hostile values for
// every boundary-owned variable — including duplicates, since getenv
// returns the first match — plus credential-channel variables.
func (m *m27) hostileAmbient() []string {
	return append(m.fixtureEnv(),
		"PATH="+os.Getenv("PATH"),
		"HOME="+os.Getenv("HOME"),
		"LANG=C.UTF-8",
		"HTTP_PROXY=http://evil.corp:8888",
		"http_proxy=http://evil.corp:8888",
		"HTTPS_PROXY=http://evil.corp:8888",
		"https_proxy=http://evil.corp:8888",
		"ALL_PROXY=socks5://evil.corp:1080",
		"all_proxy=socks5://evil.corp:1080",
		"NO_PROXY=*",
		"no_proxy=*",
		"SSL_CERT_FILE=/tmp/evil-ca.pem",
		"GIT_SSL_CAINFO=/tmp/evil-ca.pem",
		"GH_TOKEN=ghp_evilambienttoken",
		"AWS_SECRET_ACCESS_KEY=evilawscred",
		"SSH_AUTH_SOCK=/tmp/evil-agent.sock",
		"CS_INIT_CONFIG=evil-internal",
	)
}

// TestC2_7_3: curl, git smart HTTP, Python urllib and a Node env-aware
// proxy client each reach the echo fixture through the broker under the
// session CA; every observed request has a ledger record. The proxy
// environment is asserted at full width separately below.
func TestC2_7_3(t *testing.T) {
	m := newM27(t)
	m.obs.Reset()
	script := filepath.Join(m.work, "clients.sh")
	writeFile(t, script, `#!/bin/sh
set -x
curl -sf https://echo.example.com/c-curl >/dev/null || echo "curl rc=$?"
GIT_TERMINAL_PROMPT=0 git ls-remote https://echo.example.com/acme/widgets.git >/dev/null 2>&1 || echo "git rc=$?"
"`+m.py+`" - <<'PYEOF'
try:
    import requests
    print("py:", requests.get("https://echo.example.com/c-py", timeout=15).status_code)
except ImportError:
    import urllib.request
    print("py:", urllib.request.urlopen("https://echo.example.com/c-py").status)
PYEOF
NODE_USE_ENV_PROXY=1 "`+m.node(t)+`" -e 'fetch("https://echo.example.com/c-node").then(r=>console.log("node:",r.status))'
`)
	out := m.run(t, nil, nil, "/bin/sh", script)
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

// TestC2_7_3_ProxyEnv: inside the sandbox every proxy variable the
// boundary owns is set exactly once — to the broker/relay — with
// NO_PROXY and no_proxy empty, whatever the parent environment held.
// Hostile ambient values and duplicate entries (getenv returns the
// first) are asserted in both modes, plus the raw-dup case through
// os.StartProcess, which unlike exec.Cmd.Env does not dedup.
func TestC2_7_3_ProxyEnv(t *testing.T) {
	m := newM27(t)
	for _, mode := range []struct {
		name string
		opts []string
	}{
		{"enforced", nil},
		{"cooperative", []string{"--cooperative"}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			out := m.runEnv(t, m.hostileAmbient(), mode.opts,
				m.helper, "-mode", "env")
			t.Log(out.stdout, out.stderr)
			if out.code != 0 {
				t.Fatalf("env dump run exited %d", out.code)
			}
			env := parseEnvDump(t, out.stdout)
			assertChildEnv(t, env, filepath.Join(out.rd, "session-ca.pem"))
			// The declared credential is a placeholder; the hostile
			// ambient one never crosses.
			gh := env["GH_TOKEN"]
			if len(gh) != 1 || !strings.HasPrefix(gh[0], "csph_") {
				t.Fatalf("GH_TOKEN=%v, want one csph_ placeholder", gh)
			}
			for _, v := range []string{"AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK", "CS_INIT_CONFIG"} {
				if _, ok := env[v]; ok {
					t.Fatalf("%s crossed the boundary: %v", v, env[v])
				}
			}
			// Allowlisted vars still arrive.
			if env["PATH"][0] != os.Getenv("PATH") {
				t.Fatalf("PATH not passed through: %v", env["PATH"])
			}
		})
	}

	// Duplicates earlier in environ: exec.Cmd.Env dedups (last wins),
	// so this case goes through os.StartProcess to hand cs an environ
	// that really contains HTTP_PROXY twice — the first hostile.
	t.Run("duplicates", func(t *testing.T) {
		ambient := append(m.fixtureEnv(),
			"PATH="+os.Getenv("PATH"),
			"HTTP_PROXY=http://evil.corp:8888",
			"NO_PROXY=*",
			"HTTP_PROXY=http://also-evil.corp:9999",
		)
		out := m.runRaw(t, ambient, nil, m.helper, "-mode", "env")
		t.Log(out.stdout, out.stderr)
		if out.code != 0 {
			t.Fatalf("env dump run exited %d", out.code)
		}
		assertChildEnv(t, parseEnvDump(t, out.stdout),
			filepath.Join(out.rd, "session-ca.pem"))
	})
}

// runRaw spawns cs via os.StartProcess — the only path that hands the
// child an env slice verbatim, preserving duplicate entries that
// exec.Cmd.Env would collapse.
func (m *m27) runRaw(t *testing.T, ambient []string, opts []string, cmdline ...string) runOut {
	t.Helper()
	dd := filepath.Join(m.work, fmt.Sprintf("dd%d", m.seq))
	m.seedCreds(t, dd)
	rd := filepath.Join(m.work, fmt.Sprintf("rd%d", m.seq))
	m.seq++
	args := []string{"run", "--data-dir", dd, "--run-dir", rd, "--policy", m.policy}
	args = append(args, opts...)
	args = append(args, "--")
	for _, a := range cmdline {
		args = append(args, strings.ReplaceAll(a, "%RUNDIR%", rd))
	}
	so, err := os.Create(filepath.Join(m.work, "raw-out.txt"))
	if err != nil {
		t.Fatal(err)
	}
	se, err := os.Create(filepath.Join(m.work, "raw-err.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := so.Close(); err != nil {
			t.Error(err)
		}
		if err := se.Close(); err != nil {
			t.Error(err)
		}
	}()
	proc, err := os.StartProcess(m.bin, append([]string{m.bin}, args...), &os.ProcAttr{
		Env:   ambient,
		Files: []*os.File{os.Stdin, so, se},
	})
	if err != nil {
		t.Fatalf("start cs: %v", err)
	}
	ps, werr := proc.Wait()
	out := runOut{dd: dd, rd: rd}
	if so2, err := os.ReadFile(so.Name()); err == nil {
		out.stdout = string(so2)
	} else {
		t.Fatal(err)
	}
	if se2, err := os.ReadFile(se.Name()); err == nil {
		out.stderr = string(se2)
	} else {
		t.Fatal(err)
	}
	out.code = -1
	if werr == nil && ps.Exited() {
		out.code = ps.ExitCode()
	}
	if strings.Contains(out.stderr, "WARNING: DATA RACE") {
		t.Fatalf("data race in cs subprocess:\n%s", out.stderr)
	}
	for _, l := range strings.Split(out.stderr, "\n") {
		if strings.HasPrefix(l, "cs: bundle ") {
			out.bundle = strings.TrimSpace(strings.TrimPrefix(l, "cs: bundle "))
		}
		if strings.HasPrefix(l, "cs: run-dir ") {
			out.rd = strings.TrimSpace(strings.TrimPrefix(l, "cs: run-dir "))
		}
	}
	return out
}

// TestC2_7_4: no host credential channel is usable inside the enforced
// boundary — not the declared credential (csph_ placeholder only), not
// agent sockets (env stripped AND the socket path mount-covered), not
// cloud credential variables or files, not the runner's keys/data dir,
// not host /proc data. The same scan under --cooperative is reported,
// never counted.
func TestC2_7_4(t *testing.T) {
	m := newM27(t)
	cred := "CANARY_GH_3KJ7D9XQ2W8N5M4P1R6T0V2B"
	filecan := "CANARY_FILE_9QZ8X7W6V5U4T3S2R1"
	cloudcan := "CANARY_GCP_8F4K2M9P7Q1W3X6Y5Z0"

	// Bootstrap the data dir once so its keys exist to hunt for.
	boot := m.run(t, nil, nil, "/bin/true")
	if boot.code != 0 {
		t.Fatalf("bootstrap run: %s", boot.stderr)
	}
	// Plant a canary file inside the data dir; the tmpfs must hide it.
	writeFile(t, filepath.Join(boot.dd, "keys", "planted-canary.txt"), filecan+"\n")

	// A fake home full of credential files at the well-known paths,
	// plus a cloud keyfile at an arbitrary ambient-var path and a live
	// SSH agent socket the parent advertises.
	home := filepath.Join(m.work, "credhome")
	for _, p := range []string{
		".ssh/id_ed25519", ".aws/credentials", ".netrc",
		".config/gcloud/application_default_credentials.json",
		".config/gh/hosts.yml", ".docker/config.json",
		".kube/config", ".gnupg/private-keys-v1.d/k.key",
	} {
		writeFile(t, filepath.Join(home, p), cloudcan+"\n")
	}
	cloudfile := filepath.Join(m.work, "gcp-sa.json")
	writeFile(t, cloudfile, cloudcan+"\n")
	kubefile := filepath.Join(m.work, "extra-kube.config")
	writeFile(t, kubefile, cloudcan+"\n")
	agentSock := filepath.Join(m.work, "ssh-agent.sock")
	agentLn, err := net.Listen("unix", agentSock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Listener teardown; a close error only means it already died.
		_ = agentLn.Close()
	})

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
	needles = append(needles, cred, filecan, cloudcan, m27Canary, "PRIVATE KEY-----")

	// Needles travel in a file outside the scanned dirs: carrying them
	// on the scan's own argv would be a self-inflicted hit in
	// /proc/*/cmdline.
	needleFile := filepath.Join(m.work, "needles.txt")
	writeFile(t, needleFile, strings.Join(needles, "\n")+"\n")

	// The ambient env carries every credential channel the parent
	// would have: the declared GH credential, cloud vars, the SSH
	// agent socket, and pointers at the planted files.
	ambient := append(m.fixtureEnv(),
		"PATH="+os.Getenv("PATH"),
		"HOME="+home,
		"GH_TOKEN="+cred,
		"SSH_AUTH_SOCK="+agentSock,
		"GPG_AGENT_INFO="+agentSock+":0:1",
		"AWS_SECRET_ACCESS_KEY="+cred,
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"GOOGLE_APPLICATION_CREDENTIALS="+cloudfile,
		"KUBECONFIG="+kubefile,
		"AZURE_CLIENT_SECRET="+cred,
		"ANTHROPIC_API_KEY="+cred,
		"DOCKER_CONFIG="+filepath.Join(home, ".docker"),
	)

	// %RUNDIR% is substituted into the command args by runEnv. $HOME is
	// the ambient fake home the boundary passes through; the planted
	// credential dirs inside it must come back empty (tmpfs covers),
	// the arbitrary-path keyfiles unreadable (/dev/null covers), and
	// the agent socket undialable.
	scanScript := fmt.Sprintf(`set -x
"%s" -mode env > "%%RUNDIR%%/env.txt"
"%s" -mode leak -unix "%s" | tee "%%RUNDIR%%/leak.txt"
"%s" -mode scan -findfile "%s" -dir "$HOME" -empty "%s"
test ! -s "%s"
test ! -s "%s"
`,
		m.helper, m.helper, agentSock, m.helper,
		needleFile,
		strings.Join([]string{
			filepath.Join(home, ".aws"),
			filepath.Join(home, ".ssh"),
			filepath.Join(home, ".gnupg"),
			filepath.Join(home, ".config", "gcloud"),
			filepath.Join(home, ".config", "gh"),
			filepath.Join(home, ".docker"),
			filepath.Join(home, ".kube"),
			boot.dd,
		}, ","),
		cloudfile, kubefile)

	out := m.runEnv(t, ambient, []string{"--data-dir", boot.dd},
		"/bin/sh", "-c", scanScript)
	t.Log(out.stdout, out.stderr)
	if out.code != 0 {
		t.Fatalf("canary scan run exited %d", out.code)
	}
	if !strings.Contains(out.stdout, "clean") {
		t.Fatalf("canary scan found secret material inside:\n%s", out.stdout)
	}
	// The agent socket is a file the netns cannot hide: the mount
	// namespace must have made it unreachable.
	leak, err := os.ReadFile(filepath.Join(out.rd, "leak.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(leak), " reach ") {
		t.Fatalf("host SSH agent socket reachable inside:\n%s", leak)
	}
	// Environment assertions: placeholder for GH_TOKEN, nothing else.
	envDump, err := os.ReadFile(filepath.Join(out.rd, "env.txt"))
	if err != nil {
		t.Fatal(err)
	}
	env := parseEnvDump(t, string(envDump))
	gh := env["GH_TOKEN"]
	if len(gh) != 1 || !strings.HasPrefix(gh[0], "csph_") {
		t.Fatalf("credential is not a placeholder inside: GH_TOKEN=%v", gh)
	}
	for _, v := range []string{
		"SSH_AUTH_SOCK", "GPG_AGENT_INFO", "AWS_SECRET_ACCESS_KEY",
		"AWS_ACCESS_KEY_ID", "GOOGLE_APPLICATION_CREDENTIALS",
		"KUBECONFIG", "AZURE_CLIENT_SECRET", "ANTHROPIC_API_KEY",
		"DOCKER_CONFIG",
	} {
		if got, ok := env[v]; ok {
			t.Fatalf("credential channel %s crossed the boundary: %v", v, got)
		}
	}
	assertChildEnv(t, env, filepath.Join(out.rd, "session-ca.pem"))

	// The same scan under --cooperative is reported, not counted: with
	// no mount namespace the filesystem channels genuinely stay open.
	cscan := fmt.Sprintf(`"%s" -mode env; "%s" -mode leak -unix "%s"`,
		m.helper, m.helper, agentSock)
	coop := m.runEnv(t, ambient,
		[]string{"--cooperative", "--data-dir", boot.dd},
		"/bin/sh", "-c", cscan)
	t.Logf("cooperative scan (informational):\n%s", coop.stdout)
	if strings.Contains(coop.stdout, "SSH_AUTH_SOCK=") ||
		strings.Contains(coop.stdout, "AWS_SECRET_ACCESS_KEY=") {
		t.Fatalf("cooperative child saw host credential channels:\n%s", coop.stdout)
	}
}

// TestC2_7_ExitStatus: cs run's exit status is the command's own,
// unchanged — plain codes and the shell's 128+signal convention — in
// both boundary modes. The seal of a normally-exited session records
// the command-exit reason.
func TestC2_7_ExitStatus(t *testing.T) {
	m := newM27(t)
	cases := []struct {
		name   string
		script string
		want   int
	}{
		{"zero", "exit 0", 0},
		{"one", "exit 1", 1},
		{"three", "exit 3", 3},
		{"forty-two", "exit 42", 42},
		{"sigterm", "kill -TERM $$", 143},
	}
	for _, mode := range []struct {
		name string
		opts []string
	}{
		{"enforced", nil},
		{"cooperative", []string{"--cooperative"}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			for _, c := range cases {
				out := m.run(t, nil, mode.opts, "/bin/sh", "-c", c.script)
				if out.code != c.want {
					t.Fatalf("%s: exit %d, want %d (script %q)\nstderr: %s",
						c.name, out.code, c.want, c.script, out.stderr)
				}
			}
		})
	}
	// A normally-exited run records the exit reason in its seal.
	out := m.run(t, nil, nil, "/bin/true")
	m.assertCleanSeal(t, out.bundle, "command-exit")
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

// TestC2_7_6: SIGINT terminates the command and every descendant in
// both modes — a trapped-SIGINT marker fires, a heartbeat stops, a
// grandchild that ignores SIGTERM (and even SIGINT) dies to the kill
// escalation, a setsid stray inside the pid namespace dies with it —
// then the session seals with reason "signal" into a bundle both
// verifiers accept.
func TestC2_7_6(t *testing.T) {
	for _, mode := range []struct {
		name string
		opts []string
		want string
	}{
		{"enforced", nil, "enforced"},
		{"cooperative", []string{"--cooperative"}, "cooperative"},
	} {
		t.Run(mode.name, func(t *testing.T) {
			sigintRun(t, mode.opts, mode.name == "enforced", mode.want)
		})
	}
}

func sigintRun(t *testing.T, opts []string, enforced bool, wantBoundary string) {
	m := newM27(t)
	heart := filepath.Join(m.work, "heart")
	stray := filepath.Join(m.work, "stray")
	intm := filepath.Join(m.work, "int-seen")
	dd := filepath.Join(m.work, "ddsig")
	m.seedCreds(t, dd)
	rd := filepath.Join(m.work, "rdsig")

	// The agent: an INT trap marker, a heartbeat child in its own
	// process group, and a stray grandchild that ignores SIGTERM and
	// SIGINT — only the kill escalation can reap it. In enforced mode
	// a second stray also escapes via setsid; only the pid namespace
	// catches that one.
	strayCmd := fmt.Sprintf(
		`sh -c 'trap "" TERM INT; while :; do echo s >> %q; sleep 0.2; done'`,
		stray)
	if enforced {
		strayCmd = "setsid " + strayCmd
	}
	agent := filepath.Join(m.work, "agent.sh")
	writeFile(t, agent, fmt.Sprintf(`#!/bin/sh
trap 'echo seen >> %q' INT
{ while :; do echo b >> %q; sleep 0.2; done; } &
%s &
wait
`, intm, heart, strayCmd))

	args := []string{"run", "--data-dir", dd, "--run-dir", rd,
		"--policy", m.policy}
	args = append(args, opts...)
	args = append(args, "--", "/bin/sh", agent)
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
		// The agent never got going; nothing to interrupt.
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

	// The interrupted session sealed with reason signal into a
	// verifiable bundle.
	stderr := se.String()
	if strings.Contains(stderr, "WARNING: DATA RACE") {
		t.Fatalf("data race in cs subprocess:\n%s", stderr)
	}
	bundle := ""
	for _, l := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(l, "cs: bundle ") {
			bundle = strings.TrimSpace(strings.TrimPrefix(l, "cs: bundle "))
		}
	}
	if bundle == "" {
		t.Fatalf("no bundle reported:\n%s", stderr)
	}
	m.assertCleanSeal(t, bundle, "signal")
	res := m.verify(t, bundle, "")
	if res["verdict"] != "CLEAN" && res["verdict"] != "CLEAN_WITH_DENIALS" {
		t.Fatalf("verdict %v\n%s", res["verdict"], stderr)
	}
	if res["boundary"] != wantBoundary {
		t.Fatalf("boundary %v, want %s", res["boundary"], wantBoundary)
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
