// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runner

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// InitMain is the `cs __init` entry point: it runs as pid 1 inside the
// fresh namespaces. It brings loopback up, covers the data directory
// with an empty tmpfs, starts the in-namespace relay toward the parent's
// Unix socket, then execs the agent with the boundary environment. Any
// failure before the agent starts exits nonzero; once the agent runs,
// init exits with the agent's status.
func InitMain(args []string) int {
	var relaySock, dataDir, caPath, runDir, token, ph, envFD string
	var argv []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			argv = args[i+1:]
			break
		}
		val := ""
		if j := strings.IndexByte(a, '='); j >= 0 {
			a, val = a[:j], a[j+1:]
		} else if i+1 < len(args) {
			i++
			val = args[i]
		}
		switch a {
		case "--relay-sock":
			relaySock = val
		case "--datadir":
			dataDir = val
		case "--ca":
			caPath = val
		case "--run-dir":
			runDir = val
		case "--token":
			token = val
		case "--ph":
			ph = val
		case "--env-fd":
			envFD = val
		default:
			fmt.Fprintln(os.Stderr, "cs-init: unknown flag", a)
			return 2
		}
	}
	fail := func(err error) int {
		fmt.Fprintln(os.Stderr, "cs-init:", err)
		return 1
	}
	if len(argv) == 0 || relaySock == "" || dataDir == "" || caPath == "" {
		return fail(fmt.Errorf("missing required arguments"))
	}

	// The agent's ambient environment arrives over an inherited pipe —
	// never through init's own environ, which /proc/1/environ would
	// publish to every sandbox process.
	ambient := os.Environ()
	if envFD != "" {
		n, err := strconv.Atoi(envFD)
		if err != nil {
			return fail(fmt.Errorf("--env-fd: %w", err))
		}
		f := os.NewFile(uintptr(n), "envpipe")
		data, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			return fail(fmt.Errorf("read env pipe: %w", err))
		}
		ambient = nil
		for _, kv := range strings.Split(strings.TrimRight(string(data), "\x00"), "\x00") {
			if kv != "" {
				ambient = append(ambient, kv)
			}
		}
	}

	// 1. Only loopback inside this netns.
	if err := loUp(); err != nil {
		return fail(fmt.Errorf("loopback up: %w", err))
	}

	// 2. Hide the whole runner data directory under an empty tmpfs, then
	// mount a fresh /proc scoped to this pid namespace — the inherited
	// /proc would otherwise show every host process (its env, cmdline
	// and same-uid memory) to the sandbox.
	if err := mountTmpfs(dataDir); err != nil {
		return fail(fmt.Errorf("cover data dir: %w", err))
	}
	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		return fail(fmt.Errorf("proc mount: %w", err))
	}

	// 3. Relay: the only reachable peer is the parent's Unix socket,
	// which splices to the broker.
	ln, err := listenLoopback()
	if err != nil {
		return fail(fmt.Errorf("relay listen: %w", err))
	}
	relayPort := ln.Addr().(*net.TCPAddr).Port
	go relayToSock(ln, relaySock)

	// 4. Agent environment: ambient overlaid with the boundary vars.
	placeholders := map[string]string{}
	for _, kv := range strings.Split(ph, ";") {
		if kv == "" {
			continue
		}
		name, val, ok := strings.Cut(kv, "=")
		if !ok {
			return fail(fmt.Errorf("bad placeholder %q", kv))
		}
		placeholders[name] = val
	}
	env := sandboxEnv(ambient, proxyURL(fmt.Sprintf("127.0.0.1:%d", relayPort), token), caPath, placeholders)
	if runDir != "" {
		writeProxyEnv(runDir, env, fmt.Sprintf("127.0.0.1:%d", relayPort))
	}

	// 5. Spawn the agent in its own process group so signal forwarding
	// hits the whole tree the agent makes. init is pid 1 of the
	// namespace: a single Wait4 loop reaps every descendant while
	// keeping the agent's own status.
	argv0, err := exec.LookPath(argv[0])
	if err != nil {
		return fail(fmt.Errorf("spawn %q: %w", argv[0], err))
	}
	argv[0] = argv0
	proc, err := os.StartProcess(argv0, argv, &os.ProcAttr{
		Env:   env,
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Sys:   &syscall.SysProcAttr{Setpgid: true},
	})
	if err != nil {
		return fail(fmt.Errorf("spawn %q: %w", argv[0], err))
	}

	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	// signal.Notify delivers through the channel without interrupting
	// the wait syscall, so the reaper runs in its own goroutine and the
	// loop selects on reaps and signals alike. Every reap belongs to
	// init: the agent, plus grandchildren reparented to pid 1.
	type reap struct {
		pid int
		ws  syscall.WaitStatus
		err error
	}
	reaped := make(chan reap, 8)
	go func() {
		for {
			var ws syscall.WaitStatus
			pid, werr := syscall.Wait4(-1, &ws, 0, nil)
			reaped <- reap{pid, ws, werr}
			if werr != nil {
				return
			}
		}
	}()
	forwarded := false
	var ws syscall.WaitStatus
	for {
		select {
		case s := <-sig:
			if !forwarded {
				forwarded = true
				_ = syscall.Kill(-proc.Pid, s.(syscall.Signal))
			} else {
				_ = syscall.Kill(-proc.Pid, syscall.SIGKILL)
			}
		case r := <-reaped:
			if r.err != nil {
				// ECHILD: the agent is already reaped (only possible
				// if it never started).
				return 1
			}
			if r.pid == proc.Pid {
				ws = r.ws
				goto agentDone
			}
		}
	}
agentDone:
	// The agent is done: kill whatever survived in its group, then exit
	// with its status. Anything that escaped the group dies with the
	// pid namespace when init exits.
	_ = syscall.Kill(-proc.Pid, syscall.SIGKILL)
	if ws.Exited() {
		return ws.ExitStatus()
	}
	if s := ws.Signal(); s != 0 {
		return 128 + int(s)
	}
	return 1
}

// spawnEnforced starts the in-namespace init and the parent relay that
// connects it to the broker.
func (s *session) spawnEnforced(_ context.Context) (*sandboxCmd, error) {
	relaySock := s.runDir + "/relay.sock"
	r, err := newUnixRelay(relaySock, s.brokerAddr)
	if err != nil {
		return nil, err
	}
	s.relay = r

	var ph []string
	for k, v := range s.placeholders {
		ph = append(ph, k+"="+v)
	}
	args := []string{
		"__init",
		"--relay-sock=" + relaySock,
		"--datadir=" + s.dataDir,
		"--ca=" + s.caPath,
		"--run-dir=" + s.runDir,
		"--token=" + s.token,
		"--ph=" + strings.Join(ph, ";"),
		"--env-fd=3",
		"--",
	}
	args = append(args, s.command...)

	// The agent's ambient env goes over an inherited pipe, not init's
	// environ: /proc/1/environ inside the sandbox would otherwise
	// publish the parent's real credential values. init itself gets a
	// minimal env — just the PATH its own LookPath needs.
	envR, envW, err := os.Pipe()
	if err != nil {
		r.close()
		return nil, fmt.Errorf("env pipe: %w", err)
	}
	initEnv := []string{"PATH=" + envValue(s.ambient, "PATH")}
	cmd := spawnInNS(args, initEnv, []*os.File{envR})
	if err := cmd.Start(); err != nil {
		r.close()
		_ = envR.Close()
		_ = envW.Close()
		return nil, fmt.Errorf("namespace spawn: %w", err)
	}
	_ = envR.Close() // child's copy is fd 3 now
	go func() {
		for _, kv := range s.ambient {
			_, _ = envW.WriteString(kv)
			_, _ = envW.WriteString("\x00")
		}
		_ = envW.Close()
	}()
	return &sandboxCmd{
		cmd: cmd,
		onSignal: func() {
			_ = cmd.Process.Signal(syscall.SIGINT)
		},
	}, nil
}

// relayToSock splices each accepted loopback connection to the parent
// Unix socket — the only path out of the namespace.
func relayToSock(ln net.Listener, sock string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			up, err := net.Dial("unix", sock)
			if err != nil {
				_ = c.Close()
				return
			}
			splice(c, up)
		}()
	}
}

// loUp brings the loopback interface up inside the netns.
func loUp() error {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(s) }()
	type ifreq struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}
	var ifr ifreq
	copy(ifr.name[:], "lo")
	ifr.flags = syscall.IFF_UP | syscall.IFF_RUNNING
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s),
		syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return errno
	}
	return nil
}

// mountTmpfs covers dir with a fresh empty tmpfs, hiding everything the
// runner stored underneath.
func mountTmpfs(dir string) error {
	return syscall.Mount("tmpfs", dir, "tmpfs",
		syscall.MS_NOSUID|syscall.MS_NODEV, "")
}

func listenLoopback() (net.Listener, error) {
	return net.Listen("tcp4", "127.0.0.1:0")
}

// envValue returns the last NAME=value in env, or "".
func envValue(env []string, name string) string {
	v := ""
	for _, kv := range env {
		if k, val, ok := strings.Cut(kv, "="); ok && k == name {
			v = val
		}
	}
	return v
}

// writeProxyEnv drops the sandbox's proxy environment into the run dir
// so out-of-band checks (e.g. env -i grandchildren) can recover it.
// relay names where boundary traffic flows.
func writeProxyEnv(runDir string, env []string, relay string) {
	var b strings.Builder
	fmt.Fprintf(&b, "relay=%s\n", relay)
	for _, kv := range env {
		for _, v := range append(proxyVars, trustVars...) {
			if strings.HasPrefix(kv, v+"=") {
				b.WriteString(kv + "\n")
			}
		}
	}
	_ = os.WriteFile(runDir+"/proxy.env", []byte(b.String()), 0o644)
}
