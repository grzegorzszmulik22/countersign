// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// nsFlags are the namespaces enforced mode creates. PID is included so a
// killed init takes the whole agent tree with it: nothing inside the
// boundary can outlive the session.
const nsFlags = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET | syscall.CLONE_NEWPID

// spawnInNS re-execs this binary inside fresh user/mount/net/pid
// namespaces with uid 0→euid mapped. This is the only way in; there is
// no setuid helper, no added capability, no container runtime.
func spawnInNS(argv []string, env []string, extraFiles []*os.File) *exec.Cmd {
	cmd := exec.Command("/proc/self/exe", argv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: nsFlags,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Geteuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getegid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
	}
	cmd.Env = env
	cmd.ExtraFiles = extraFiles
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

// probeResult records whether unprivileged namespaces work here.
type probeResult struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	When   string `json:"when"`
}

// probe attempts the real enforced path — new user+mount+net+pid
// namespaces, lo up, an empty tmpfs mount, a loopback bind — by running
// this binary's __probe entry point inside the namespaces. Its output
// is recorded under the data dir (writeProbeResult).
func probe(ctx context.Context) probeResult {
	res := probeResult{When: nowTS()}
	if v := os.Getenv("CS_RUN_PROBE_OVERRIDE"); v == "unavailable" {
		res.Detail = "probe forced unavailable by CS_RUN_PROBE_OVERRIDE"
		return res
	}
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.Command("/proc/self/exe", "__probe")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: nsFlags,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Geteuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getegid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		res.Detail = "namespace spawn: " + err.Error()
		return res
	}
	err := cmd.Wait()
	if pctx.Err() != nil {
		res.Detail = "probe timed out"
		return res
	}
	if err != nil {
		res.Detail = fmt.Sprintf("%v: %s", err, bytes.TrimSpace(out.Bytes()))
		return res
	}
	res.OK = true
	res.Detail = "user+mount+net+pid namespaces, loopback and tmpfs all work"
	return res
}

func writeProbeResult(dataDir string, pr probeResult) error {
	data, err := json.MarshalIndent(pr, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal probe result: %w", err)
	}
	return os.WriteFile(filepath.Join(dataDir, "probe.json"), append(data, '\n'), 0o600)
}

// ProbeMain is `cs __probe`: it runs inside the probed namespaces and
// exercises the exact steps enforced mode needs. Its output is the
// probe's evidence.
func ProbeMain() int {
	if err := loUp(); err != nil {
		fmt.Fprintln(os.Stderr, "loopback up:", err)
		return 1
	}
	dir, err := os.MkdirTemp("", "cs-probe-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mktemp:", err)
		return 1
	}
	defer func() {
		// The probe tmpfs mount dies with the namespace anyway;
		// RemoveAll only releases the temp dir entry itself.
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintln(os.Stderr, "probe cleanup:", err)
		}
	}()
	if err := mountTmpfs(dir); err != nil {
		fmt.Fprintln(os.Stderr, "tmpfs mount:", err)
		return 1
	}
	ln, err := listenLoopback()
	if err != nil {
		fmt.Fprintln(os.Stderr, "loopback listen:", err)
		return 1
	}
	if err := ln.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "probe listener close:", err)
		return 1
	}
	fmt.Println("probe ok")
	return 0
}

// sandboxCmd wraps the spawned sandbox process (the in-namespace init
// for enforced mode, the command itself in cooperative mode) with the
// interrupt sequencing both paths share.
type sandboxCmd struct {
	cmd      *exec.Cmd
	code     int
	waitErr  error
	envErr   chan error // enforced: result of streaming ambient env to init
	onSignal func()     // graceful interrupt: forward or group SIGINT
	onKill   func()     // escalation: kill the pid or its whole group
	grace    time.Duration
}

func (c *sandboxCmd) wait() {
	err := c.cmd.Wait()
	c.waitErr = err
	c.code = exitCodeOf(err)
}

// envWriteErr reports whether the ambient env stream into init
// completed. A truncated stream would silently corrupt the boundary
// env, so a write failure fails the run.
func (c *sandboxCmd) envWriteErr() error {
	if c.envErr == nil {
		return nil
	}
	return <-c.envErr
}

func (c *sandboxCmd) exitCode() int { return c.code }

// interrupt runs the SIGINT sequence: graceful signal first, then kill
// after the grace window. done is closed when the process exits.
func (c *sandboxCmd) interrupt(done <-chan struct{}) {
	if c.onSignal != nil {
		c.onSignal()
	} else if err := c.cmd.Process.Signal(syscall.SIGINT); err != nil {
		// Already dead is the only failure worth tolerating — the
		// escalation below still runs in case a descendant lingers.
		fmt.Fprintf(os.Stderr, "cs: interrupt signal: %v\n", err)
	}
	grace := c.grace
	if grace == 0 {
		grace = 2 * time.Second
	}
	select {
	case <-done:
	case <-time.After(grace):
	}
	// Escalate unconditionally: the leader can die on the first
	// signal while a descendant that ignored it lives on in the
	// group. In enforced mode killing init collapses the pid
	// namespace; in cooperative mode the hook kills the group.
	if c.onKill != nil {
		c.onKill()
	} else if err := c.cmd.Process.Kill(); err != nil &&
		!errors.Is(err, os.ErrProcessDone) {
		fmt.Fprintf(os.Stderr, "cs: interrupt kill: %v\n", err)
	}
	<-done
}

// exitCodeOf maps Wait's result to the status the command actually
// returned: its exit code, or 128+signal when a signal killed it —
// the same convention shells report in $?.
func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	return 1
}
