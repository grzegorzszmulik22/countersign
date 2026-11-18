// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// spawnCooperative runs the command on the host with the boundary
// environment but no namespaces. The proxy vars point straight at the
// broker's loopback listener; nothing prevents a client that ignores
// them from reaching the network — that is exactly what
// boundary: cooperative records. Host credential files stay reachable:
// cooperative mode is a reporting boundary, not a filesystem one.
func (s *session) spawnCooperative(_ context.Context, ambient []string) (*sandboxCmd, error) {
	env := sandboxEnv(ambient, proxyURL(s.brokerAddr, s.token), s.caPath, s.placeholders)
	// proxy.env's relay= line names where boundary traffic flows; in
	// cooperative mode that is the broker itself.
	if err := writeProxyEnv(s.runDir, env, s.brokerAddr); err != nil {
		return nil, fmt.Errorf("proxy.env: %w", err)
	}

	cmd := exec.Command(s.command[0], s.command[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Its own process group: SIGINT reaches the command and the whole
	// tree it builds, and the SIGKILL escalation reaps the group, not
	// just the leader. A descendant that setsid's away is a documented
	// cooperative limitation — only a pid namespace catches those.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawn %q: %w", s.command[0], err)
	}
	group := func(sig syscall.Signal) {
		if err := syscall.Kill(-cmd.Process.Pid, sig); err != nil && err != syscall.ESRCH {
			fmt.Fprintf(os.Stderr, "cs: group signal %v: %v\n", sig, err)
		}
	}
	return &sandboxCmd{
		cmd:      cmd,
		onSignal: func() { group(syscall.SIGINT) },
		onKill:   func() { group(syscall.SIGKILL) },
	}, nil
}
