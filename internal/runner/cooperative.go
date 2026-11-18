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
// boundary: cooperative records.
func (s *session) spawnCooperative(_ context.Context, ambient []string) (*sandboxCmd, error) {
	env := sandboxEnv(ambient, proxyURL(s.brokerAddr, s.token), s.caPath, s.placeholders)
	// proxy.env's relay= line names where boundary traffic flows; in
	// cooperative mode that is the broker itself.
	writeProxyEnv(s.runDir, env, s.brokerAddr)

	cmd := exec.Command(s.command[0], s.command[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Its own process group: SIGINT reaches the command and the whole
	// tree it builds.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawn %q: %w", s.command[0], err)
	}
	return &sandboxCmd{
		cmd: cmd,
		onSignal: func() {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
		},
	}, nil
}
