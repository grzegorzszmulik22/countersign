// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package runner

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// Enforced mode is Linux-only: elsewhere the probe always reports
// unavailable so `cs run` refuses with the --cooperative message.
func probe(ctx context.Context) probeResult {
	return probeResult{When: nowTS(), Detail: "enforced mode requires Linux namespaces"}
}

func writeProbeResult(string, probeResult) {}

func ProbeMain() int { return 1 }

func InitMain([]string) int { return 1 }

type probeResult struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	When   string `json:"when"`
}

func (s *session) spawnEnforced(context.Context) (*sandboxCmd, error) {
	return nil, fmt.Errorf("enforced mode requires Linux")
}

type sandboxCmd struct {
	cmd      *exec.Cmd
	code     int
	envErr   chan error
	onSignal func()
	onKill   func()
	grace    time.Duration
}

func (c *sandboxCmd) wait() {
	err := c.cmd.Wait()
	if err == nil {
		c.code = 0
	} else if ee, ok := err.(*exec.ExitError); ok {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			c.code = 128 + int(ws.Signal())
		} else {
			c.code = ee.ExitCode()
		}
	} else {
		c.code = 1
	}
}

func (c *sandboxCmd) envWriteErr() error {
	if c.envErr == nil {
		return nil
	}
	return <-c.envErr
}

func (c *sandboxCmd) exitCode() int { return c.code }

func (c *sandboxCmd) interrupt(done <-chan struct{}) {
	if c.onSignal != nil {
		c.onSignal()
	}
	grace := c.grace
	if grace == 0 {
		grace = 2 * time.Second
	}
	select {
	case <-done:
		return
	case <-time.After(grace):
	}
	if c.onKill != nil {
		c.onKill()
	}
	<-done
}
