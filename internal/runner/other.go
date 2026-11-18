// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package runner

import (
	"context"
	"fmt"
	"os/exec"
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
	onSignal func()
}

func (c *sandboxCmd) wait() {
	err := c.cmd.Wait()
	if err == nil {
		c.code = 0
	} else if ee, ok := err.(*exec.ExitError); ok {
		c.code = ee.ExitCode()
	} else {
		c.code = 1
	}
}
func (c *sandboxCmd) exitCode() int { return c.code }
func (c *sandboxCmd) interrupt(<-chan struct{}) {
	if c.onSignal != nil {
		c.onSignal()
	}
}
