// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Package runner implements the M2.7 local runner: `cs run -- <command>`.
// One process plays the roles the spec assigns to csledger (file store),
// csbroker --local (loopback forward proxy) and the session controller:
// keys and an append-only ledger live under a data directory, the broker
// serves the session over its public API, and every record the broker
// writes is bridged into the signed evidence chain. In the default
// enforced mode the command runs inside user+mount+network+pid namespaces
// where the data directory is hidden under an empty tmpfs and the only
// reachable peer is a loopback relay that splices to the broker through a
// Unix socket handed in by the parent. --cooperative sets the same
// environment without namespaces and records boundary: cooperative.
package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Options configures one `cs run` invocation.
type Options struct {
	// PolicyFile is the session policy; empty selects the built-in
	// allow-all test policy.
	PolicyFile string
	// Cooperative runs without namespaces and records
	// boundary: cooperative.
	Cooperative bool
	// DataDir is the hidden runner data directory (ledger, keys,
	// sessions, bundles). Empty uses the default under XDG_DATA_HOME.
	DataDir string
	// RunDir is the sandbox-visible scratch directory holding the
	// session CA PEM and the relay socket. Empty uses os.MkdirTemp.
	RunDir string
	// Command is the agent command line (required).
	Command []string
	// Env is the environment the command inherits before proxy and
	// trust variables are overlaid. Nil uses os.Environ().
	Env []string
	// Logf receives runner diagnostics; nil discards them.
	Logf func(format string, args ...any)
}

// Result reports how a run ended.
type Result struct {
	SessionID  string
	Boundary   string // "enforced" | "cooperative"
	DataDir    string
	RunDir     string
	BundlePath string
	ExitCode   int
	Interrupt  bool // ctx cancelled the run (e.g. SIGINT)
}

const boundaryEnforced = "enforced"
const boundaryCooperative = "cooperative"

// Run executes one session end to end: probe, setup, spawn, wait, seal,
// bundle. The returned ExitCode is the command's status (or 130 when the
// run was interrupted before the command finished).
func Run(ctx context.Context, opt Options) (*Result, error) {
	if len(opt.Command) == 0 {
		return nil, fmt.Errorf("cs run: a command after -- is required")
	}
	logf := opt.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ambient := opt.Env
	if ambient == nil {
		ambient = os.Environ()
	}

	dataDir := opt.DataDir
	if dataDir == "" {
		var err error
		dataDir, err = defaultDataDir()
		if err != nil {
			return nil, err
		}
	}
	dataDir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return nil, err
	}

	// Probe before any heavy setup: enforced mode fails closed when
	// unprivileged namespaces are unavailable.
	boundary := boundaryCooperative
	if !opt.Cooperative {
		pr := probe(ctx)
		writeProbeResult(dataDir, pr)
		if !pr.OK {
			return nil, fmt.Errorf("unprivileged user namespaces unavailable on this host (%s); re-run with --cooperative to run without the enforced boundary", pr.Detail)
		}
		boundary = boundaryEnforced
	}

	s, err := newSession(ctx, opt, dataDir, ambient, boundary)
	if err != nil {
		return nil, err
	}
	defer s.cleanup(logf)

	code, interrupted, err := s.spawnAndWait(ctx)
	if err != nil {
		return nil, err
	}

	bundlePath, err := s.sealAndBundle(code, interrupted)
	if err != nil {
		return nil, err
	}
	return &Result{
		SessionID:  s.id,
		Boundary:   boundary,
		DataDir:    dataDir,
		RunDir:     s.runDir,
		BundlePath: bundlePath,
		ExitCode:   code,
		Interrupt:  interrupted,
	}, nil
}

func defaultDataDir() (string, error) {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("data dir: %w", err)
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "countersign"), nil
}

func nowTS() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.999999999Z")
}
