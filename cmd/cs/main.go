// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// cs is the Countersign CLI. `cs run -- <command>` runs one agent under
// the local boundary (M2.7): a csledger file store, a csbroker --local
// on loopback, and the command inside user+mount+net+pid namespaces
// whose only egress is the broker. __init and __probe are internal
// entry points the runner re-execs inside the namespaces.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/countersign/countersign/internal/runner"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "__init":
			os.Exit(runner.InitMain(os.Args[2:]))
		case "__probe":
			os.Exit(runner.ProbeMain())
		}
	}
	fs := flag.NewFlagSet("cs", flag.ExitOnError)
	policy := fs.String("policy", "", "session policy file (default: built-in allow-all test policy)")
	cooperative := fs.Bool("cooperative", false, "run without namespaces and record boundary: cooperative")
	dataDir := fs.String("data-dir", "", "runner data directory (default: $XDG_DATA_HOME/countersign)")
	runDir := fs.String("run-dir", "", "sandbox-visible run directory (default: mktemp)")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(fs.Output(), "usage: cs run [--policy FILE] [--cooperative] -- COMMAND [ARGS...]")
		fs.PrintDefaults()
	}
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "run" {
		args = args[1:]
	} else if len(args) > 0 {
		fs.Usage()
		os.Exit(2)
	} else {
		fs.Usage()
		os.Exit(2)
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	cmd := fs.Args()
	if len(cmd) > 0 && cmd[0] == "--" {
		cmd = cmd[1:]
	}
	if len(cmd) == 0 {
		_, _ = fmt.Fprintln(fs.Output(), "cs run: a command after -- is required")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	res, err := runner.Run(ctx, runner.Options{
		PolicyFile:  *policy,
		Cooperative: *cooperative,
		DataDir:     *dataDir,
		RunDir:      *runDir,
		Command:     cmd,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "cs run:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "cs: session %s\ncs: boundary %s\ncs: bundle %s\ncs: run-dir %s\n",
		res.SessionID, res.Boundary, res.BundlePath, res.RunDir)
	os.Exit(res.ExitCode)
}
