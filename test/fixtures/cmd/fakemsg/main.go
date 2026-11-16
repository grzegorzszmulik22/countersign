// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/countersign/countersign/test/fixtures/fakemsg"
	"github.com/countersign/countersign/test/fixtures/fxlib"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	runDir := flag.String("run-dir", "", "run directory holding the test CA")
	flag.Parse()
	if *runDir == "" {
		fmt.Fprintln(os.Stderr, "-run-dir required")
		os.Exit(2)
	}
	ca, err := fxlib.EnsureCA(*runDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cert, err := ca.Issue([]string{"api.slack.com", "127.0.0.1"})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx := fxlib.WaitSignal()
	bound, err := fakemsg.New().Serve(ctx, *addr, cert)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(bound)
	<-ctx.Done()
}
