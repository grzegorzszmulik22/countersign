// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"

	"github.com/countersign/countersign/test/fixtures/fxlib"
	"github.com/countersign/countersign/test/fixtures/mockllm"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	runDir := flag.String("run-dir", "", "run directory holding the test CA")
	transcript := flag.String("transcript", "", "scenario transcript JSON (required)")
	variant := flag.String("variant", "", "planted-change variant kind[@turn]")
	conditional := flag.Bool("conditional", false, "honour conditional responses gated on context markers")
	flakyP := flag.Float64("flaky", 0, "probability the variant applies to a request (0 = deterministic)")
	seed := flag.Int64("seed", 1, "RNG seed for --flaky")
	flag.Parse()
	if *runDir == "" || *transcript == "" {
		fmt.Fprintln(os.Stderr, "-run-dir and -transcript required")
		os.Exit(2)
	}
	t, err := mockllm.LoadTranscript(*transcript)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var opts mockllm.Options
	opts.Conditional = *conditional
	if *variant != "" {
		opts.Variant, err = mockllm.ParseVariant(*variant)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	if *flakyP > 0 {
		opts.Flaky = &mockllm.Flaky{P: *flakyP, Rand: rand.New(rand.NewSource(*seed))}
	}
	ca, err := fxlib.EnsureCA(*runDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cert, err := ca.Issue([]string{"api.anthropic.com", "api.openai.com", "127.0.0.1"})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx := fxlib.WaitSignal()
	bound, err := mockllm.New(t, opts).Serve(ctx, *addr, cert)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(bound)
	<-ctx.Done()
}
