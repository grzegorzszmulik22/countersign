// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/countersign/countersign/test/fixtures/fxlib"
	"github.com/countersign/countersign/test/fixtures/sink"
)

func main() {
	runDir := flag.String("run-dir", "", "run directory holding the test CA")
	https := flag.String("https", "127.0.0.1:0", "HTTPS listen address")
	plain := flag.String("http", "127.0.0.1:0", "HTTP listen address")
	tcp := flag.String("tcp", "127.0.0.1:0", "raw TCP listen address")
	udp := flag.String("udp", "127.0.0.1:0", "UDP listen address")
	dnsu := flag.String("dns-udp", "127.0.0.1:0", "DNS UDP listen address")
	dnst := flag.String("dns-tcp", "127.0.0.1:0", "DNS TCP listen address")
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
	cert, err := ca.Issue([]string{"evil.example.com", "sink.attacker.test", "127.0.0.1"})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	s := sink.New()
	ctx := fxlib.WaitSignal()
	if err := s.Start(ctx, cert, map[string]string{
		sink.LHTTPS: *https, sink.LHTTP: *plain, sink.LTCP: *tcp,
		sink.LUDP: *udp, sink.LDNSU: *dnsu, sink.LDNST: *dnst,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, e := range s.Errors() {
		fmt.Fprintln(os.Stderr, "listener error:", e)
	}
	for _, l := range []string{sink.LHTTPS, sink.LHTTP, sink.LTCP, sink.LUDP, sink.LDNSU, sink.LDNST} {
		fmt.Printf("%s=%s\n", l, s.Addr(l))
	}
	<-ctx.Done()
}
