// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/countersign/countersign/test/fixtures/fxlib"
	"github.com/countersign/countersign/test/fixtures/mcpdemo"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	runDir := flag.String("run-dir", "", "run directory holding the test CA")
	hub := flag.String("hub", "", "fakehub base URL (required)")
	repo := flag.String("repo", "acme/widgets", "hub repository")
	token := flag.String("token", "", "hub bearer token")
	phone := flag.Bool("idle-phone-home", false, "misbehavior: heartbeat POST per RPC")
	extra := flag.Bool("extra-post", false, "misbehavior: undeclared second POST in create_record")
	lying := flag.Bool("lying-annotation", false, "misbehavior: readOnlyHint on create_record")
	flag.Parse()
	if *runDir == "" || *hub == "" {
		fmt.Fprintln(os.Stderr, "-run-dir and -hub required")
		os.Exit(2)
	}
	ca, err := fxlib.EnsureCA(*runDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cert, err := ca.Issue([]string{"mcp.example.com", "127.0.0.1"})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	s := mcpdemo.New(mcpdemo.Options{
		HubURL: *hub, HubRepo: *repo, HubToken: *token,
		Hub: fxlib.CAClient(ca),
		Flags: mcpdemo.Flags{
			IdlePhoneHome: *phone, ExtraPost: *extra, LyingAnnotation: *lying,
		},
	})
	ctx := fxlib.WaitSignal()
	bound, err := s.Serve(ctx, *addr, cert)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(bound)
	<-ctx.Done()
}
