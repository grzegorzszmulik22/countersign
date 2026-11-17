// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// csbroker is the Countersign broker. Local mode (--local) loads a session
// table, listens for forward-proxy clients and serves them under each
// session's policy.
package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/countersign/countersign/internal/proxy"
)

func main() {
	listen := flag.String("listen", ":3128", "proxy listen address (tests bind 127.0.0.1:0)")
	local := flag.Bool("local", false, "local mode: session table from a file (required until cluster mode)")
	sessionsFile := flag.String("sessions", "", "session table YAML (local mode)")
	recordsDir := flag.String("records-dir", "", "directory for broker records and broker.log (required)")
	upstreamCA := flag.String("upstream-ca", "", "PEM file appended to upstream trust roots")
	flag.Parse()

	if !*local {
		fmt.Fprintln(os.Stderr, "csbroker: --local required (cluster mode arrives with M4)")
		os.Exit(2)
	}
	if *sessionsFile == "" || *recordsDir == "" {
		fmt.Fprintln(os.Stderr, "csbroker: --sessions and --records-dir required in local mode")
		os.Exit(2)
	}

	var roots *x509.CertPool
	if *upstreamCA != "" {
		pemBytes, err := os.ReadFile(*upstreamCA)
		if err != nil {
			fmt.Fprintln(os.Stderr, "csbroker:", err)
			os.Exit(1)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			fmt.Fprintln(os.Stderr, "csbroker: --upstream-ca: no certificates parsed")
			os.Exit(1)
		}
		roots = pool
	}

	srv, err := proxy.NewServer(proxy.Config{
		SessionsFile: *sessionsFile,
		RecordsDir:   *recordsDir,
		RootCAs:      roots,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "csbroker:", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	bound, err := srv.Serve(ctx, *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "csbroker: listen:", err)
		os.Exit(1)
	}
	fmt.Println("listening", bound.String())
	<-ctx.Done()
	_ = srv.Close()
}
