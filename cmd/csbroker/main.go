// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// csbroker is the Countersign broker. Local mode (--local) loads a session
// table, listens for forward-proxy clients and serves them under each
// session's policy.
package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/proxy"
)

func main() {
	listen := flag.String("listen", ":3128", "proxy listen address (tests bind 127.0.0.1:0)")
	local := flag.Bool("local", false, "local mode: session table from a file (required until cluster mode)")
	sessionsFile := flag.String("sessions", "", "session table YAML (local mode)")
	recordsDir := flag.String("records-dir", "", "directory for broker records and broker.log (required)")
	ledgerDir := flag.String("ledger-dir", "", "evidence ledger directory (M2.4; signs records with --broker-key)")
	brokerKey := flag.String("broker-key", "", "ed25519 key file for ledger record signing (created if absent; required with --ledger-dir)")
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

	var signer keys.Signer
	if *ledgerDir != "" {
		if *brokerKey == "" {
			fmt.Fprintln(os.Stderr, "csbroker: --ledger-dir requires --broker-key")
			os.Exit(2)
		}
		s, err := keys.LoadSigner(*brokerKey)
		signer = s
		if os.IsNotExist(err) {
			var seed [32]byte
			if _, err := rand.Read(seed[:]); err != nil {
				fmt.Fprintln(os.Stderr, "csbroker: key seed:", err)
				os.Exit(1)
			}
			signer = keys.NewSigner(seed[:])
			if err := keys.SaveSigner(signer, *brokerKey); err != nil {
				fmt.Fprintln(os.Stderr, "csbroker: save broker key:", err)
				os.Exit(1)
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "csbroker: --broker-key:", err)
			os.Exit(1)
		}
	}

	srv, err := proxy.NewServer(proxy.Config{
		SessionsFile: *sessionsFile,
		RecordsDir:   *recordsDir,
		LedgerDir:    *ledgerDir,
		BrokerSigner: signer,
		LogSigner:    signer,
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
