// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Command livebroker runs the Countersign broker in local mode for a live,
// non-gated real-agent run (07 §13, "Not gated, for behaviour"). It is
// tooling, not product: M2.7's `cs run` replaces it.
//
// It differs from `csbroker -local` in two ways only:
//   - it writes the session CA certificate (public part, never the key) to
//     -out/ca.pem and the proxy URL with the session token to -out/proxy.url,
//     so an unmodified agent can be pointed at the broker;
//   - names listed in -resolve dial the given loopback address (the local
//     fixtures stand in for the internet); every other name dials the real
//     network, and only reaches it when the session policy grants it.
package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/countersign/countersign/internal/proxy"
)

func main() {
	policy := flag.String("policy", "", "SessionPolicy YAML for the one live session (required)")
	records := flag.String("records", "", "records directory (required)")
	out := flag.String("out", "", "directory for ca.pem and proxy.url (required)")
	listen := flag.String("listen", "127.0.0.1:0", "proxy listen address")
	resolve := flag.String("resolve", "", "name=addr,... fixture names and their loopback addresses")
	fixtureCA := flag.String("fixture-ca", "", "PEM of the fixtures' test root, trusted for upstream TLS")
	flag.Parse()
	if *policy == "" || *records == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*policy, *records, *out, *listen, *resolve, *fixtureCA); err != nil {
		fmt.Fprintln(os.Stderr, "livebroker:", err)
		os.Exit(1)
	}
}

func run(policy, records, out, listen, resolve, fixtureCA string) error {
	pol, err := filepath.Abs(policy)
	if err != nil {
		return err
	}
	for _, d := range []string{records, out} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	tok := make([]byte, 16)
	if _, err := rand.Read(tok); err != nil {
		return err
	}
	token := hex.EncodeToString(tok)
	sessFile := filepath.Join(out, "sessions.yaml")
	table := fmt.Sprintf("sessions:\n  - id: live\n    token: %s\n    client_ip: 127.0.0.1\n    policy: %s\n", token, filepath.ToSlash(pol))
	if err := os.WriteFile(sessFile, []byte(table), 0o600); err != nil {
		return err
	}

	routes := map[string]string{}
	for _, kv := range strings.Split(resolve, ",") {
		if name, addr, ok := strings.Cut(strings.TrimSpace(kv), "="); ok {
			routes[strings.ToLower(name)] = addr
		}
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if fixtureCA != "" {
		b, err := os.ReadFile(fixtureCA)
		if err != nil {
			return err
		}
		if !roots.AppendCertsFromPEM(b) {
			return fmt.Errorf("no certificate in %s", fixtureCA)
		}
	}
	var d net.Dialer
	srv, err := proxy.NewServer(proxy.Config{
		SessionsFile: sessFile,
		RecordsDir:   records,
		RootCAs:      roots,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host := addr
			if h, _, err := net.SplitHostPort(addr); err == nil {
				host = h
			}
			if real, ok := routes[strings.ToLower(host)]; ok {
				return d.DialContext(ctx, network, real)
			}
			return d.DialContext(ctx, network, addr)
		},
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	addr, err := srv.Serve(ctx, listen)
	if err != nil {
		return err
	}
	sess := srv.Session("live")
	if sess == nil || sess.CACert() == nil {
		return fmt.Errorf("session live has no CA")
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sess.CACert().Raw})
	if err := os.WriteFile(filepath.Join(out, "ca.pem"), caPEM, 0o644); err != nil {
		return err
	}
	purl := fmt.Sprintf("http://cs:%s@%s", token, addr.String())
	if err := os.WriteFile(filepath.Join(out, "proxy.url"), []byte(purl+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Println("livebroker: listening", addr.String(), "ready", time.Now().UTC().Format(time.RFC3339))
	<-ctx.Done()
	return srv.Close()
}
