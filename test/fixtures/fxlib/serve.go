// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package fxlib

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

// ServeTLS runs h on ln over TLS with cert until ctx is done. h already
// includes the admin endpoints (mount them via MountAdmin).
func ServeTLS(ctx context.Context, ln net.Listener, cert tls.Certificate, h http.Handler) error {
	srv := &http.Server{
		Handler: h,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		},
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	tln := tls.NewListener(ln, srv.TLSConfig)
	err := srv.Serve(tln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// MountAdmin returns a handler that serves the fixture's routes plus the
// __observed/__state/__reset endpoints (which take precedence). Other /__*
// paths (fixture test APIs like /__admin/*) fall through to h.
func MountAdmin(obs *Obs, state func() any, reset func(), h http.Handler) http.Handler {
	admin := AdminHandler(obs, state, reset)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/__observed", "/__state", "/__reset":
			admin.ServeHTTP(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// WaitSignal returns a context cancelled on SIGINT/SIGTERM.
func WaitSignal() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx
}

// Listen announces a TCP listener, failing loudly with the address on error.
func Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	return ln, nil
}

// CAClient returns an http.Client trusting ca's root — for fixture-to-fixture
// calls (e.g. mcpdemo reaching fakehub).
func CAClient(ca *CA) *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: ca.Pool()},
	}}
}
