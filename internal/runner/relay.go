// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// unixRelay is the parent half of the enforced boundary's only network
// path. It accepts connections on a Unix socket inside the sandbox-visible
// run directory and splices each one to the broker's loopback listener.
// Every accepted connection goes to the broker and nowhere else — the
// relay reads nothing from the client before dialing and the dial target
// is fixed at construction.
type unixRelay struct {
	ln     *net.UnixListener
	broker string
	wg     sync.WaitGroup
	conns  sync.Map // net.Conn → struct{} for close-time cleanup
}

func newUnixRelay(sockPath, brokerAddr string) (*unixRelay, error) {
	laddr := &net.UnixAddr{Name: sockPath, Net: "unix"}
	ln, err := net.ListenUnix("unix", laddr)
	if err != nil {
		return nil, fmt.Errorf("relay listen: %w", err)
	}
	ln.SetUnlinkOnClose(true)
	r := &unixRelay{ln: ln, broker: brokerAddr}
	r.wg.Add(1)
	go r.acceptLoop()
	return r, nil
}

func (r *unixRelay) acceptLoop() {
	defer r.wg.Done()
	for {
		c, err := r.ln.AcceptUnix()
		if err != nil {
			return
		}
		go r.serve(c)
	}
}

func (r *unixRelay) serve(c *net.UnixConn) {
	up, err := net.DialTimeout("tcp", r.broker, 10*time.Second)
	if err != nil {
		_ = c.Close()
		return
	}
	r.conns.Store(c, struct{}{})
	r.conns.Store(up, struct{}{})
	defer func() {
		r.conns.Delete(c)
		r.conns.Delete(up)
	}()
	splice(c, up)
}

// splice copies both directions and propagates half-close.
func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		_, _ = io.Copy(b, a)
		if tc, ok := b.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		wg.Done()
	}()
	go func() {
		_, _ = io.Copy(a, b)
		if uc, ok := a.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
		if tc, ok := a.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		wg.Done()
	}()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

// close stops accepting and closes in-flight connections.
func (r *unixRelay) close() {
	_ = r.ln.Close()
	r.conns.Range(func(k, _ any) bool {
		_ = k.(net.Conn).Close()
		return true
	})
	r.wg.Wait()
}
