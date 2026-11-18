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
	logf   func(string, ...any)
	wg     sync.WaitGroup
	conns  sync.Map // net.Conn → struct{} for close-time cleanup
}

func newUnixRelay(sockPath, brokerAddr string, logf func(string, ...any)) (*unixRelay, error) {
	laddr := &net.UnixAddr{Name: sockPath, Net: "unix"}
	ln, err := net.ListenUnix("unix", laddr)
	if err != nil {
		return nil, fmt.Errorf("relay listen: %w", err)
	}
	ln.SetUnlinkOnClose(true)
	r := &unixRelay{ln: ln, broker: brokerAddr, logf: logf}
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
		r.logf("relay dial %s: %v", r.broker, err)
		// Nothing else can be done with this conn — close errors
		// here add no information.
		_ = c.Close()
		return
	}
	r.conns.Store(c, struct{}{})
	r.conns.Store(up, struct{}{})
	defer func() {
		r.conns.Delete(c)
		r.conns.Delete(up)
	}()
	if err := splice(c, up); err != nil {
		r.logf("relay splice %s ↔ %s: %v", c.RemoteAddr(), up.RemoteAddr(), err)
	}
}

// splice copies both directions and propagates half-close. Copy errors
// are reported to the caller: a truncated stream through the boundary
// is a boundary event, not silence.
func splice(a, b net.Conn) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var first error
	report := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		if first == nil {
			first = err
		}
		mu.Unlock()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(b, a)
		report(err)
		if tc, ok := b.(*net.TCPConn); ok {
			// Half-close is best effort: a peer that died mid-copy
			// makes it fail, and both conns are closed below.
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(a, b)
		report(err)
		if uc, ok := a.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
		if tc, ok := a.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
	// Both copies are done; close failures now cannot lose data.
	_ = a.Close()
	_ = b.Close()
	return first
}

// close stops accepting and closes in-flight connections.
func (r *unixRelay) close() {
	// Shutdown path: the listener and conns are torn down regardless
	// of close errors, which only ever mean "already closed".
	_ = r.ln.Close()
	r.conns.Range(func(k, _ any) bool {
		_ = k.(net.Conn).Close()
		return true
	})
	r.wg.Wait()
}
