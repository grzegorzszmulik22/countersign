// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"errors"
	"net"
	"testing"
	"time"
)

// errConn fails every read and write: a peer that dies mid-splice.
type errConn struct{ net.Conn }

var errForced = errors.New("forced I/O failure")

func (e errConn) Read([]byte) (int, error)  { return 0, errForced }
func (e errConn) Write([]byte) (int, error) { return 0, errForced }
func (e errConn) SetDeadline(time.Time) error {
	return nil
}

// TestSplicePropagatesErrors: a copy that fails mid-stream must surface
// as a splice error — the boundary relay reporting a truncated stream
// is the behavior P5 pins, not a comment.
func TestSplicePropagatesErrors(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer func() {
		// Teardown only; Close on an already-dead pipe is a no-op.
		_ = a1.Close()
		_ = a2.Close()
		_ = b1.Close()
		_ = b2.Close()
	}()
	if err := splice(errConn{a1}, errConn{b1}); err == nil {
		t.Fatal("splice returned nil error when both copy directions failed")
	}
}
