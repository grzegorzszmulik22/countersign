// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package echo

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Minimal RFC 6455 server for the echo fixture's WebSocket endpoint. Text and
// binary messages are echoed verbatim; ping is answered with pong; close ends
// the exchange. No fragmentation support beyond passing continuation frames
// through with their original opcode (echoing each frame as received).

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

func wsHandshake(w http.ResponseWriter, r *http.Request) (net2conn, *bufio.ReadWriter, error) {
	if !headerHasToken(r.Header, "Connection", "upgrade") ||
		!headerHasToken(r.Header, "Upgrade", "websocket") ||
		r.Header.Get("Sec-WebSocket-Key") == "" {
		return nil, nil, errors.New("not a websocket upgrade")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijack unsupported")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, nil, err
	}
	_, _ = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n\r\n", wsAccept(r.Header.Get("Sec-WebSocket-Key")))
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, rw, nil
}

type net2conn interface {
	io.ReadWriteCloser
}

func headerHasToken(h http.Header, name, want string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), want) {
				return true
			}
		}
	}
	return false
}

// wsServe echoes frames until close or error. Frames are copied verbatim with
// the mask bit cleared (servers never mask).
func wsServe(conn io.ReadWriteCloser, rw *bufio.ReadWriter) {
	defer func() { _ = conn.Close() }()
	for {
		op, payload, err := wsReadFrame(rw)
		if err != nil {
			return
		}
		switch op {
		case 0x8: // close
			_ = wsWriteFrame(rw, 0x8, payload)
			_ = rw.Flush()
			return
		case 0x9: // ping -> pong
			if err := wsWriteFrame(rw, 0xA, payload); err != nil {
				return
			}
		default: // text (1), binary (2), continuation (0): echo
			if err := wsWriteFrame(rw, op, payload); err != nil {
				return
			}
		}
		if err := rw.Flush(); err != nil {
			return
		}
	}
}

func wsReadFrame(r *bufio.ReadWriter) (opcode byte, payload []byte, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	opcode = hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	l := uint64(hdr[1] & 0x7F)
	switch l {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		l = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		l = binary.BigEndian.Uint64(b[:])
	}
	if l > 1<<24 {
		return 0, nil, errors.New("ws frame too large")
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(r, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload = make([]byte, l)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, nil
}

func wsWriteFrame(w *bufio.ReadWriter, opcode byte, payload []byte) error {
	hdr := []byte{0x80 | opcode}
	switch {
	case len(payload) < 126:
		hdr = append(hdr, byte(len(payload)))
	case len(payload) <= 0xFFFF:
		hdr = append(hdr, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		hdr = append(hdr, 127)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(len(payload)))
		hdr = append(hdr, b[:]...)
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
