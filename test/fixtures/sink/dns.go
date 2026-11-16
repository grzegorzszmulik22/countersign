// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package sink

import (
	"encoding/binary"
	"errors"
)

// Minimal DNS responder: answers every query name with A 10.66.66.66. The
// request bytes (exactly as received) are what the fixture records; the
// response proves the listener resolves names end to end.

var dnsAnswerIP = [4]byte{10, 66, 66, 66}

// dnsResponse builds a response to a single-question DNS query message.
func dnsResponse(query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, errors.New("short dns header")
	}
	// Header: ID(2) FLAGS(2) QD(2) AN(2) NS(2) AR(2)
	qd := binary.BigEndian.Uint16(query[4:6])
	if qd < 1 {
		return nil, errors.New("no question")
	}
	// Find end of the first question (labels + qtype + qclass).
	i := 12
	for {
		if i >= len(query) {
			return nil, errors.New("truncated name")
		}
		l := int(query[i])
		i++
		if l == 0 {
			break
		}
		if l&0xC0 == 0xC0 { // compression pointer: two bytes, terminates
			i++
			break
		}
		i += l
	}
	if i+4 > len(query) {
		return nil, errors.New("truncated question")
	}
	questionEnd := i + 4 // includes QTYPE+QCLASS

	resp := make([]byte, 0, questionEnd+16)
	resp = append(resp, query[:2]...) // same ID
	// Flags: QR=1, OPCODE copied, AA=0, TC=0, RD copied, RA=1, RCODE=0.
	resp = append(resp, 0x80|(query[2]&0x78)|(query[2]&0x01), 0x80)
	resp = append(resp, query[4:6]...)            // QDCOUNT
	resp = append(resp, 0x00, 0x01)               // ANCOUNT = 1
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)   // NS, AR
	resp = append(resp, query[12:questionEnd]...) // question section verbatim
	resp = append(resp, 0xC0, 0x0C)               // name = pointer to offset 12
	resp = append(resp, 0x00, 0x01)               // TYPE A
	resp = append(resp, 0x00, 0x01)               // CLASS IN
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C)   // TTL 60
	resp = append(resp, 0x00, 0x04)               // RDLENGTH
	resp = append(resp, dnsAnswerIP[:]...)        // RDATA
	return resp, nil
}

// dnsQueryName extracts the first query name for the observation record.
func dnsQueryName(query []byte) (string, error) {
	if len(query) < 13 {
		return "", errors.New("short dns")
	}
	name := ""
	i := 12
	for {
		l := int(query[i])
		i++
		if l == 0 {
			break
		}
		if l&0xC0 == 0xC0 || i+l > len(query) {
			return name, errors.New("pointer or overrun in name")
		}
		if name != "" {
			name += "."
		}
		name += string(query[i : i+l])
		i += l
	}
	return name, nil
}
