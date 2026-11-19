// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// m27helper is the M2.7 in-sandbox probe binary. It runs inside the
// boundary (or on the host as a sink) and reports what it could do —
// the check decides what was allowed. Modes:
//
//	leak   attempt every non-proxy escape path and report each result
//	sink   host-side TCP/UDP/unix listeners logging every arrival
//	scan   hunt canary strings across env, /proc and readable files
//	env    dump the environment as seen inside the sandbox
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	mode := flagStr("mode", "")
	switch mode {
	case "leak":
		os.Exit(leak())
	case "sink":
		os.Exit(sink())
	case "scan":
		os.Exit(scan())
	case "env":
		for _, kv := range os.Environ() {
			fmt.Println(kv)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: m27helper -mode leak|sink|scan|env [flags]")
		os.Exit(2)
	}
}

func flagStr(name, def string) string {
	pre := "-" + name + "="
	for i, a := range os.Args[1:] {
		if strings.HasPrefix(a, pre) {
			return a[len(pre):]
		}
		if a == "-"+name && i+2 < len(os.Args) {
			return os.Args[i+2]
		}
	}
	return def
}

// ---- leak ------------------------------------------------------------

// leak tries each escape path once and prints one line per attempt:
// "<probe> <result> <detail>". "reach" means traffic flowed.
func leak() int {
	probes := 0
	fail := func(format string, a ...any) { fmt.Printf(format+"\n", a...) }

	for _, t := range csv(flagStr("tcp", "")) {
		probes++
		c, err := net.DialTimeout("tcp", t, 3*time.Second)
		if err != nil {
			fail("tcp %s fail %v", t, err)
		} else {
			fail("tcp %s reach connected", t)
			_ = c.Close()
		}
	}
	for _, t := range csv(flagStr("tcp6", "")) {
		probes++
		c, err := net.DialTimeout("tcp6", t, 3*time.Second)
		if err != nil {
			fail("tcp6 %s fail %v", t, err)
		} else {
			fail("tcp6 %s reach connected", t)
			_ = c.Close()
		}
	}
	for _, t := range csv(flagStr("udp", "")) {
		probes++
		c, err := net.DialTimeout("udp", t, 3*time.Second)
		if err != nil {
			fail("udp %s fail %v", t, err)
			continue
		}
		_, werr := c.Write([]byte("M27LEAK " + t))
		_ = c.Close()
		if werr != nil {
			fail("udp %s fail %v", t, werr)
		} else {
			fail("udp %s sent", t)
		}
	}
	relay := flagStr("relay", "")
	if relay == "" {
		// Discover the relay the runner advertised via proxy.env.
		for _, d := range csv(flagStr("rundir", "")) {
			data, err := os.ReadFile(filepath.Join(d, "proxy.env"))
			if err != nil {
				continue
			}
			for _, l := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(l, "relay=") {
					relay = strings.TrimPrefix(l, "relay=")
				}
			}
		}
	}
	if t := relay; t != "" {
		probes++
		c, err := net.DialTimeout("tcp", t, 3*time.Second)
		if err != nil {
			fail("relay %s fail %v", t, err)
		} else {
			// A wrong relay would read a destination header; the honest
			// one pipes these bytes straight to the broker, which closes
			// on the malformed request line.
			_, _ = fmt.Fprintf(c, "TARGET=%s\r\nGET /m27mark HTTP/1.1\r\nHost: x\r\n\r\n",
				flagStr("spoof-target", ""))
			_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
			buf := make([]byte, 256)
			n, _ := c.Read(buf)
			fail("relay %s reply %q", t, string(buf[:n]))
			_ = c.Close()
		}
	}
	for _, p := range csv(flagStr("unix", "")) {
		probes++
		c, err := net.DialTimeout("unix", p, 3*time.Second)
		if err != nil {
			fail("unix %s fail %v", p, err)
		} else {
			fail("unix %s reach connected", p)
			_ = c.Close()
		}
	}
	probes++
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var r net.Resolver
	if _, err := r.LookupHost(ctx, "echo.example.com"); err != nil {
		fmt.Printf("dns fail %v\n", err)
	} else {
		fmt.Println("dns resolved")
	}
	if probes == 0 {
		fmt.Println("no probes configured")
		return 2
	}
	return 0
}

// ---- sink ------------------------------------------------------------

// sink binds the requested listeners, prints "<name>=<addr>" for each,
// and appends one line per arrival to -out until killed.
func sink() int {
	out := flagStr("out", "")
	mark := func(format string, a ...any) {
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err == nil {
			_, _ = fmt.Fprintf(f, format+"\n", a...)
			_ = f.Close()
		}
	}
	wait := make(chan struct{})
	for _, t := range csv(flagStr("tcp", "")) {
		ln, err := net.Listen("tcp", t)
		if err != nil {
			fmt.Fprintln(os.Stderr, "tcp listen:", err)
			return 1
		}
		fmt.Printf("tcp=%s\n", ln.Addr())
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				mark("tcp-arrival %s", c.RemoteAddr())
				_ = c.Close()
			}
		}(ln)
	}
	for _, t := range csv(flagStr("tcp6", "")) {
		ln, err := net.Listen("tcp6", t)
		if err != nil {
			fmt.Fprintln(os.Stderr, "tcp6 listen:", err)
			return 1
		}
		fmt.Printf("tcp6=%s\n", ln.Addr())
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				mark("tcp6-arrival %s", c.RemoteAddr())
				_ = c.Close()
			}
		}(ln)
	}
	for _, t := range csv(flagStr("udp", "")) {
		pc, err := net.ListenPacket("udp", t)
		if err != nil {
			fmt.Fprintln(os.Stderr, "udp listen:", err)
			return 1
		}
		fmt.Printf("udp=%s\n", pc.LocalAddr())
		go func(p net.PacketConn) {
			buf := make([]byte, 1024)
			for {
				n, a, err := p.ReadFrom(buf)
				if err != nil {
					return
				}
				mark("udp-arrival %s %q", a, string(buf[:n]))
			}
		}(pc)
	}
	for _, p := range csv(flagStr("unix", "")) {
		_ = os.Remove(p)
		ln, err := net.Listen("unix", p)
		if err != nil {
			fmt.Fprintln(os.Stderr, "unix listen:", err)
			return 1
		}
		fmt.Printf("unix=%s\n", ln.Addr())
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				mark("unix-arrival %s", c.RemoteAddr())
				_ = c.Close()
			}
		}(ln)
	}
	<-wait
	return 0
}

// ---- scan ------------------------------------------------------------

// scan hunts each -find string (or every line of -findfile) in the
// environment, in /proc/*/environ and /proc/*/cmdline, and in every
// readable file under each -dir. Each hit prints "HIT <where>"; a clean
// run prints "clean". Exit 0 iff clean and every -empty dir is
// empty-or-absent.
func scan() int {
	needles := csv(flagStr("find", ""))
	if ff := flagStr("findfile", ""); ff != "" {
		if data, err := os.ReadFile(ff); err == nil {
			for _, l := range strings.Split(string(data), "\n") {
				if l != "" {
					needles = append(needles, l)
				}
			}
		} else {
			fmt.Println("findfile unreadable:", err)
			return 2
		}
	}
	dirty := 0
	contains := func(data []byte) bool {
		for _, n := range needles {
			if n != "" && strings.Contains(string(data), n) {
				return true
			}
		}
		return false
	}
	// Environment.
	for _, kv := range os.Environ() {
		if contains([]byte(kv)) {
			fmt.Println("HIT env " + kv)
			dirty++
		}
	}
	// /proc of every visible process: environ and cmdline.
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		if !e.IsDir() || !allDigits(e.Name()) {
			continue
		}
		for _, f := range []string{"environ", "cmdline"} {
			p := "/proc/" + e.Name() + "/" + f
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			if contains(data) {
				fmt.Printf("HIT %s\n", p)
				dirty++
			}
		}
	}
	// Files under each -dir (bounded).
	for _, dir := range csv(flagStr("dir", "")) {
		seen := 0
		_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi == nil || !fi.Mode().IsRegular() || fi.Size() > 1<<20 || seen > 5000 {
				return nil
			}
			seen++
			data, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			if contains(data) {
				fmt.Println("HIT " + p)
				dirty++
			}
			return nil
		})
	}
	// -empty dirs must be empty or absent (the tmpfs cover test).
	for _, dir := range csv(flagStr("empty", "")) {
		ents, err := os.ReadDir(dir)
		if err != nil {
			fmt.Printf("empty %s absent-ok\n", dir)
			continue
		}
		if len(ents) == 0 {
			fmt.Printf("empty %s ok\n", dir)
		} else {
			fmt.Printf("HIT %s has %d entries (data dir visible)\n", dir, len(ents))
			dirty++
		}
	}
	if dirty == 0 {
		fmt.Println("clean")
		return 0
	}
	fmt.Printf("%d hits\n", dirty)
	return 1
}

func csv(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func allDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
