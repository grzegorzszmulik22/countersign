// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// csbench drives the M1.6 measurements MM1.1–MM1.3 against the Go
// implementation. It only reads public entry points (VerifyBundle,
// Ledger.Append) and reports one JSON object per run on stdout.
//
//	csbench verify  <bundle.tar> <keys.json> <runs>
//	csbench append  <dir> <records.jsonl> <n> <workers> <runs>
//	csbench latency <dir> <records.jsonl> <rate/s> <n> <workers>
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/ledger"
)

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "csbench: "+format+"\n", args...)
	os.Exit(2)
}

func emit(v map[string]any) {
	b, err := json.Marshal(v)
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Println(string(b))
}

func loadLines(path string) [][]byte {
	data, err := os.ReadFile(path)
	if err != nil {
		fatalf("%v", err)
	}
	var lines [][]byte
	for _, l := range bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n")) {
		if len(l) > 0 {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		fatalf("no record lines in %s", path)
	}
	return lines
}

// MM1.1 — Go verification throughput, signatures included, one core.
func benchVerify(bundlePath, keysPath string, runs int) {
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		fatalf("%v", err)
	}
	m, err := keys.LoadManifest(keysPath)
	if err != nil {
		fatalf("%v", err)
	}
	runtime.GOMAXPROCS(1)
	for r := 0; r < runs; r++ {
		t0 := time.Now()
		res := ledger.VerifyBundle(bundle, m)
		el := time.Since(t0).Seconds()
		n, _ := res.Stats["records"].(int)
		emit(map[string]any{
			"metric": "MM1.1", "run": r, "records": n,
			"records_per_s": float64(n) / el,
		})
	}
}

// MM1.2 — durable append throughput, single writer (one ledger), group
// commit: workers goroutines call Append; each call returns durable.
func benchAppend(dir, linesPath string, n, workers, runs int) {
	lines := loadLines(linesPath)
	for r := 0; r < runs; r++ {
		l, err := ledger.Open(dir, "countersign.dev/log/bench",
			keys.NewSigner(bytes.Repeat([]byte{7}, 32)))
		if err != nil {
			fatalf("%v", err)
		}
		var next atomic.Int64
		var wg sync.WaitGroup
		t0 := time.Now()
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					i := next.Add(1) - 1
					if i >= int64(n) {
						return
					}
					if _, err := l.Append(lines[i%int64(len(lines))]); err != nil {
						fatalf("append: %v", err)
					}
				}
			}()
		}
		wg.Wait()
		el := time.Since(t0).Seconds()
		if err := l.Close(); err != nil {
			fatalf("close: %v", err)
		}
		emit(map[string]any{
			"metric": "MM1.2", "run": r, "records": n,
			"workers": workers,
			"records_per_s": float64(n) / el,
		})
	}
}

// MM1.3 — append latency at a fixed rate: a token pacer admits `rate`
// appends per second; each completed append records its own latency.
func benchLatency(dir, linesPath string, rate, n, workers int) {
	lines := loadLines(linesPath)
	l, err := ledger.Open(dir, "countersign.dev/log/bench",
		keys.NewSigner(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		fatalf("%v", err)
	}
	tokens := make(chan time.Time, rate)
	go func() {
		tick := time.NewTicker(time.Second / time.Duration(rate))
		defer tick.Stop()
		for t := range tick.C {
			select {
			case tokens <- t:
			default:
			}
		}
	}()
	lat := make([]float64, n)
	var issued, done atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := issued.Add(1) - 1
				if i >= int64(n) {
					return
				}
				<-tokens
				t0 := time.Now()
				if _, err := l.Append(lines[i%int64(len(lines))]); err != nil {
					fatalf("append: %v", err)
				}
				lat[i] = float64(time.Since(t0).Microseconds()) / 1000.0
				done.Add(1)
			}
		}()
	}
	wg.Wait()
	if err := l.Close(); err != nil {
		fatalf("close: %v", err)
	}
	sort.Float64s(lat)
	pick := func(q float64) float64 {
		return lat[int(q*float64(len(lat)-1))]
	}
	emit(map[string]any{
		"metric": "MM1.3", "rate": rate, "records": n,
		"p50_ms": pick(0.50), "p99_ms": pick(0.99), "max_ms": lat[len(lat)-1],
	})
}

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: csbench verify|append|latency ...")
	}
	atoi := func(s string) int {
		v, err := strconv.Atoi(s)
		if err != nil {
			fatalf("%v", err)
		}
		return v
	}
	switch os.Args[1] {
	case "verify":
		if len(os.Args) != 5 {
			fatalf("usage: csbench verify <bundle> <keys.json> <runs>")
		}
		benchVerify(os.Args[2], os.Args[3], atoi(os.Args[4]))
	case "append":
		if len(os.Args) != 7 {
			fatalf("usage: csbench append <dir> <records.jsonl> <n> <workers> <runs>")
		}
		benchAppend(os.Args[2], os.Args[3],
			atoi(os.Args[4]), atoi(os.Args[5]), atoi(os.Args[6]))
	case "latency":
		if len(os.Args) != 7 {
			fatalf("usage: csbench latency <dir> <records.jsonl> <rate> <n> <workers>")
		}
		benchLatency(os.Args[2], os.Args[3],
			atoi(os.Args[4]), atoi(os.Args[5]), atoi(os.Args[6]))
	default:
		fatalf("unknown mode %q", os.Args[1])
	}
}
