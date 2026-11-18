// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0
//
// csbench drives the M1.6 measurements MM1.1–MM1.3 against the Go
// implementation, as restated by CR-002 (spec/milestones/M1-evidence-core.md).
// It only reads public entry points (VerifyBundle, Ledger.Append) and reports
// one JSON object per run on stdout.
//
// Rates are reported per CPU-second of the measured process (user+sys via
// getrusage) beside the wall rate, so an oversubscribed host does not depress
// the number being judged. The 1-minute load average is sampled once per
// second and recorded with every run; MM1.3 is judged only on runs whose
// samples all stayed at or below the core count.
//
// The group-commit count is reported two ways: in-process it is estimated
// from append-return timestamp cohorts (appends covered by one commit are
// released together, so returns cluster at commit instants); the exact
// count is obtained by the harness, which runs this mode under
// "strace --seccomp-bpf -f -y -e trace=fsync,fdatasync" and counts fsync
// calls on log/entries.jsonl — one per group commit (03 §5: an fsync at
// most every 2 ms, covering entries, hashes and session indices).
//
//	csbench verify   <bundle.tar> <keys.json> <runs>
//	csbench append   <dir> <records.jsonl> <n> <workers> <runs>
//	csbench latency  <dir> <records.jsonl> <rate/s> <n> <workers>
//	csbench calibrate
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/ledger"
	"github.com/countersign/countersign/internal/names"
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

// cpuNow returns this process's user+sys CPU time in seconds (RUSAGE_SELF
// aggregates every thread on Linux).
func cpuNow() float64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		fatalf("rusage: %v", err)
	}
	u := float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6
	s := float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6
	return u + s
}

// load1 reads the 1-minute load average.
func load1() float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return -1
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return -1
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return -1
	}
	return v
}

// startLoadSampler samples the 1-minute load average immediately and then
// once per second until stop is closed. done closes when the goroutine
// exits, after which samples is final.
func startLoadSampler() (stop, done chan struct{}, samples *[]float64) {
	stop = make(chan struct{})
	done = make(chan struct{})
	samples = &[]float64{}
	go func() {
		defer close(done)
		*samples = append(*samples, load1())
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				*samples = append(*samples, load1())
			}
		}
	}()
	return stop, done, samples
}

func loadMax(samples []float64) float64 {
	m := -1.0
	for _, v := range samples {
		if v > m {
			m = v
		}
	}
	return m
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

// calibrateEd25519 measures raw ed25519.Verify operations per CPU-second on
// this core (GOMAXPROCS is 1 when invoked from benchVerify). The message is
// record-sized so the hash share is representative. CR-002: the calibration
// runs in the same process/run as the bundle verification it scales.
func calibrateEd25519() (rate float64, ops int, cpuS float64) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	msg := bytes.Repeat([]byte{9}, 1400)
	sig := ed25519.Sign(priv, msg)
	pub := priv.Public().(ed25519.PublicKey)
	c0 := cpuNow()
	for cpuNow()-c0 < 0.75 {
		for i := 0; i < 128; i++ {
			if !ed25519.Verify(pub, msg, sig) {
				fatalf("calibration signature rejected")
			}
		}
		ops += 128
	}
	cpuS = cpuNow() - c0
	return float64(ops) / cpuS, ops, cpuS
}

// countCommits clusters append-return timestamps into covering group
// commits. Appends covered by one commit are released together; commits are
// spaced by the >= 2 ms fsync cap plus the sync itself, so a 1.5 ms gap in
// the return stream marks a new cohort. Each cohort is one fsync event.
func countCommits(ts []float64) (commits int, medianGapMs float64) {
	if len(ts) == 0 {
		return 0, 0
	}
	sort.Float64s(ts)
	commits = 1
	var gaps []float64
	for i := 1; i < len(ts); i++ {
		if g := ts[i] - ts[i-1]; g > 0.0015 {
			commits++
			gaps = append(gaps, g)
		}
	}
	if len(gaps) > 0 {
		sort.Float64s(gaps)
		medianGapMs = gaps[len(gaps)/2] * 1000
	}
	return commits, medianGapMs
}

// MM1.1 — Go verification throughput, signatures included, records per
// CPU-second of one core (GOMAXPROCS=1), reported beside the wall rate and
// the raw Ed25519 calibration rate from the same run.
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
	cal, calOps, calCPU := calibrateEd25519()
	emit(map[string]any{
		"metric": "calibration", "kind": "ed25519-verify",
		"ops": calOps, "cpu_s": calCPU,
		"ed25519_verify_per_cpu_s": cal,
	})
	for r := 0; r < runs; r++ {
		stop, done, samples := startLoadSampler()
		t0 := time.Now()
		c0 := cpuNow()
		res := ledger.VerifyBundle(bundle, m)
		cpuS := cpuNow() - c0
		el := time.Since(t0).Seconds()
		close(stop)
		<-done
		n, _ := res.Stats["records"].(int)
		emit(map[string]any{
			"metric": "MM1.1", "run": r, "records": n,
			"cpu_s": cpuS, "wall_s": el,
			"records_per_cpu_s": float64(n) / cpuS,
			"records_per_s":     float64(n) / el,
			"load1_samples":     *samples, "load1_max": loadMax(*samples),
		})
	}
}

// MM1.2 — durable append throughput, single writer, group commit: records
// per CPU-second of the writer process, wall rate beside it, and the group
// commits (fsync events) counted from append-return cohorts.
func benchAppend(dir, linesPath string, n, workers, runs int) {
	lines := loadLines(linesPath)
	for r := 0; r < runs; r++ {
		l, err := ledger.Open(dir, names.APIGroup+"/log/bench",
			keys.NewSigner(bytes.Repeat([]byte{7}, 32)))
		if err != nil {
			fatalf("%v", err)
		}
		var next atomic.Int64
		var wg sync.WaitGroup
		stop, done, samples := startLoadSampler()
		t0 := time.Now()
		c0 := cpuNow()
		ret := make([]float64, n)
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
					ret[i] = time.Since(t0).Seconds()
				}
			}()
		}
		wg.Wait()
		cpuS := cpuNow() - c0
		el := time.Since(t0).Seconds()
		close(stop)
		<-done
		if err := l.Close(); err != nil {
			fatalf("close: %v", err)
		}
		commits, medGap := countCommits(ret)
		emit(map[string]any{
			"metric": "MM1.2", "run": r, "records": n,
			"workers": workers,
			"cpu_s":   cpuS, "wall_s": el,
			"records_per_cpu_s": float64(n) / cpuS,
			"records_per_s":     float64(n) / el,
			"cluster_commits":   commits, "cluster_per_record": float64(commits) / float64(n),
			"median_commit_gap_ms": medGap,
			"load1_samples":        *samples, "load1_max": loadMax(*samples),
		})
	}
}

// MM1.3 — append latency at a fixed paced rate: a token pacer admits `rate`
// appends per second; each completed append records its own latency. The
// 1-minute load average is sampled every second for the whole run.
func benchLatency(dir, linesPath string, rate, n, workers int) {
	lines := loadLines(linesPath)
	l, err := ledger.Open(dir, names.APIGroup+"/log/bench",
		keys.NewSigner(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		fatalf("%v", err)
	}
	stop, done, samples := startLoadSampler()
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
	var issued, finished atomic.Int64
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
				finished.Add(1)
			}
		}()
	}
	wg.Wait()
	close(stop)
	<-done
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
		"load1_samples": *samples, "load1_max": loadMax(*samples),
	})
}

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: csbench verify|append|latency|calibrate ...")
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
	case "calibrate":
		if len(os.Args) != 2 {
			fatalf("usage: csbench calibrate")
		}
		runtime.GOMAXPROCS(1)
		cal, ops, cpuS := calibrateEd25519()
		emit(map[string]any{"metric": "calibration", "kind": "ed25519-verify",
			"ops": ops, "cpu_s": cpuS, "ed25519_verify_per_cpu_s": cal})
	default:
		fatalf("unknown mode %q", os.Args[1])
	}
}
