#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M2.3 (streaming bodies, digests, aborts).
# Emits one "CHECK <id> PASS|FAIL" line per numbered check; exits non-zero
# if any check fails.
set -u
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
ROOT=$PWD
export PATH="$ROOT/.tools/bin:$PATH"
GO="$ROOT/.tools/bin/go"
fail=0

mkdir -p "$ROOT/.check-work"
WORK=$(mktemp -d "$ROOT/.check-work/M2.3.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad() { say "$1" FAIL "$2"; fail=1; }

# Hosts where C2.3.2 reports SKIP: see the note above the report loop.
timing_skip_host() { # <check-id>: is this host listed for a SKIP of it?
    awk -v id="$1" -v h="$(hostname -s)" '$1 == id { n = split($2, a, ","); for (i = 1; i <= n; i++) if (a[i] == h) f = 1 } END { exit !f }' tools/env-skips.txt 2>/dev/null
}

gotest() { # <id> <go-test -run pattern> [extra args...]
    local id=$1 pat=$2; shift 2
    if ! [ -x "$GO" ]; then
        echo "go toolchain missing: run make tools"
        return 1
    fi
    if "$GO" test -tags fixtures -count=1 -run "$pat" "$@" ./internal/proxy >"$WORK/$id.full.log" 2>&1; then
        return 0
    fi
    tail -8 "$WORK/$id.full.log"
    return 1
}

job_C2.3.1() { gotest "$1" '^TestC231ByteEquality$' -timeout 300s; }
job_C2.3.2() {
    timing_skip_host C2.3.2 && return 0
    # The 2 ms p99 bound is measured end-to-end through three goroutine
    # hops in one process; on a host shared with other lanes/suites the
    # scheduler's tail can exceed it without the broker holding anything
    # back. A sabotage (no-flush, buffer-whole) fails deterministically on
    # coalescing and read count, so one retry cannot launder it.
    gotest "$1" '^TestC232SSEFlush$' -timeout 120s || \
        gotest "$1" '^TestC232SSEFlush$' -timeout 120s
}
job_C2.3.3() { gotest "$1" '^TestC233(WriteAheadDigest|CloseWaitsForInFlightRecords)$' -timeout 120s; }
job_C2.3.4() { gotest "$1" '^TestC234ClientAbort$' -timeout 120s; }
job_C2.3.5() { gotest "$1" '^TestC235MemoryBound$' -timeout 300s; }

job_lint.proxy() {
    command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not on PATH"; return 1; }
    mkdir -p "$ROOT/.check-work/tmp"
    if GOLANGCI_LINT_CACHE="$ROOT/.check-work/golangci-lint-cache-M2.3" TMPDIR="$ROOT/.check-work/tmp" \
        golangci-lint run --build-tags fixtures ./internal/proxy ./cmd/csbroker >"$WORK/lint.proxy.detail.log" 2>&1; then
        return 0
    fi
    tail -8 "$WORK/lint.proxy.detail.log"
    return 1
}

# Timing-sensitive: C2.3.2 measures per-event added delay against a 2 ms
# p99 bound and C2.3.1/C2.3.5 push a GiB through the pipe, so jobs run
# serially — parallel lint/build load was enough to skew the measurement.
for id in C2.3.1 C2.3.2 C2.3.3 C2.3.4 C2.3.5 lint.proxy; do
    ( "job_$id" "$id" >"$WORK/$id.out" 2>&1; echo $? >"$WORK/$id.rc" )
done

# C2.3.2's 2 ms p99 bound is measured only on hosts quiet enough to mean
# anything. tools/env-skips.txt lists the hosts where it reports SKIP instead
# (supervisor decision 2026-11-17: on the 2-core oci-free-a1 it read 35-70 ms
# while other lanes and a kind cluster ran; it passes on agent-vpc). The skip
# is never a pass: regress accepts it only on the listed hosts.
skipped=0
for id in C2.3.1 C2.3.2 C2.3.3 C2.3.4 C2.3.5 lint.proxy; do
    if [ "$id" = C2.3.2 ] && timing_skip_host C2.3.2; then
        say "$id" SKIP "timing bound not measured on $(hostname -s) (tools/env-skips.txt); measured on agent-vpc"
        skipped=1
    elif [ "$(cat "$WORK/$id.rc" 2>/dev/null)" = "0" ]; then
        pass "$id"
    else
        bad "$id" "$(tail -6 "$WORK/$id.out" 2>/dev/null | tr '\n' ' ')"
    fi
done

[ "$fail" -eq 0 ] && [ "$skipped" -eq 0 ] && echo "M2.3 suite: all checks passed"
[ "$fail" -ne 0 ] && echo "M2.3 suite: FAILURES" >&2
[ "$fail" -eq 0 ] && [ "$skipped" -ne 0 ] && echo "M2.3 suite: passed except listed SKIPs" >&2
[ "$fail" -ne 0 ] && exit 1
[ "$skipped" -ne 0 ] && exit 2
exit 0
