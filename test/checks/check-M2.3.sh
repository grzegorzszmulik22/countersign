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
    # The 2 ms p99 bound is measured end-to-end through three goroutine
    # hops in one process; on a host shared with other lanes/suites the
    # scheduler's tail can exceed it without the broker holding anything
    # back. A sabotage (no-flush, buffer-whole) fails deterministically on
    # coalescing and read count, so one retry cannot launder it.
    gotest "$1" '^TestC232SSEFlush$' -timeout 120s || \
        gotest "$1" '^TestC232SSEFlush$' -timeout 120s
}
job_C2.3.3() { gotest "$1" '^TestC233WriteAheadDigest$' -timeout 120s; }
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

for id in C2.3.1 C2.3.2 C2.3.3 C2.3.4 C2.3.5 lint.proxy; do
    if [ "$(cat "$WORK/$id.rc" 2>/dev/null)" = "0" ]; then
        pass "$id"
    else
        bad "$id" "$(tail -6 "$WORK/$id.out" 2>/dev/null | tr '\n' ' ')"
    fi
done

[ "$fail" -eq 0 ] && echo "M2.3 suite: all checks passed" || echo "M2.3 suite: FAILURES" >&2
exit "$fail"
