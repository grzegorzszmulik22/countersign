#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M2.4 (write-ahead evidence, fail-closed, sealing).
# Emits one "CHECK <id> PASS|FAIL" line per numbered check; exits non-zero
# if any check fails.
set -u
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
ROOT=$PWD
export PATH="$ROOT/.tools/bin:$PATH"
GO="$ROOT/.tools/bin/go"
fail=0

# Full spec volume for the durability proofs: C2.4.1's 100k-request
# ordering proof, C2.4.2's 200 SIGKILLs, C2.4.5's 100k-request count
# equality. The tests read this env var; an un-env'd `go test -race`
# (e.g. a whole-package race pass under Go's default 10m timeout) runs
# a smaller volume that still exercises every concurrent path. Since
# check-M2.4, sabotage-M2.4 and regress all reach the tests through
# this script, the spec counts always apply there.
export CS_M24_SPEC_VOLUME=1

mkdir -p "$ROOT/.check-work"
WORK=$(mktemp -d "$ROOT/.check-work/M2.4.XXXXXX")
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

# C2.4.1's 100k-request ordering proof and C2.4.5's count-equality both
# drive the full volume; C2.4.2 SIGKILLs a real broker process 200 times.
# They run serially — the ordering/count claims are about durable-write
# timing, and parallel load would only add scheduler noise.
job_C2.4.1() { gotest "$1" '^TestC241OrderingProof$' -timeout 600s; }
job_C2.4.2() { gotest "$1" '^TestC242CrashProof$' -timeout 900s; }
job_C2.4.3() { gotest "$1" '^TestC243FailClosed$' -timeout 300s; }
job_C2.4.4() { gotest "$1" '^TestC244DeniedCounted$' -timeout 300s; }
job_C2.4.5() { gotest "$1" '^TestC245CountEquality$' -timeout 600s; }
job_C2.4.6() { gotest "$1" '^TestC246SealExportVerify$' -timeout 300s; }

job_lint.proxy() {
    command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not on PATH"; return 1; }
    mkdir -p "$ROOT/.check-work/tmp"
    if GOLANGCI_LINT_CACHE="$ROOT/.check-work/golangci-lint-cache-M2.4" TMPDIR="$ROOT/.check-work/tmp" \
        golangci-lint run --build-tags fixtures ./internal/proxy ./cmd/csbroker >"$WORK/lint.proxy.detail.log" 2>&1; then
        return 0
    fi
    tail -8 "$WORK/lint.proxy.detail.log"
    return 1
}

for id in C2.4.1 C2.4.2 C2.4.3 C2.4.4 C2.4.5 C2.4.6 lint.proxy; do
    ( "job_$id" "$id" >"$WORK/$id.out" 2>&1; echo $? >"$WORK/$id.rc" )
done

for id in C2.4.1 C2.4.2 C2.4.3 C2.4.4 C2.4.5 C2.4.6 lint.proxy; do
    if [ "$(cat "$WORK/$id.rc" 2>/dev/null)" = "0" ]; then
        pass "$id"
    else
        bad "$id" "$(tail -6 "$WORK/$id.out" 2>/dev/null | tr '\n' ' ')"
    fi
done

[ "$fail" -eq 0 ] && echo "M2.4 suite: all checks passed"
[ "$fail" -ne 0 ] && { echo "M2.4 suite: FAILURES" >&2; exit 1; }
exit 0
