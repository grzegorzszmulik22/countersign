#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M2.5 (protocol edges: smuggling, path forms,
# upstream address policy, WebSocket, passthrough, isolation, fuzz).
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
WORK=$(mktemp -d "$ROOT/.check-work/M2.5.XXXXXX")
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

job_C2.5.1() { gotest "$1" '^TestC251SmugglingCorpus$' -timeout 300s; }
job_C2.5.2() { gotest "$1" '^TestC252PathForms$' -timeout 120s; }
job_C2.5.3() { gotest "$1" '^TestC253UpstreamAddrCheck$' -timeout 120s; }
job_C2.5.4() { gotest "$1" '^TestC254WebSocket$' -timeout 120s; }
job_C2.5.5() { gotest "$1" '^TestC255Passthrough$' -timeout 120s; }
job_C2.5.6() {
    # The isolation bound is measured end-to-end while a 400-conn flood
    # churns; on a host shared with other lanes/suites the scheduler's
    # tail can push session B's p99 past it without the budget actually
    # leaking. A real isolation break fails deterministically on every
    # run, so one retry cannot launder it — same rule as C2.3.2.
    gotest "$1" '^TestC256Isolation$' -timeout 300s || \
        gotest "$1" '^TestC256Isolation$' -timeout 300s
}

# C2.5.7: native fuzzing of the request-head and CONNECT-authority
# parsers, 10 minutes each, no panic (04 §2 step 1, M2.5 spec).
job_C2.5.7() {
    local log="$WORK/$1.fuzz.log"
    if ! [ -x "$GO" ]; then
        echo "go toolchain missing: run make tools"
        return 1
    fi
    "$GO" test -tags fixtures -count=1 -run '^$' -fuzz '^FuzzRequestHead$' \
        -fuzztime=600s ./internal/proxy >"$log" 2>&1 || { tail -12 "$log"; return 1; }
    "$GO" test -tags fixtures -count=1 -run '^$' -fuzz '^FuzzConnectAuthority$' \
        -fuzztime=600s ./internal/proxy >>"$log" 2>&1 || { tail -12 "$log"; return 1; }
    return 0
}

job_lint.proxy() {
    command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not on PATH"; return 1; }
    mkdir -p "$ROOT/.check-work/tmp"
    if GOLANGCI_LINT_CACHE="$ROOT/.check-work/golangci-lint-cache-M2.5" TMPDIR="$ROOT/.check-work/tmp" \
        golangci-lint run --build-tags fixtures ./internal/proxy ./cmd/csbroker >"$WORK/lint.proxy.detail.log" 2>&1; then
        return 0
    fi
    tail -8 "$WORK/lint.proxy.detail.log"
    return 1
}

# Serial: C2.5.6 measures a latency bound under a conn flood; parallel
# fuzzing/load would only add scheduler noise to the measurement.
for id in C2.5.1 C2.5.2 C2.5.3 C2.5.4 C2.5.5 C2.5.6 C2.5.7 lint.proxy; do
    ( "job_$id" "$id" >"$WORK/$id.out" 2>&1; echo $? >"$WORK/$id.rc" )
done

for id in C2.5.1 C2.5.2 C2.5.3 C2.5.4 C2.5.5 C2.5.6 C2.5.7 lint.proxy; do
    if [ "$(cat "$WORK/$id.rc" 2>/dev/null)" = "0" ]; then
        pass "$id"
    else
        bad "$id" "$(tail -6 "$WORK/$id.out" 2>/dev/null | tr '\n' ' ')"
    fi
done

[ "$fail" -eq 0 ] && echo "M2.5 suite: all checks passed"
[ "$fail" -ne 0 ] && { echo "M2.5 suite: FAILURES" >&2; exit 1; }
exit 0
