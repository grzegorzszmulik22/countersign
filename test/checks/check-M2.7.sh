#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M2.7 (local runner: enforced/cooperative `cs run`).
# Emits one "CHECK <id> PASS|FAIL" line per numbered check; exits non-zero
# if any check fails.
#
#   C2.7.1  direct egress impossible inside the enforced boundary;
#           identical probes reach the world under --cooperative
#   C2.7.2  env -i grandchild still reaches nothing but the broker
#   C2.7.3  curl/git/python/node reach echo through the broker; every
#           request has a ledger record; session verifies enforced
#   C2.7.4  canary scan finds no credential/signing-key/CA-key material
#           inside the enforced boundary; the data dir reads empty
#   C2.7.5  probe-forced enforced refusal names --cooperative;
#           cooperative runs seal boundary: cooperative, which
#           csverify prints
#   C2.7.6  SIGINT ends the command and its descendants, seals the
#           session, both verifiers accept the bundle
#   C2.7.X  exit status passes through unchanged (0,1,3,42,128+sig)
#   race.runner  whole suite under the race detector (hosts with cc)
#   lint.runner golangci-lint over the chunk's packages
set -u
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
ROOT=$PWD
export PATH="$ROOT/.tools/bin:$PATH"
GO="$ROOT/.tools/bin/go"
fail=0

mkdir -p "$ROOT/.check-work"
WORK=$(mktemp -d "$ROOT/.check-work/M2.7.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad() { say "$1" FAIL "$2"; fail=1; }

if ! [ -x "$GO" ]; then
    echo "go toolchain missing: run make tools" >&2
    exit 2
fi

# Build the binaries the suite drives: cs (runner), csverify (verifier)
# and the in-sandbox probe helper.
BIN=$WORK/bin
mkdir -p "$BIN"
if ! "$GO" build -tags fixtures -o "$BIN/cs" ./cmd/cs \
        >"$WORK/build.cs.log" 2>&1; then
    cat "$WORK/build.cs.log" >&2
    for id in C2.7.1 C2.7.2 C2.7.3 C2.7.4 C2.7.5 C2.7.6; do
        bad "$id" "cs build failed"
    done
    exit 1
fi
for tool in csverify:./cmd/csverify m27helper:./test/runner/m27helper; do
    name=${tool%%:*}; pkg=${tool##*:}
    if ! "$GO" build -tags fixtures -o "$BIN/$name" "$pkg" \
            >"$WORK/build.$name.log" 2>&1; then
        cat "$WORK/build.$name.log" >&2
        for id in C2.7.1 C2.7.2 C2.7.3 C2.7.4 C2.7.5 C2.7.6; do
            bad "$id" "$name build failed"
        done
        exit 1
    fi
done
export M27_BIN=$BIN
export M27_ROOT=$ROOT

gotest() { # <id> <go-test -run pattern>
    local id=$1 pat=$2
    if "$GO" test -tags fixtures -count=1 -run "$pat" -timeout 300s \
            ./internal/runner >"$WORK/$id.full.log" 2>&1; then
        return 0
    fi
    tail -12 "$WORK/$id.full.log"
    return 1
}

job_C2.7.1() { gotest "$1" '^TestC2_7_1$|^TestC2_7_RelayConcurrent$|^TestSplicePropagatesErrors$'; }
job_C2.7.2() { gotest "$1" '^TestC2_7_2$'; }
job_C2.7.3() { gotest "$1" '^TestC2_7_3'; }
job_C2.7.4() { gotest "$1" '^TestC2_7_4$'; }
job_C2.7.5() { gotest "$1" '^TestC2_7_5$'; }
job_C2.7.X() { gotest "$1" '^TestC2_7_ExitStatus$'; }
job_C2.7.6() { gotest "$1" '^TestC2_7_6$'; }

# The same suite under the race detector: the tests rebuild cs with
# -race themselves when M27_BIN is unset, so the subprocess is covered
# too. Requires a C compiler for cgo — skip only when none exists.
job_race.runner() {
    command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 \
        || command -v clang >/dev/null 2>&1 \
        || { echo "no C compiler; -race unsupported here"; return 0; }
    if env -u M27_BIN "$GO" test -race -tags fixtures -count=1 \
            -timeout 600s ./internal/runner \
            >"$WORK/race.runner.detail.log" 2>&1; then
        return 0
    fi
    tail -12 "$WORK/race.runner.detail.log"
    return 1
}

# fixtures-tagged lint of the packages this chunk owns.
job_lint.runner() {
    command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not on PATH"; return 1; }
    mkdir -p "$ROOT/.check-work/tmp"
    if GOLANGCI_LINT_CACHE="$ROOT/.check-work/golangci-lint-cache-M2.7" TMPDIR="$ROOT/.check-work/tmp" \
        golangci-lint run --build-tags fixtures \
        ./internal/runner ./cmd/cs ./test/runner/... \
        >"$WORK/lint.runner.detail.log" 2>&1; then
        return 0
    fi
    tail -8 "$WORK/lint.runner.detail.log"
    return 1
}

# Serial: the tests spawn real user/mount/net/pid namespaces and drive
# signals through process groups; parallel runs only add flake surface.
for id in C2.7.1 C2.7.2 C2.7.3 C2.7.4 C2.7.5 C2.7.X C2.7.6 lint.runner race.runner; do
    ( "job_$id" "$id" >"$WORK/$id.out" 2>&1; echo $? >"$WORK/$id.rc" )
done

for id in C2.7.1 C2.7.2 C2.7.3 C2.7.4 C2.7.5 C2.7.X C2.7.6 lint.runner race.runner; do
    if [ "$(cat "$WORK/$id.rc" 2>/dev/null)" = "0" ]; then
        pass "$id"
    else
        bad "$id" "$(tail -6 "$WORK/$id.out" 2>/dev/null | tr '\n' ' ')"
    fi
done

[ "$fail" -eq 0 ] && echo "M2.7 suite: all checks passed" || echo "M2.7 suite: FAILURES" >&2
exit "$fail"
