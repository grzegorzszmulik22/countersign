#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M2.1 (proxy listener and sessions, local mode).
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
WORK=$(mktemp -d "$ROOT/.check-work/M2.1.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad() { say "$1" FAIL "$2"; fail=1; }

# Check bodies run in parallel; each writes $WORK/<id>.out + <id>.rc.
gotest() { # <id> <go-test -run pattern>
    local id=$1 pat=$2
    if ! [ -x "$GO" ]; then
        echo "go toolchain missing: run make tools"
        return 1
    fi
    if "$GO" test -tags fixtures -count=1 -run "$pat" ./internal/proxy >"$WORK/$id.full.log" 2>&1; then
        return 0
    fi
    tail -8 "$WORK/$id.full.log"
    return 1
}

job_C2.1.1() { gotest "$1" '^TestC211SessionAuth$'; }
job_C2.1.2() { gotest "$1" '^TestC212NoGrant$'; }
job_C2.1.3() { gotest "$1" '^TestC213HopByHop$'; }
job_C2.1.4() { gotest "$1" '^TestC214ConnectPort$'; }
job_C2.1.5() { gotest "$1" '^TestC215PlainHTTPScheme$'; }

# fixtures-tagged lint of the package this chunk owns.
job_lint.proxy() {
    command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not on PATH"; return 1; }
    mkdir -p "$ROOT/.check-work/tmp"
    if GOLANGCI_LINT_CACHE="$ROOT/.check-work/golangci-lint-cache-M2.1" TMPDIR="$ROOT/.check-work/tmp" \
        golangci-lint run --build-tags fixtures ./internal/proxy ./cmd/csbroker >"$WORK/lint.proxy.detail.log" 2>&1; then
        return 0
    fi
    tail -8 "$WORK/lint.proxy.detail.log"
    return 1
}

ids=(C2.1.1 C2.1.2 C2.1.3 C2.1.4 C2.1.5 lint.proxy)

for id in "${ids[@]}"; do
    ( "job_$id" "$id" >"$WORK/$id.out" 2>&1; echo $? >"$WORK/$id.rc" ) &
done
wait

for id in "${ids[@]}"; do
    if [ "$(cat "$WORK/$id.rc" 2>/dev/null)" = "0" ]; then
        pass "$id"
    else
        bad "$id" "$(tail -6 "$WORK/$id.out" 2>/dev/null | tr '\n' ' ')"
    fi
done

[ "$fail" -eq 0 ] && echo "M2.1 suite: all checks passed" || echo "M2.1 suite: FAILURES" >&2
exit "$fail"
