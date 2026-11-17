#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M1.3 (Merkle log and checkpoints).
set -u
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
ROOT=$PWD
export PATH="$ROOT/.tools/bin:$PATH"
GO="$ROOT/.tools/bin/go"
fail=0

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad() { say "$1" FAIL "$2"; fail=1; }

gotest() {
    local id=$1; shift
    if "$GO" test "$@" >"/tmp/${id}.$$.log" 2>&1; then
        pass "$id"
    else
        bad "$id" "$(tail -5 "/tmp/${id}.$$.log" | tr '\n' ' ')"
    fi
    rm -f "/tmp/${id}.$$.log"
}

gotest C1.3.1 ./internal/mlog/ -run '^TestC131' -count=1 -v
gotest C1.3.2 ./internal/mlog/ -run '^TestC132' -count=1 -v
gotest C1.3.3 ./internal/mlog/ -run '^TestC133' -count=1 -v
gotest C1.3.4 ./internal/mlog/ -run '^TestC134' -count=1 -v
gotest C1.3.5 ./internal/mlog/ -run '^TestC135' -count=1 -v

[ "$fail" -eq 0 ] && echo "M1.3 suite: all checks passed" || echo "M1.3 suite: FAILURES" >&2
exit "$fail"
