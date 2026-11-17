#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M1.2 (signing, keys, emitter chains).
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

gotest C1.2.1 ./internal/keys/ -run '^TestC121' -count=1 -v
gotest C1.2.2 ./internal/keys/ -run '^TestC122' -count=1 -v
gotest C1.2.3 ./internal/keys/ -run '^TestC123' -count=1 -v
gotest C1.2.4 ./internal/keys/ -run '^TestC124|TestSignerFile|TestManifest' -count=1 -v
gotest C1.2.5 ./internal/keys/ -run '^TestC125' -count=1 -v

[ "$fail" -eq 0 ] && echo "M1.2 suite: all checks passed" || echo "M1.2 suite: FAILURES" >&2
exit "$fail"
