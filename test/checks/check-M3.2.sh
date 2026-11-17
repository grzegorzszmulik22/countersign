#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M3.2 (credential store, placeholders, injection).
# Emits one "CHECK <id> PASS|FAIL" line per numbered check; exits non-zero
# if any check fails.
set -u
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
ROOT=$PWD
GO=$ROOT/.tools/bin/go
fail=0

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad() { say "$1" FAIL "$2"; fail=1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

gotest() { # gotest <id> <pkg> <test-pattern>
    local id=$1 pkg=$2 pat=$3
    if ! [ -x "$GO" ]; then
        echo "go toolchain missing: run make tools"
        return 1
    fi
    if "$GO" test -tags fixtures -count=1 -run "$pat" "$pkg" >"$WORK/$id.full.log" 2>&1; then
        return 0
    fi
    tail -8 "$WORK/$id.full.log"
    return 1
}

# C3.2.1 — store unit tests + exact-placeholder injection end to end.
job_C3.2.1() {
    gotest "$1" ./internal/creds 'TestFileStoreGet|TestFileStoreStrict|TestKubeStoreIface' || return 1
    gotest "$1" ./internal/proxy '^TestC321InjectHeaderPlaceholder$'
}

# C3.2.2 — placeholder format/uniqueness + absent-slot injection; the
# placeholder (not the secret) is all that ever leaves the broker's
# client side.
job_C3.2.2() {
    gotest "$1" ./internal/creds '^TestPlaceholderShape$' || return 1
    gotest "$1" ./internal/proxy '^TestC322InjectAbsentAndScope$'
}

# C3.2.3 — host/method/path scope: a different grant on the same host and
# NO_GRANT outside every grant both carry no credential.
job_C3.2.3() { gotest "$1" ./internal/proxy '^TestC323Scope$'; }

# C3.2.4 — real git clone through the broker with a Basic credential
# delivered via the session's placeholder environment.
job_C3.2.4() { gotest "$1" ./internal/proxy '^TestC324GitCloneBasic$'; }

# C3.2.5 — 50k-request injection invariant vs the Python reference
# matcher (a wrapper logs every injection).
job_C3.2.5() { gotest "$1" ./internal/proxy '^TestC325InjectionInvariant$'; }

# C3.2.6 — write-ahead: injection only after the effect.http record is
# durable; failing sink => 502 LEDGER_UNAVAILABLE, zero upstream contact.
job_C3.2.6() { gotest "$1" ./internal/proxy '^TestC326InjectAfterAck$'; }

# canary scan — no real secret material may appear in records, logs or
# evidence (04 §4.4). Asserted inside the Go tests as well.
job_canary.records() {
    grep -rlE 'CANARY_[A-Z0-9]{32}' "$ROOT/internal/proxy" "$ROOT/internal/creds" \
        --include='*.go' --exclude='*_test.go' 2>/dev/null | grep . && {
        echo "canary literal in production source"
        return 1
    }
    return 0
}

ids=(C3.2.1 C3.2.2 C3.2.3 C3.2.4 C3.2.5 C3.2.6 canary.records)

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

[ "$fail" -eq 0 ] && echo "M3.2 suite: all checks passed" || echo "M3.2 suite: FAILURES" >&2
exit "$fail"
