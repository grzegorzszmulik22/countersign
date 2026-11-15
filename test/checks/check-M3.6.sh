#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M3.6 (semantic matchers: git-smart-http).
# Emits one "CHECK <id> PASS|FAIL" line per check; exits non-zero if any
# fails. C3.6.1/C3.6.2 run a real git client against fakehub through
# test/gateproxy (the §2 step-1/2 decision path the broker applies per
# request; the broker data plane itself is M2) under -tags fixtures.
set -u
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
ROOT=$PWD
GO="$ROOT/.tools/bin/go"
fail=0

mkdir -p "$ROOT/.check-work"
WORK=$(mktemp -d "$ROOT/.check-work/M3.6.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad() { say "$1" FAIL "$2"; fail=1; }

gotest() { # <id> <tags> <run pattern> (invoked inside a job)
    local id=$1 tags=$2 pat=$3
    if ! [ -x "$GO" ]; then
        echo "go toolchain missing: run make tools"
        return 1
    fi
    local tagarg=()
    [ -n "$tags" ] && tagarg=(-tags "$tags")
    if "$GO" test "${tagarg[@]}" -count=1 -run "$pat" ./internal/policy \
            >"$WORK/$id.full.log" 2>&1; then
        return 0
    fi
    tail -8 "$WORK/$id.full.log"
    return 1
}

# --- C3.6.1: real git vs fakehub through the gate: access read allows
# clone/fetch and denies push; access write lets the same push through -------
job_C3.6.1() { gotest "$1" fixtures '^TestC361GitSmartHTTP$'; }

# --- C3.6.2: a grant for acme/widgets carries no push to attacker/loot ------
job_C3.6.2() { gotest "$1" fixtures '^TestC362CrossRepoPush$'; }

# --- C3.6.3: bad service / extra segments / traversal never match -----------
job_C3.6.3() { gotest "$1" "" '^TestC363GitMatcherEdges$'; }

# --- C3.6.4: >=30 matcher rows in the decision table, all passing ------------
job_C3.6.4() {
    gotest "$1.count" "" '^TestC364GitMatcherRows$' || return 1
    gotest "$1" "" '^TestDecisionTable$' || return 1
    return 0
}

# --- fixtures-tagged lint of the code paths the e2e checks exercise ---------
job_lint.fixtures() {
    command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not on PATH"; return 1; }
    mkdir -p "$WORK/lintcache" "$WORK/tmp"
    if GOLANGCI_LINT_CACHE="$WORK/lintcache" TMPDIR="$WORK/tmp" \
        golangci-lint run --build-tags fixtures ./internal/policy ./test/gateproxy \
            >"$WORK/lint.detail.log" 2>&1; then
        return 0
    fi
    tail -5 "$WORK/lint.detail.log"
    return 1
}

# ---------------------------------------------------------------------------
ids=(C3.6.1 C3.6.2 C3.6.3 C3.6.4 lint.fixtures)
for id in "${ids[@]}"; do
    ( "job_$id" "$id" >"$WORK/$id.out" 2>&1; echo $? >"$WORK/$id.rc" ) &
done
wait

for id in "${ids[@]}"; do
    if [ ! -f "$WORK/$id.rc" ]; then
        bad "$id" "check body did not run"
    elif [ "$(cat "$WORK/$id.rc")" -eq 0 ]; then
        pass "$id"
    else
        bad "$id" "$(tail -4 "$WORK/$id.out" | tr '\n' ' ')"
    fi
done

[ "$fail" -eq 0 ] && echo "M3.6 suite: all checks passed" || echo "M3.6 suite: FAILURES" >&2
exit "$fail"
