#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M3.1 (policy schema and matcher).
# Emits one "CHECK <id> PASS|FAIL" line per numbered check; exits non-zero if
# any check fails.
set -u
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
ROOT=$PWD
GO=$ROOT/.tools/bin/go
fail=0

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad() { say "$1" FAIL "$2"; fail=1; }

# --- C3.1.1/2/3/4/6: go test suite ------------------------------------------
testout=$(mktemp)
trap 'rm -f "$testout"' EXIT
"$GO" test -count=1 -v \
    -run 'TestDecisionTable|TestSchemaConformance|TestInvalidPolicies|TestPolicyDigest|TestPropertyVsPython' \
    ./internal/policy >"$testout" 2>&1
go_rc=$?
cat "$testout"

verdict() { # verdict <check-id> <test-name>
    if grep -q "^--- PASS: $2 " "$testout"; then
        pass "$1"
    elif [ "$go_rc" -ne 0 ]; then
        ctx=$(grep -E 'FAIL:|\.go:|panic|reference|build failed' "$testout" | head -2 | tr '\n' ' ')
        bad "$1" "${ctx:-$(tail -2 "$testout" | tr '\n' ' ')}"
    else
        bad "$1" "test $2 did not run"
    fi
}

verdict C3.1.1 TestDecisionTable
verdict C3.1.2 TestInvalidPolicies
verdict C3.1.3 TestPolicyDigest
verdict C3.1.4 TestPropertyVsPython
verdict C3.1.6 TestSchemaConformance

# --- C3.1.5: fuzz the YAML loader for 10 minutes ----------------------------
fzout=$(mktemp)
trap 'rm -f "$testout" "$fzout"' EXIT
if "$GO" test -count=1 -run='^$' -fuzz=FuzzLoadPolicy -fuzztime=600s ./internal/policy >"$fzout" 2>&1; then
    tail -3 "$fzout"
    pass C3.1.5
else
    cat "$fzout"
    bad C3.1.5 "$(grep -E 'panic|FAIL|error' "$fzout" | head -2 | tr '\n' ' ')"
fi

[ "$fail" -eq 0 ] && echo "M3.1 suite: all checks passed" || echo "M3.1 suite: FAILURES" >&2
exit "$fail"
