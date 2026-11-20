#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M3.5 (limits). Emits one "CHECK <id> PASS|FAIL"
# line per numbered check; exits non-zero if any check fails.
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

# C3.5.1 — each limit at its boundary: allowed at the value, denied one
# over with the right LIMIT_* (URL counts path + query).
job_C3.5.1() { gotest "$1" ./internal/proxy '^TestC351LimitBoundaries$'; }

# C3.5.2 — the rate bucket is per (session, grant): burst exhausted on
# one session leaves session B and other grants untouched.
job_C3.5.2() { gotest "$1" ./internal/proxy '^TestC352RateScope$'; }

# C3.5.3 — the body cap holds while streaming: upstream sees at most the
# limit, the write aborts, result.error = "limit-body". -race -count=200:
# the mid-write denial's accounting lands asynchronously — repetitions
# are what catch timing-dependent escapes.
job_C3.5.3() {
    if ! [ -x "$GO" ]; then
        echo "go toolchain missing: run make tools"
        return 1
    fi
    # Requires a C compiler for cgo — skip only when none exists (same
    # rule as M2.7's race.runner; the row lives in tools/env-skips.txt).
    command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 \
        || command -v clang >/dev/null 2>&1 \
        || { echo "no C compiler; -race unsupported here"; return 0; }
    # -race -count=200 runs ~10+ min under the regress fan-out; Go's
    # default 10m test timeout kills it mid-run, so give real headroom.
    if "$GO" test -tags fixtures -race -count=200 -timeout=30m -run '^TestC353' \
        ./internal/proxy >"$WORK/$1.full.log" 2>&1; then
        return 0
    fi
    tail -8 "$WORK/$1.full.log"
    return 1
}

# C3.5.4 — the broker never follows redirects; a 3xx reaches the client
# and the follow-up is evaluated on its own grant (no credential hops).
job_C3.5.4() { gotest "$1" ./internal/proxy '^TestC354Redirects$'; }

ids=(C3.5.1 C3.5.2 C3.5.3 C3.5.4)

for id in "${ids[@]}"; do
    ( "job_$id" "$id" >"$WORK/$id.out" 2>&1; echo $? >"$WORK/$id.rc" ) &
done
wait

skipped=0
for id in "${ids[@]}"; do
    if [ "$id" = C3.5.3 ] && grep -q "^no C compiler" "$WORK/$id.out" 2>/dev/null; then
        # Never a silent pass: without a C compiler -race cannot run, so
        # the check is a SKIP, accepted by regress only on hosts listed
        # in tools/env-skips.txt.
        say "$id" SKIP "no C compiler on $(hostname -s); -race unsupported"
        skipped=1
    elif [ "$(cat "$WORK/$id.rc" 2>/dev/null)" = "0" ]; then
        pass "$id"
    else
        bad "$id" "$(tail -6 "$WORK/$id.out" 2>/dev/null | tr '\n' ' ')"
    fi
done

[ "$fail" -eq 0 ] && [ "$skipped" -eq 0 ] && echo "M3.5 suite: all checks passed"
[ "$fail" -ne 0 ] && echo "M3.5 suite: FAILURES" >&2
[ "$fail" -eq 0 ] && [ "$skipped" -ne 0 ] && echo "M3.5 suite: passed except listed SKIPs" >&2
[ "$fail" -ne 0 ] && exit 1
[ "$skipped" -ne 0 ] && exit 2
exit 0
