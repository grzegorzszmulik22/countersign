#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M3.3 (pinning, placeholder misuse, credential
# shapes). Emits one "CHECK <id> PASS|FAIL" line per numbered check;
# exits non-zero if any check fails.
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

# C3.3.1 — foreign credential material on a credentialed grant is refused
# and never reaches the upstream (A6 in miniature).
job_C3.3.1() { gotest "$1" ./internal/proxy '^TestC331ForeignCredential$'; }

# C3.3.2 — the session's own placeholder anywhere but the exact inject
# slot (query, JSON body, other header, other host, Basic username,
# slot-with-extra-junk) is PLACEHOLDER_MISUSE.
job_C3.3.2() { gotest "$1" ./internal/proxy '^TestC332PlaceholderMisuse$'; }

# C3.3.3 — another session's (or another grant's) placeholder in the
# slot is misuse, not an authorized substitution.
job_C3.3.3() { gotest "$1" ./internal/proxy '^TestC333CrossSessionPlaceholder$'; }

# C3.3.4 — §4.4-shaped strings in the URL or buffered body of a
# credentialed-grant request are FOREIGN_CREDENTIAL; the same string on
# a non-credentialed grant (even on the same host) is allowed.
job_C3.3.4() { gotest "$1" ./internal/proxy '^TestC334CredentialShape$'; }

# C3.3.5 — detector conformance: 100% of positive credshapes.json
# vectors detected, 0% of negatives flagged.
job_C3.3.5() {
    gotest "$1" ./internal/proxy '^TestC335ShapeVectorsEndToEnd$' || return 1
    gotest "$1" ./internal/creds '^TestCredshapesVectors$'
}

# C3.3.6 — ordinary bearer-less requests to non-credentialed grants are
# untouched by every credential rule.
job_C3.3.6() { gotest "$1" ./internal/proxy '^TestC336NonCredentialedUnaffected$'; }

ids=(C3.3.1 C3.3.2 C3.3.3 C3.3.4 C3.3.5 C3.3.6)

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

[ "$fail" -eq 0 ] && echo "M3.3 suite: all checks passed" || echo "M3.3 suite: FAILURES" >&2
exit "$fail"
