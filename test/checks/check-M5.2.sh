#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M5.2 (reversibility classes and autonomy, 05 §1–§2).
# Emits one "CHECK <id> PASS|FAIL|BLOCKED" line per numbered check; exits
# non-zero if any check fails or could not run.
#
#   C5.2.1  MM5.1: decision table test/vectors/policy/classes.yaml (>= 250
#           rows, expected column derived from 05 §1–§2) all pass, and the
#           Go classifier matches the independent Python reference
#           ref/python/refclassify on 10,000 generated cases
#   C5.2.2  a request matching no rule is irreversible; unknown stagers and
#           a staged class without a stager fail policy validation
#   C5.2.3  a grant requires looser than autonomy[class] has no effect
#           (strictest wins), asserted on >= 20 corpus rows
#   C5.2.4  declared_safe lands on the shared decision block, survives the
#           strict record codec and validates against the record schemas
#   C5.2.5  merged M2–M4 suites pass with the default autonomy table —
#           BLOCKED: needs M2.4 broker wiring (lane broker2)
set -u
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
ROOT=$PWD
GO=$ROOT/.tools/bin/go
PY=$ROOT/.tools/bin/python3
export GOMAXPROCS=2
fail=0

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad() { say "$1" FAIL "$2"; fail=1; }
blocked() { say "$1" BLOCKED "$2"; fail=1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

gotest() { # gotest <id> <pkg> <test-pattern> [extra go test flags]
    local id=$1 pkg=$2 pat=$3; shift 3
    if ! [ -x "$GO" ]; then
        echo "go toolchain missing: run make tools"
        return 1
    fi
    if "$GO" test -count=1 -run "$pat" "$@" "$pkg" >"$WORK/$id.full.log" 2>&1; then
        return 0
    fi
    tail -8 "$WORK/$id.full.log"
    return 1
}

# --- C5.2.1 / MM5.1 ---------------------------------------------------------
# Table driver asserts >= 250 rows; the differential test feeds 10,000
# generated (policy, grant, request, taint) cases through refclassify and
# requires identical {class, requires, declared_safe}.
job_C5.2.1() {
    gotest "$1" ./internal/classify \
        'TestClassesTable|TestClassesSchemaConformance|TestDifferentialVsRefclassify'
}

# --- C5.2.2 -----------------------------------------------------------------
job_C5.2.2() {
    gotest "$1" ./internal/classify 'TestNoRuleIrreversible|TestInvalidClassPolicies' || return 1
    # the shared invalid corpus carries the stager/autonomy vectors too.
    gotest "$1" ./internal/policy 'TestInvalidPolicies'
}

# --- C5.2.3 -----------------------------------------------------------------
# The table test counts c523-tagged rows (requires looser than
# autonomy[class]) and fails below 20; each tagged row asserts the autonomy
# value is the imposed condition.
job_C5.2.3() { gotest "$1" ./internal/classify 'TestClassesTable'; }

# --- C5.2.4 -----------------------------------------------------------------
job_C5.2.4() { gotest "$1" ./internal/classify 'TestDeclaredSafeRecordSurvival'; }

# --- C5.2.5 -----------------------------------------------------------------
# "All merged M2–M4 suites (M2.1–M2.4, M2.7, M3.1, M3.2, M3.6) pass with the
# default autonomy table." M2.4 (broker decision recording, REVIEW_REQUIRED
# denial) belongs to lane broker2 and is not merged; nothing on this branch
# can run the slice.
job_C5.2.5() {
    echo "broker wiring (class and decision.requires on every effect," \
        "REVIEW_REQUIRED) lives in internal/proxy under M2.4 (lane broker2)"
    return 1
}

for id in C5.2.1 C5.2.2 C5.2.3 C5.2.4; do
    ( "job_$id" "$id" >"$WORK/$id.out" 2>&1; echo $? >"$WORK/$id.rc" ) &
done
wait

for id in C5.2.1 C5.2.2 C5.2.3 C5.2.4; do
    if [ "$(cat "$WORK/$id.rc" 2>/dev/null)" = "0" ]; then
        pass "$id"
    else
        bad "$id" "$(tail -6 "$WORK/$id.out" 2>/dev/null | tr '\n' ' ')"
    fi
done
blocked C5.2.5 "broker wiring and C5.2.5 wait for M2.4 (lane broker2)"

# MM5.1 numbers for the evidence dir.
if [ -n "${CS_CHECK_RUNNING:-}" ]; then
    mdir=$(ls -td "evidence/$CS_CHECK_RUNNING"/*/ 2>/dev/null | head -1)
fi
if [ -n "${mdir:-}" ]; then
    rows=$(grep -c 'name: "' test/vectors/policy/classes.yaml || true)
    cat >"${mdir}measurements.json" <<EOF
{
  "chunk": "M5.2", "check": "MM5.1",
  "metric": "decision-table rows passing; Go vs Python differential cases",
  "target": "100% of >= 250 rows; 100% of 10,000",
  "samples": {"table_rows": $rows, "differential_cases": 10000},
  "met": $([ "$fail" -eq 0 ] && echo true || echo false),
  "machine": "see sysinfo.txt in this evidence folder"
}
EOF
fi

[ "$fail" -eq 0 ] && echo "M5.2 suite: all checks passed" \
    || echo "M5.2 suite: FAILURES" >&2
exit "$fail"
