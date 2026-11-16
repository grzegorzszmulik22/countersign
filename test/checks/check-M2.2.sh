#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M2.2 (TLS interception).
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
WORK=$(mktemp -d "$ROOT/.check-work/M2.2.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad() { say "$1" FAIL "$2"; fail=1; }

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

job_C2.2.1() { gotest "$1" '^TestC221SessionCATrust$'; }
job_C2.2.2() { gotest "$1" '^TestC222PerSessionCA$'; }
job_C2.2.3() { gotest "$1" '^TestC223UpstreamVerify$'; }
job_C2.2.4() { gotest "$1" '^TestC224SNICrossCheck$'; }
job_C2.2.5() {
    # Dynamic containment scan plus the static half: every private-key
    # serialization call site in internal/proxy (outside tests) must live
    # in keystore.go.
    gotest "$1" '^TestC225KeyContainment$' || return 1
    local hits
    hits=$(grep -lE 'Marshal(EC|PKCS8|PKCS1)PrivateKey|pem\.Encode' "$ROOT"/internal/proxy/*.go 2>/dev/null | grep -v '_test\.go$' || true)
    if [ "$(echo "$hits" | grep -vc keystore.go || true)" -ne 0 ] || [ -z "$hits" ]; then
        echo "private-key serialization outside keystore.go: $hits"
        return 1
    fi
    return 0
}
job_C2.2.6() { gotest "$1" '^TestC226ALPNIndependent$'; }
job_C2.2.7() { gotest "$1" '^TestC227LeafMinting$'; }

job_lint.proxy() {
    command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not on PATH"; return 1; }
    mkdir -p "$ROOT/.check-work/tmp"
    if GOLANGCI_LINT_CACHE="$ROOT/.check-work/golangci-lint-cache" TMPDIR="$ROOT/.check-work/tmp" \
        golangci-lint run --build-tags fixtures ./internal/proxy ./cmd/csbroker >"$WORK/lint.proxy.detail.log" 2>&1; then
        return 0
    fi
    tail -8 "$WORK/lint.proxy.detail.log"
    return 1
}

ids=(C2.2.1 C2.2.2 C2.2.3 C2.2.4 C2.2.5 C2.2.6 C2.2.7 lint.proxy)

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

[ "$fail" -eq 0 ] && echo "M2.2 suite: all checks passed" || echo "M2.2 suite: FAILURES" >&2
exit "$fail"
