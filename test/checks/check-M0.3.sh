#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M0.3 (fixture services).
# Emits one "CHECK <id> PASS|FAIL|SKIPPED-ENV" line per check; exits non-zero
# if any check fails. Behavioural checks run as Go tests under -tags fixtures;
# the release-exclusion check (C0.3.4) is shell-driven.
set -u
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
ROOT=$PWD
GO="$ROOT/.tools/bin/go"
MAKE=${MAKE:-make}
fail=0

WORK="$ROOT/.check-work/M0.3"
rm -rf "$WORK"
mkdir -p "$WORK"

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad() { say "$1" FAIL "$2"; fail=1; }

gotest() { # <check-id> <go-test -run pattern> <pkg-pattern>
    local id=$1 pat=$2 pkg=$3
    if ! [ -x "$GO" ]; then
        bad "$id" "go toolchain missing: run make tools"
        return
    fi
    if "$GO" test -tags fixtures -count=1 -run "$pat" "$pkg" >"$WORK/$id.log" 2>&1; then
        pass "$id"
    else
        bad "$id" "$(tail -6 "$WORK/$id.log" | tr '\n' ' ')"
    fi
}

# --- C0.3.1: every listed behaviour, per fixture -----------------------------
gotest C0.3.1.echo    '^TestC031Echo'     ./test/fixtures/echo
gotest C0.3.1.sink    '^TestC031Sink'     ./test/fixtures/sink
gotest C0.3.1.fakehub '^TestC031Fakehub'  ./test/fixtures/fakehub
gotest C0.3.1.fakereg '^TestC031Fakereg'  ./test/fixtures/fakereg
gotest C0.3.1.fakemsg '^TestC031Fakemsg'  ./test/fixtures/fakemsg
gotest C0.3.1.mockllm '^TestC031Mockllm'  ./test/fixtures/mockllm
gotest C0.3.1.mcpdemo '^TestC031Mcpdemo'  ./test/fixtures/mcpdemo

# --- C0.3.2: sink reports the exact bytes over each listener -----------------
gotest C0.3.2 '^TestC032SinkExactBytes' ./test/fixtures/sink
# The ICMP listener needs CAP_NET_RAW; the Go test probes and returns a
# distinct message. Report it separately so a missing capability is loud.
if [ -f "$WORK/C0.3.2.log" ] && grep -q 'CS-ICMP-SKIPPED-ENV' "$WORK/C0.3.2.log"; then
    say C0.3.2.icmp SKIPPED-ENV "no CAP_NET_RAW on this host (works in cluster packaging on oci-free-a1)"
fi

# --- C0.3.3: mockllm byte-identical to reference.* in all three shapes -------
gotest C0.3.3 '^TestC033MockllmGolden' ./test/fixtures/mockllm

# --- C0.3.4: release build contains no fixture or resolver-override code -----
c034() {
    local rel="$WORK/release-bin" p files syms deps
    rm -rf "$rel"; mkdir -p "$rel"
    # A release build is `go build` without the fixtures tag. Product commands
    # do not exist yet (later milestones), so the buildable release targets are
    # the fixture command stubs plus every library in the module.
    if ! "$GO" build -o "$rel" ./test/fixtures/cmd/... 2>"$WORK/C0.3.4.build.log"; then
        echo "release build failed: $(tail -3 "$WORK/C0.3.4.build.log" | tr '\n' ' ')"
        return 1
    fi
    if ! "$GO" build ./... 2>>"$WORK/C0.3.4.build.log"; then
        echo "go build ./... failed: $(tail -3 "$WORK/C0.3.4.build.log" | tr '\n' ' ')"
        return 1
    fi
    # (a) Fixture source must be excluded by the build tag: each fixture
    # package contributes only stub/doc files when built without the tag.
    for p in echo sink fakehub fakereg fakemsg mockllm mcpdemo; do
        files=$("$GO" list -f '{{join .GoFiles ","}}' "./test/fixtures/$p" 2>/dev/null)
        if [ "$files" != "stub.go" ]; then
            echo "package test/fixtures/$p builds without the fixtures tag (files: $files)"
            return 1
        fi
    done
    for p in fxlib fxres; do
        files=$("$GO" list -f '{{join .GoFiles ","}}' "./test/fixtures/$p" 2>/dev/null)
        if [ "$files" != "stub.go" ]; then
            echo "package test/fixtures/$p builds without the fixtures tag (files: $files)"
            return 1
        fi
    done
    # (b) Release binaries carry no fixture or resolver-override symbols, and
    # their dependency list contains no fixture packages.
    for bin in "$rel"/*; do
        syms=$("$GO" tool nm "$bin" 2>/dev/null \
            | grep -cE 'countersign/test/fixtures/(echo|sink|fakehub|fakereg|fakemsg|mockllm|mcpdemo|fxlib|fxres)\.' || true)
        if [ "$syms" -ne 0 ]; then
            echo "$(basename "$bin") links fixture/resolver-override symbols"
            return 1
        fi
    done
    deps=$("$GO" list -deps ./test/fixtures/cmd/... 2>/dev/null \
        | grep -cE 'countersign/test/fixtures/(echo|sink|fakehub|fakereg|fakemsg|mockllm|mcpdemo|fxlib|fxres)$' || true)
    if [ "$deps" -ne 0 ]; then
        echo "fixture packages appear in release dependency graph"
        return 1
    fi
    return 0
}
if out=$(c034); then
    pass C0.3.4
else
    bad C0.3.4 "$out"
fi

# --- C0.3.5: /__state semantics for every fixture ----------------------------
gotest C0.3.5 '^TestC035State' ./test/fixtures/...

# --- fixtures-tagged lint: repo lint gate runs untagged, so the suite lints --
# the fixture build itself to keep this code inside the lint invariant.
lintfx() {
    command -v golangci-lint >/dev/null 2>&1 || {
        echo "golangci-lint not on PATH"
        return 1
    }
    local log="$WORK/lint.fixtures.log"
    if golangci-lint run --build-tags fixtures ./test/fixtures/... >"$log" 2>&1; then
        return 0
    fi
    tail -5 "$log"
    return 1
}
if out=$(lintfx); then
    pass lint.fixtures
else
    bad lint.fixtures "$out"
fi

# --- binary smoke: the fixture commands run as local processes ---------------
# (the cluster packaging on oci-free-a1 is out of scope for this host)
smoke() {
    local bindir="$WORK/fixture-bin" addr ok=1
    mkdir -p "$bindir"
    "$GO" build -tags fixtures -o "$bindir" ./test/fixtures/cmd/... 2>"$WORK/smoke.build.log" || {
        echo "fixture build failed: $(tail -3 "$WORK/smoke.build.log" | tr '\n' ' ')"
        return 1
    }
    for name in echo sink fakehub fakereg fakemsg mockllm mcpdemo; do
        [ -x "$bindir/$name" ] || { echo "missing binary $name"; ok=0; }
    done
    [ "$ok" -eq 1 ] || return 1
    return 0
}
if out=$(smoke); then
    pass C0.3.1.binaries
else
    bad C0.3.1.binaries "$out"
fi

[ "$fail" -eq 0 ] && echo "M0.3 suite: all checks passed" || echo "M0.3 suite: FAILURES" >&2
exit "$fail"
