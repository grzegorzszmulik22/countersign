#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# check-M1.5.sh — check suite for the Python reference verifier.
# C1.5.1 import scan; C1.5.2 differential vs csverify on every golden bundle;
# C1.5.3 no-Go-source scan; C1.5.4 RFC 6962 / C2SP vectors; C1.5.5 derived
# bundle vectors beyond the goldens (index/records disagreement, tolerated
# divergences, all warning codes).
set -uo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

PY="$root/.tools/python/bin/python3"
if [ ! -x "$PY" ]; then
    echo "pinned python missing: run make tools" >&2
    exit 2
fi

fail=0
run() {
    local id=$1; shift
    local desc=$1; shift
    if "$@"; then
        echo "CHECK $id PASS  $desc"
    else
        echo "CHECK $id FAIL  $desc"
        fail=1
    fi
}

run C1.5.1 "stdlib+cryptography imports only" \
    "$PY" test/refverify/check_imports.py

# C1.5.2: differential against csverify on every golden bundle. The check
# builds csverify from cmd/csverify with the pinned Go toolchain when no
# binary exists; it exits 3 (BLOCKED) only if neither a binary nor the Go
# toolchain plus golden bundles are present.
if "$PY" test/refverify/check_differential.py; then
    echo "CHECK C1.5.2 PASS  golden-bundle differential vs csverify"
else
    code=$?
    if [ "$code" -eq 3 ]; then
        echo "CHECK C1.5.2 BLOCKED  csverify/golden bundles absent in this lane"
    else
        echo "CHECK C1.5.2 FAIL  golden-bundle differential vs csverify"
        fail=1
    fi
fi

run C1.5.3 "no Go sources under ref/python" \
    "$PY" test/refverify/check_nogo.py

run C1.5.4 "RFC 6962 + C2SP vectors" \
    "$PY" test/refverify/check_upstream.py

run C1.5.5 "derived bundle vectors beyond the goldens" \
    "$PY" test/refverify/check_vectors.py

if [ "$fail" -eq 0 ]; then
    echo "check-M1.5: suite PASS"
else
    echo "check-M1.5: suite FAIL" >&2
fi
exit "$fail"
