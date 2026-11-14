#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Self-test chunk for the check/sabotage harness (M0.5): a suite that is BLIND
# to the file its sabotage patch corrupts. `make sabotage-DUMMY2` must report
# the patch as uncaught and exit non-zero.
set -u
cd "$(dirname "$0")/../.."

if [ -f LICENSE ]; then
    echo "CHECK D2.1 PASS"
    echo "DUMMY2 suite: all checks passed"
    exit 0
fi
echo "CHECK D2.1 FAIL — LICENSE missing"
echo "DUMMY2 suite: FAILURES" >&2
exit 1
