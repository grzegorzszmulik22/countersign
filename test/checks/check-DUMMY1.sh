#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Self-test chunk for the check/sabotage harness (M0.5): a suite that really
# looks at the file its sabotage corrupts.
set -u
cd "$(dirname "$0")/../.."

if [ "$(cat test/dummy/greeting.txt 2>/dev/null)" = "hello countersign" ]; then
    echo "CHECK D1.1 PASS"
    echo "DUMMY1 suite: all checks passed"
    exit 0
fi
echo "CHECK D1.1 FAIL — greeting.txt corrupted"
echo "DUMMY1 suite: FAILURES" >&2
exit 1
