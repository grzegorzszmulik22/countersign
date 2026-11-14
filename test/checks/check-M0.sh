#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# check-M0.sh — milestone-level suite: runs `make check-<id>` for every chunk
# suite test/checks/check-M0.<n>*.sh that exists, in name order. Required by
# C0.2.2 ("make check-M0 still passes" under make offline-on). Each chunk
# writes its own evidence folder through tools/check.sh.
set -u
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
MAKE=${MAKE:-make}
fail=0

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }

found=0
for f in test/checks/check-M0.[0-9]*.sh; do
    [ -e "$f" ] || continue
    found=1
    id=${f#test/checks/check-}
    id=${id%.sh}
    echo "== make check-$id =="
    if ! "$MAKE" "check-$id"; then
        say "$id" FAIL "make check-$id non-zero"
        fail=1
    else
        say "$id" PASS
    fi
done
[ "$found" -eq 1 ] || { echo "no M0.* check suites found" >&2; exit 2; }

[ "$fail" -eq 0 ] && echo "check-M0: all M0.* suites passed" || echo "check-M0: FAILURES" >&2
exit "$fail"
