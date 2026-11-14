#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# regress — (1) verify spec/FROZEN.sha256 (06-agent-loop.md §7), (2) re-run the
# check suite of every chunk marked DONE in spec/PROGRESS.md or spec/progress/*.md.
# The chunk currently being checked (CS_CHECK_RUNNING) is skipped to avoid
# recursion.
set -uo pipefail
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"

root=$(git rev-parse --show-toplevel)
cd "$root"
rc=0

echo "== frozen files =="
if [ -f spec/FROZEN.sha256 ]; then
    if ! tools/verify-frozen.sh; then
        rc=1
    fi
else
    echo "spec/FROZEN.sha256 not present yet; nothing frozen"
fi

echo "== DONE chunk checks =="
done_chunks=$(awk -F'|' '
    /^\|/ {
        n = gsub(/[ \t]/, "", $0)
        # fields: $1 empty, $2 chunk, optional $3 title, then status, attempts, ...
        split($0, f, "|")
        # row format (§13): | chunk | status | attempts | evidence | note |
        # PROGRESS.md format: | chunk | title | status | attempts | evidence | note |
        status = ""
        for (i = 3; i <= 4; i++) {
            v = f[i]; gsub(/[ *]/, "", v)
            if (v == "DONE") { status = v; break }
        }
        if (status == "DONE") { c = f[2]; gsub(/[ *]/, "", c); print c }
    }' spec/PROGRESS.md spec/progress/*.md 2>/dev/null | sort -u)

if [ -z "${done_chunks:-}" ]; then
    echo "no DONE chunks"
fi
for c in $done_chunks; do
    if [ "$c" = "${CS_CHECK_RUNNING:-}" ]; then
        echo "skip $c (currently running)"
        continue
    fi
    echo "-- make check-$c"
    "${MAKE:-make}" "check-$c" || rc=1
done

if [ "$rc" -eq 0 ]; then
    echo "regress: PASS"
else
    echo "regress: FAIL" >&2
fi
exit "$rc"
