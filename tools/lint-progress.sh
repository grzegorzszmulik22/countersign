#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# lint-progress.sh — validate progress rows in spec/PROGRESS.md and
# spec/progress/*.md against 06-agent-loop.md §13:
#   | chunk | status | attempts | last evidence folder | note |
# (the supervisor's PROGRESS.md adds a title column after chunk; both forms are
# accepted). Status must be a known value; attempts empty or an integer.
set -uo pipefail

cd "$(dirname "$0")/.."

files=()
[ -f spec/PROGRESS.md ] && files+=(spec/PROGRESS.md)
for f in spec/progress/*.md; do
    [ -e "$f" ] && files+=("$f")
done
[ "${#files[@]}" -eq 0 ] && { echo "progress lint: no progress files"; exit 0; }

bad=$(awk '
    BEGIN {
        split("TODO IN_PROGRESS DONE BLOCKED SKIPPED-ENV AWAITING-GATE", ok, " ")
        for (s in ok) valid[ok[s]] = 1
        rc = 0
    }
    /^\|/ {
        line = $0
        gsub(/^[ \t]+|[ \t]+$/, "", line)
        n = split(line, f, "|")
        # f[1] is empty (leading |), f[n] is empty (trailing |)
        if (n < 7) next                        # not a full row
        body = ""
        for (i = 2; i < n; i++) body = body f[i]
        if (body ~ /^[ :|-]*$/) next           # separator row
        rowkind = f[2]; gsub(/[ *]/, "", rowkind)
        if (rowkind ~ /^(chunk|#)$/) next      # header row
        # status sits in f[3] (§13 five-column) or f[4] (six-column w/ title)
        status = ""
        for (i = 3; i <= 4 && i < n; i++) {
            v = f[i]; gsub(/[ *]/, "", v)
            if (v in valid || v ~ /^BLOCKED-CR-[0-9]+$/) { status = v; break }
        }
        if (status == "") { printf "%s:%d: bad row: %s\n", FILENAME, FNR, line; rc = 1; next }
        attempts = f[i+1]; gsub(/[ \t]/, "", attempts)
        if (attempts != "" && attempts !~ /^[0-9]+$/) {
            printf "%s:%d: attempts not an integer: %s\n", FILENAME, FNR, line; rc = 1
        }
    }
    END { exit rc }
' "${files[@]}")

rc=$?
if [ "$rc" -eq 0 ]; then
    echo "progress rows: ok"
else
    printf '%s' "$bad"
fi
exit "$rc"
