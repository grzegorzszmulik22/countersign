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
        # Frozen files are the inputs to every chunk check; once one is
        # tampered with the verdict is already FAIL and re-running the chunk
        # suites (~tens of minutes on a contended host) cannot change it.
        echo "regress: FAIL" >&2
        exit 1
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

# Independent suites run in parallel — sequential runs pushed `make regress`
# past the wall-clock budget on this contended host even when every suite
# passed. A suite that itself invokes `make regress`/`make check-*` (e.g.
# M0.5's frozen-tamper check, which dirties the main tree and re-runs other
# chunks' suites) must not overlap other suites; it runs alone afterwards.
#
# Suites carrying latency-bound checks (C2.3.2's SSE p99, C2.5.6's
# isolation p99 under flood) run serially FIRST, before the parallel
# fan-out: their bounds assume the flood/measurement is the only real
# load, which stops being true once every suite is running. The checks
# themselves are unchanged — only their scheduling window is quieter.
early=(M2.3 M2.5)
solo=(); par=()
for c in $done_chunks; do
    if [ "$c" = "${CS_CHECK_RUNNING:-}" ]; then
        echo "skip $c (currently running)"
        continue
    fi
    if grep -qE '("\$MAKE"|make|MAKE)[[:space:]]+"?(regress|check-[A-Za-z0-9])' \
            "test/checks/check-$c.sh" 2>/dev/null; then
        solo+=("$c")
    else
        par+=("$c")
    fi
done
# Move the latency-bound chunks out of par into early (keeping discovery
# order) so a chunk is never run twice.
if [ ${#early[@]} -gt 0 ]; then
    next=(); snext=()
    for c in ${par[@]+"${par[@]}"}; do
        keep=1
        for e in "${early[@]}"; do [ "$c" = "$e" ] && keep=0; done
        [ "$keep" -eq 1 ] && next+=("$c")
    done
    for c in ${solo[@]+"${solo[@]}"}; do
        keep=1
        for e in "${early[@]}"; do [ "$c" = "$e" ] && keep=0; done
        [ "$keep" -eq 1 ] && snext+=("$c")
    done
    par=(${next[@]+"${next[@]}"}); solo=(${snext[@]+"${snext[@]}"})
fi

tmpd=$(mktemp -d)
# A failing suite is accepted only when every non-PASS check is a SKIP that
# tools/env-skips.txt allows on this host (and the suite checked something).
host=$(hostname -s)
env_ok() { python3 tools/env_skip_ok.py tools/env-skips.txt "$host" <"$1"; }

for c in ${early[@]+"${early[@]}"}; do
    [ "$c" != "${CS_CHECK_RUNNING:-}" ] || continue
    [ -f "test/checks/check-$c.sh" ] || continue
    echo "-- make check-$c"
    r=0; "${MAKE:-make}" "check-$c" >"$tmpd/$c.log" 2>&1 || r=$?
    cat "$tmpd/$c.log"
    [ "$r" -eq 0 ] || env_ok "$tmpd/$c.log" || rc=1
done

declare -A pids=()
for c in ${par[@]+"${par[@]}"}; do
    "${MAKE:-make}" "check-$c" >"$tmpd/$c.log" 2>&1 &
    pids[$c]=$!
done
for c in ${par[@]+"${par[@]}"}; do
    echo "-- make check-$c"
    r=0; wait "${pids[$c]}" || r=$?
    cat "$tmpd/$c.log"
    [ "$r" -eq 0 ] || env_ok "$tmpd/$c.log" || rc=1
done

for c in ${solo[@]+"${solo[@]}"}; do
    echo "-- make check-$c"
    r=0; "${MAKE:-make}" "check-$c" >"$tmpd/$c.log" 2>&1 || r=$?
    cat "$tmpd/$c.log"
    [ "$r" -eq 0 ] || env_ok "$tmpd/$c.log" || rc=1
done
rm -rf "$tmpd"

if [ "$rc" -eq 0 ]; then
    echo "regress: PASS"
else
    echo "regress: FAIL" >&2
fi
exit "$rc"
