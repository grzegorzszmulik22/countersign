#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M3.4 (response scrubbing). Emits one
# "CHECK <id> PASS|FAIL" line per numbered check; exits non-zero if any
# check fails.
set -u
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
ROOT=$PWD
GO=$ROOT/.tools/bin/go
fail=0

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad() { say "$1" FAIL "$2"; fail=1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

gotest() { # gotest <id> <pkg> <test-pattern>
    local id=$1 pkg=$2 pat=$3
    if ! [ -x "$GO" ]; then
        echo "go toolchain missing: run make tools"
        return 1
    fi
    if "$GO" test -tags fixtures -count=1 -run "$pat" "$pkg" >"$WORK/$id.full.log" 2>&1; then
        return 0
    fi
    tail -8 "$WORK/$id.full.log"
    return 1
}

# C3.4.1 — fakehub /debug/echo through a credentialed grant: the client
# sees the placeholder where the real credential was reflected;
# result.scrubbed >= 1 (A5 in miniature).
job_C3.4.1() { gotest "$1" ./internal/proxy '^TestC341EchoScrubbed$'; }

# C3.4.2 — secret split at every interior byte of a ~40-byte secret is
# always scrubbed (the carry-over window); byte-at-a-time streams and
# the base64 form too.
job_C3.4.2() { gotest "$1" ./internal/proxy '^TestC342SplitPoints$'; }

# C3.4.3 — secret inside a gzip response is scrubbed; the client
# receives a valid identity-encoded body with the placeholder.
job_C3.4.3() {
    gotest "$1" ./internal/proxy '^TestC343GzipScrubbed$' || return 1
    gotest "$1" ./internal/creds '^TestScrubber' || true
}

# C3.4.4 — secret in a response header, in a trailer, and near the end
# of a 1 GiB body: all scrubbed. Unverifiable encoding fails closed.
job_C3.4.4() { gotest "$1" ./internal/proxy '^TestC344HeaderTrailerBig$'; }

# C3.4.5 — non-credentialed requests are not scanned and not decoded:
# byte-exact pass-through including Content-Encoding.
job_C3.4.5() { gotest "$1" ./internal/proxy '^TestC345NonCredentialedPassthrough$'; }

# C3.4.6 — MM3.4: scrubbing penalty on a 100 MiB credentialed download
# <= 25%; MM3.2: no canary in records/logs (also asserted suite-wide).
job_C3.4.6() {
    gotest "$1" ./internal/proxy '^TestC346ScrubThroughput$' || return 1
    grep -oE 'MEASUREMENT [a-zA-Z0-9_.]+ [0-9.]+( [a-zA-Z0-9_.]+ [0-9.]+)*' \
        "$WORK/$1.full.log" || true
}

ids=(C3.4.1 C3.4.2 C3.4.3 C3.4.4 C3.4.5 C3.4.6)

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

# Fold the throughput samples into measurements.json for the evidence dir.
if [ -n "${CS_CHECK_RUNNING:-}" ] && [ -d "evidence/$CS_CHECK_RUNNING" ]; then
    mdir=$(ls -td "evidence/$CS_CHECK_RUNNING"/*/ 2>/dev/null | head -1)
fi
vals=$(grep -rhoE 'scrub_penalty_pct [0-9.]+' "$WORK" 2>/dev/null | awk '{print $2}' | sort -n)
if [ -n "$vals" ] && [ -n "${mdir:-}" ]; then
    python3 - "$vals" >"${mdir}measurements.json" <<'PY'
import json, statistics, sys
s = [float(v) for v in sys.argv[1:]]
print(json.dumps({
  "chunk": "M3.4", "check": "C3.4.6",
  "metric": "response-scrub throughput penalty on 100 MiB credentialed download",
  "unit": "percent", "target": 25,
  "runs": len(s), "samples": s,
  "median": statistics.median(s),
  "met": statistics.median(s) <= 25,
  "machine": "see sysinfo.txt in this evidence folder"}, indent=2))
PY
fi

[ "$fail" -eq 0 ] && echo "M3.4 suite: all checks passed" || echo "M3.4 suite: FAILURES" >&2
exit "$fail"
