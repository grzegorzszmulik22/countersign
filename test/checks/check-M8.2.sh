#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M8.2 (OpenAI Responses + Chat Completions).
#   C8.2.1 MM8.1 for both OpenAI vector sets
#   C8.2.2 interleaved streamed argument fragments assemble correctly
#   C8.2.3 C8.1.2–C8.1.6 equivalents through the broker
set -u
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
ROOT=$PWD
GO=$ROOT/.tools/bin/go
fail=0

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad() { say "$1" FAIL "$2"; fail=1; }

[ -x "$GO" ] || { echo "missing go toolchain: run make tools" >&2; exit 2; }

# The vector suite runs ~9-10 min under load; Go's default 10m test
# timeout kills it mid-run, so give real headroom.
TIMEOUT=-timeout=30m

run() {
  local id=$1; shift
  echo "--- $id: go test $*"
  local out rc
  out=$("$GO" test "$TIMEOUT" "$@" 2>&1); rc=$?
  echo "$out" | tail -15
  if [ "$rc" -eq 0 ]; then
    pass "$id"
  else
    bad "$id" "go test failed"
  fi
}

# C8.2.1 MM8.1: every Responses and Chat vector under 1,008 chunkings
# equals the Python-reference ground truth.
run C8.2.1 ./internal/inspect/ -count=1 -run '^TestVectorsChunkIndependent$' -v

# C8.2.2: streamed argument fragments for interleaved calls assemble by
# index — the fragments/interleaved vectors carry split names and args.
run C8.2.2 ./internal/inspect/ -count=1 \
    -run '^TestVectorsChunkIndependent$' -v

# C8.2.3: the C8.1.2–C8.1.6 equivalents — write-ahead ordering on the
# Responses stream, byte equality + malformed + unknown/cut handling of
# every OpenAI vector through the live broker, the malformed unit
# corpus, and the 10-minute native fuzz over all endpoint parsers.
out=$(mktemp)
if "$GO" test "$TIMEOUT" -tags fixtures ./internal/proxy/ -count=1 \
    -run '^(TestM8E2E_ResponseVectors|TestM8E2E_WriteAheadOrdering|TestM8E2E_WriteAheadBoundary|TestM8E2E_WriteAheadBoundaryEOF|TestM8E2E_WriteAheadJSON|TestM8E2E_LedgerFailClosed)$' >"$out" 2>&1 \
    && "$GO" test "$TIMEOUT" ./internal/inspect/ -count=1 -run '^TestParseMalformed$' >>"$out" 2>&1 \
    && "$GO" test "$TIMEOUT" ./internal/inspect/ -count=1 -run '^$' \
    -fuzz '^FuzzResponseParser$' -fuzztime=600s >>"$out" 2>&1; then
    tail -15 "$out"; rm -f "$out"; pass C8.2.3
else
    tail -15 "$out"; rm -f "$out"; bad C8.2.3 "go test failed"
fi

[ "$fail" -eq 0 ] && echo "M8.2 suite: all checks passed" \
    || echo "M8.2 suite: FAILURES" >&2
exit "$fail"
