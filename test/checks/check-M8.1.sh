#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M8.1 (inspection framework + Anthropic Messages).
#   C8.1.1 MM8.1: intents equal ground truth over 1,000 random chunkings
#   C8.1.2 ordering: intent.declared durable before the completing bytes
#   C8.1.3 MM8.2 byte equality + MM8.3 added-delay bounds
#   C8.1.4 stream cut mid-block: no intent, intent.unparsed, bytes exact
#   C8.1.5 unknown event/block types: ignored silently
#   C8.1.6 parser fuzz: no panic, no fabrication (MM8.4)
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

run() { # run <check-id> <go test args...>
  local id=$1; shift
  echo "--- $id: go test $*"
  local out rc
  out=$("$GO" test "$@" 2>&1); rc=$?
  echo "$out" | tail -15
  if [ "$rc" -eq 0 ]; then
    pass "$id"
  else
    bad "$id" "go test failed"
  fi
}

# C8.1.1 MM8.1: the Anthropic vectors under 1,008 chunkings each equal
# the independently computed ground truth (IDs, tools, digests, order).
run C8.1.1 ./internal/inspect/ -count=1 -run '^TestVectorsChunkIndependent$' -v

# C8.1.2: write-ahead ordering through a live broker.
run C8.1.2 -tags fixtures ./internal/proxy/ -count=1 -run '^TestM8E2E_WriteAheadOrdering$' -v

# C8.1.3: byte equality (MM8.2) on every vector through the broker,
# the paced-stream added-delay bound (MM8.3), and the declared-record
# field shape (class from toolClasses, exec anchor, via_effect).
run C8.1.3 -tags fixtures ./internal/proxy/ -count=1 \
    -run '^(TestM8E2E_ResponseVectors|TestM8E2E_Latency|TestM8E2E_IntentClassAnchor)$' -v

# C8.1.4: the cut-midblock vector declares nothing for the incomplete
# block and writes intent.unparsed while the client sees sent bytes
# (asserted inside the corpus e2e; the malformed unit cases pin it down).
run C8.1.4 ./internal/inspect/ -count=1 -run '^TestParseMalformed$' -v

# C8.1.5: unknown event and block types produce neither intents nor
# intent.unparsed — the unknown-sse vector carries zero of both.
run C8.1.5 -tags fixtures ./internal/proxy/ -count=1 \
    -run 'TestM8E2E_ResponseVectors/anthropic/unknown-sse' -v

# C8.1.6: 10-minute native fuzz of every endpoint parser under both
# content types (corpus-seeded), then the deterministic fabrication
# corpus — no panic, no fabricated intents (MM8.4).
fout=$(mktemp)
if "$GO" test ./internal/inspect/ -count=1 -run '^$' \
    -fuzz '^FuzzResponseParser$' -fuzztime=600s >"$fout" 2>&1 \
    && "$GO" test ./internal/inspect/ -count=1 \
    -run '^(TestParserNeverFabricatesOnGarbage|TestParserMutationFuzz)$' >>"$fout" 2>&1; then
    tail -15 "$fout"; rm -f "$fout"; pass C8.1.6
else
    tail -15 "$fout"; rm -f "$fout"; bad C8.1.6 "go test failed"
fi

[ "$fail" -eq 0 ] && echo "M8.1 suite: all checks passed" \
    || echo "M8.1 suite: FAILURES" >&2
exit "$fail"
