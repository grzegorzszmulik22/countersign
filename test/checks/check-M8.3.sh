#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M8.3 (request-side tracking).
#   C8.3.1 MM8.5: windows close correctly across the tracking corpus
#   C8.3.2 intent.result durable before the carrying request crosses
#   C8.3.3 context dedup: each block once; count + context_sha256 match
#   C8.3.4 LIMIT_BODY over the 32 MiB inference default / grant override
#   C8.3.5 no prompt or completion text in the ledger (marker scan)
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

run() {
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

# C8.3.1 MM8.5: the tracking corpus end-to-end — every window closes
# exactly as the independently computed expectations say.
run C8.3.1 -tags fixtures ./internal/proxy/ -count=1 \
    -run '^TestM8E2E_TrackingCorpus$' -v

# C8.3.2: the upstream asserts the intent.result is durable before a
# result-carrying request reaches it (inside the tracking corpus).
run C8.3.2 -tags fixtures ./internal/proxy/ -count=1 \
    -run '^TestM8E2E_TrackingCorpus$' -v

# C8.3.3: new_blocks once per digest per session; running count and
# context_sha256 match a recomputation (inside the tracking corpus plus
# the tracker unit tests).
run C8.3.3 ./internal/inspect/ -count=1 -run '^TestTracker' -v

# C8.3.4: over-limit inspected requests are denied LIMIT_BODY; grant
# bufferLimit raises it; the inference default is 32 MiB.
run C8.3.4 -tags fixtures ./internal/proxy/ -count=1 \
    -run '^TestM8E2E_LimitBody$' -v

# C8.3.5: planted marker strings from every transcript's text content
# never appear in the ledger (inside the tracking corpus and the
# privacy run).
run C8.3.5 -tags fixtures ./internal/proxy/ -count=1 \
    -run '^(TestM8E2E_TrackingCorpus|TestM8E2E_Privacy)$' -v

[ "$fail" -eq 0 ] && echo "M8.3 suite: all checks passed" \
    || echo "M8.3 suite: FAILURES" >&2
exit "$fail"
