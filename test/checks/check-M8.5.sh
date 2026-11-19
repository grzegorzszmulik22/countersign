#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M8.5 (privacy and redaction).
#   C8.5.1 credential shapes: [REDACTED:<shape>]; digest of original
#   C8.5.2 previews off: no preview field anywhere
#   C8.5.3 previews: UTF-8 boundary safe, <= 256 bytes
#   C8.5.4 whole-ledger scan: zero canary secrets, zero markers
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
  if "$GO" test "$@" 2>&1 | tail -15; then
    pass "$id"
  else
    bad "$id" "go test failed"
  fi
}

# C8.5.1: each credential shape redacts to [REDACTED:<shape>] and the
# input digest covers the original bytes (unit + broker-level).
run C8.5.1 ./internal/inspect/ -count=1 -run '^TestPreview' -v

# C8.5.2: privacy.previews: false omits the preview field entirely.
run C8.5.2 -tags fixtures ./internal/proxy/ -count=1 \
    -run '^TestM8E2E_Privacy$' -v

# C8.5.3: previews never split a multi-byte character and stay <= 256 B.
run C8.5.3 ./internal/inspect/ -count=1 \
    -run '^(TestPreviewCap|TestPreviewBoundaryInputs)$' -v

# C8.5.4: the planted credential and transcript markers never land in
# the ledger (broker-level scan inside the privacy + tracking runs).
run C8.5.4 -tags fixtures ./internal/proxy/ -count=1 \
    -run '^(TestM8E2E_Privacy|TestM8E2E_TrackingCorpus)$' -v

[ "$fail" -eq 0 ] && echo "M8.5 suite: all checks passed" \
    || echo "M8.5 suite: FAILURES" >&2
exit "$fail"
