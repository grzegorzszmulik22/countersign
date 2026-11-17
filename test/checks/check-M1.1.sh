#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M1.1 (records and envelope).
# Emits one "CHECK <id> PASS|FAIL" line per numbered check; exits non-zero if
# any check fails.
set -u
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
ROOT=$PWD
export PATH="$ROOT/.tools/bin:$PATH"
GO="$ROOT/.tools/bin/go"
fail=0

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad() { say "$1" FAIL "$2"; fail=1; }

gotest() { # gotest <checkid> <go test args...>
    local id=$1; shift
    if "$GO" test "$@" >"/tmp/${id}.$$.log" 2>&1; then
        pass "$id"
    else
        bad "$id" "$(tail -5 "/tmp/${id}.$$.log" | tr '\n' ' ')"
    fi
    rm -f "/tmp/${id}.$$.log"
}

# --- C1.1.1 round trip ------------------------------------------------------
gotest C1.1.1 ./internal/evidence/ -run '^TestC111' -count=1 -v

# --- C1.1.2 PAE upstream vector ---------------------------------------------
gotest C1.1.2 ./internal/evidence/ -run '^TestC112' -count=1 -v

# --- C1.1.3 decoder rejections ----------------------------------------------
gotest C1.1.3 ./internal/evidence/ -run '^TestC113' -count=1 -v

# --- C1.1.4 schema bijection --------------------------------------------------
# Committed schemas must equal what the generator emits (_common.json is
# hand-written and excluded), then the Go test proves type↔schema bijection
# and that valid samples validate.
tmp=$(mktemp -d)
"$GO" run ./tools/schemagen "$tmp" >/dev/null 2>&1
drift=$(diff -rq --exclude=_common.json "$tmp" "$ROOT/api/schema/records" 2>&1)
rm -rf "$tmp"
if [ -n "$drift" ]; then
    bad C1.1.4 "committed schemas differ from schemagen output: $(echo "$drift" | head -3 | tr '\n' ' ')"
else
    gotest C1.1.4 ./internal/evidence/ -run '^TestC114' -count=1 -v
fi

# --- C1.1.5 10-minute native fuzz of the envelope decoder ---------------------
log=/tmp/C115.$$.log
if "$GO" test ./internal/evidence/ -run '^$' -fuzz '^FuzzEnvelope$' -fuzztime=600s -v >"$log" 2>&1 \
    && "$GO" test ./internal/evidence/ -run '^$' -fuzz '^FuzzRecordLine$' -fuzztime=600s -v >>"$log" 2>&1; then
    pass C1.1.5
else
    bad C1.1.5 "$(tail -5 "$log" | tr '\n' ' ')"
fi
rm -f "$log"

[ "$fail" -eq 0 ] && echo "M1.1 suite: all checks passed" || echo "M1.1 suite: FAILURES" >&2
exit "$fail"
