#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M1.4 (ledger storage, bundle, csverify).
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

gotest() {
    local id=$1; shift
    if "$GO" test "$@" >"/tmp/${id}.$$.log" 2>&1; then
        pass "$id"
    else
        bad "$id" "$(tail -8 "/tmp/${id}.$$.log" | tr '\n' ' ')"
    fi
    rm -f "/tmp/${id}.$$.log"
}

# C1.4.1 crash-recovery durability: 50 SIGKILL trials during 10k appends.
gotest C1.4.1 ./internal/ledger/ -run '^TestC141' -count=1 -v -timeout 20m

# C1.4.2 deterministic bundle export.
gotest C1.4.2 ./internal/ledger/ -run '^TestC142' -count=1 -v

# C1.4.3 golden bundles: exact verdict, error list, warning list.
gotest C1.4.3 ./internal/ledger/ -run '^TestC143' -count=1 -v

# C1.4.4 csverify uses only bundle + --keys. The container part of the
# check is SKIPPED-ENV: agent-vpc forbids containers; covered instead by
# running the verifier from an empty dir with an empty environment.
gotest C1.4.4 ./internal/ledger/ -run '^TestC144' -count=1 -v

# C1.4.5 keys.json differing from trusted manifest for a used key → E_KEY.
gotest C1.4.5 ./internal/ledger/ -run '^TestC145' -count=1 -v

# C1.4.6 append-only open flags + no rewriting API.
gotest C1.4.6 ./internal/ledger/ -run '^TestC146' -count=1 -v

# C1.4.7 fuzz the bundle reader for ten minutes.
if "$GO" test ./internal/ledger/ -run 'FuzzC147' -fuzz='FuzzC147_BundleReader' -fuzztime=600s -count=1 >"/tmp/C1.4.7.$$.log" 2>&1; then
    pass C1.4.7
else
    bad C1.4.7 "$(tail -8 "/tmp/C1.4.7.$$.log" | tr '\n' ' ')"
fi
rm -f "/tmp/C1.4.7.$$.log"

[ "$fail" -eq 0 ] && echo "M1.4 suite: all checks passed" || echo "M1.4 suite: FAILURES" >&2
exit "$fail"
