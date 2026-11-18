#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M9.2 (Go reconciliation engine + csverify V16).
# Emits one "CHECK <id> PASS|FAIL" line per numbered check; exits non-zero
# if any check fails.
#
#   C9.2.1  Go output identical to the expected corpus results
#   C9.2.2  MM9.1 differential: Go engine vs frozen Python reference on
#           10,000 seeded random traces
#   C9.2.3  MM9.2: every planted unattributed audit-mode effect yields
#           F_UNATTRIBUTED
#   C9.2.4  re-signed bundles with tampered recorded attribution/decision
#           yield F_ATTRIBUTION_MISMATCH / F_DECISION_MISMATCH etc. (the
#           verifier must not trust broker claims)
#   C9.2.5  verdict lattice of 03 §10 on constructed bundle cases
set -u
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
ROOT=$PWD
PY=$ROOT/.tools/bin/python3
GO=$ROOT/.tools/bin/go
BIN=$ROOT/.check-work/csverify-m92
VECTORS=$ROOT/test/vectors/reconcile
WORK=$ROOT/.check-work/m92
fail=0

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad() { say "$1" FAIL "$2"; fail=1; }

if [ ! -x "$PY" ]; then
    echo "missing pinned python at .tools/bin/python3: run make tools" >&2
    exit 2
fi
mkdir -p "$WORK"

bout=$("$GO" build -o "$BIN" ./cmd/csverify 2>&1); brc=$?
if [ "$brc" -ne 0 ]; then
    echo "$bout"
    bad C9.2.1 "csverify does not build"
    bad C9.2.2 "csverify does not build"
    bad C9.2.3 "csverify does not build"
    bad C9.2.4 "csverify does not build"
    bad C9.2.5 "csverify does not build"
    exit "$fail"
fi

# --- C9.2.1: frozen corpus ------------------------------------------------
cout=$("$BIN" reconcile-corpus "$VECTORS" 2>&1); crc=$?
echo "$cout" | tail -4
ntrace=$(find "$VECTORS" -name '*.jsonl' | wc -l)
if [ "$ntrace" -lt 80 ]; then
    bad C9.2.1 "only $ntrace corpus traces"
elif [ "$crc" -ne 0 ]; then
    bad C9.2.1 "$(echo "$cout" | tail -1)"
else
    pass C9.2.1
fi

# --- C9.2.2: MM9.1 differential, 10,000 seeded traces ---------------------
# The MM9.1/MM9.2 differentials run at nice 15 per the lane note (shared host).
gout=$(nice -n 15 "$PY" test/gen/recongen.py mm91 --count 10000 --seed 91009 \
    --work "$WORK/mm91" 2>&1); grc=$?
echo "$gout"
if [ "$grc" -ne 0 ]; then
    bad C9.2.2 "generator failed: $(echo "$gout" | tail -1)"
else
    nice -n 15 "$BIN" reconcile-batch "$WORK/mm91/traces.jsonl" > "$WORK/mm91/got.jsonl" 2>&1
    rrc=$?
    cout2=$("$PY" test/gen/reconcmp.py mm91 "$WORK/mm91/expected.jsonl" \
        "$WORK/mm91/got.jsonl" 2>&1); ccrc=$?
    echo "$cout2"
    if [ "$rrc" -ne 0 ]; then
        bad C9.2.2 "reconcile-batch exited $rrc"
    elif [ "$ccrc" -ne 0 ]; then
        bad C9.2.2 "$(echo "$cout2" | tail -1)"
    else
        pass C9.2.2
    fi
fi

# --- C9.2.3: MM9.2 planted unattributed effects ---------------------------
gout=$("$PY" test/gen/recongen.py mm92 --count 1500 --seed 77031 \
    --work "$WORK/mm92" 2>&1); grc=$?
echo "$gout"
if [ "$grc" -ne 0 ]; then
    bad C9.2.3 "generator failed: $(echo "$gout" | tail -1)"
else
    nice -n 15 "$BIN" reconcile-batch "$WORK/mm92/traces.jsonl" > "$WORK/mm92/got.jsonl" 2>&1
    cout3=$("$PY" test/gen/reconcmp.py mm92 "$WORK/mm92/planted.json" \
        "$WORK/mm92/got.jsonl" 2>&1); ccrc=$?
    echo "$cout3"
    if [ "$ccrc" -ne 0 ]; then
        bad C9.2.3 "$(echo "$cout3" | tail -1)"
    else
        pass C9.2.3
    fi
fi

# --- C9.2.4: re-signed bundles with tampered recorded fields --------------
tout=$("$GO" test -count=1 -run 'TestC924' ./cmd/csverify/ 2>&1); trc=$?
echo "$tout" | tail -4
if [ "$trc" -eq 0 ]; then
    pass C9.2.4
else
    bad C9.2.4 "$(echo "$tout" | tail -1)"
fi

# --- C9.2.5: verdict lattice ----------------------------------------------
tout=$("$GO" test -count=1 -run 'TestC925' ./cmd/csverify/ 2>&1); trc=$?
echo "$tout" | tail -4
if [ "$trc" -eq 0 ]; then
    pass C9.2.5
else
    bad C9.2.5 "$(echo "$tout" | tail -1)"
fi

[ "$fail" -eq 0 ] && echo "M9.2 suite: all checks passed" \
    || echo "M9.2 suite: FAILURES" >&2
exit "$fail"
