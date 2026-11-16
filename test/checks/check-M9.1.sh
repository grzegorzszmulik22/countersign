#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M9.1 (reference reconciler + abstract trace corpus).
# Emits one "CHECK <id> PASS|FAIL" line per numbered check; exits non-zero if
# any check fails.
#
#   C9.1.1  the reference produces the expected result for every corpus trace
#   C9.1.2  statement coverage of the reference by the corpus >= 95%
#           (uncovered lines are listed in this suite's output/evidence)
#   C9.1.3  a seeded random trace generator produces 10,000 structurally
#           valid traces accepted by the reference without exception
set -u
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
ROOT=$PWD
PY=$ROOT/.tools/bin/python3
PACKS=$ROOT/internal/reconcile/packs
VECTORS=$ROOT/test/vectors/reconcile
export PYTHONPATH=$ROOT/ref/python
fail=0

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad() { say "$1" FAIL "$2"; fail=1; }

if [ ! -x "$PY" ]; then
    echo "missing pinned python at .tools/bin/python3: run make tools" >&2
    exit 2
fi

# --- C9.1.1: corpus --------------------------------------------------------
# The rule packs are inputs to every corpus trace; a pack that fails to load
# makes the corpus run fail and is reported under this check.
pout=$("$PY" -m refreconcile.corpus packcheck "$PACKS" 2>&1); prc=$?
echo "$pout"
ntrace=$(find "$VECTORS" -name '*.jsonl' | wc -l)
cout=$("$PY" -m refreconcile.corpus corpus "$VECTORS" --packs "$PACKS" 2>&1)
crc=$?
echo "$cout"
if [ "$prc" -ne 0 ]; then
    bad C9.1.1 "rule packs failed to load: $(echo "$pout" | tail -1)"
elif [ "$ntrace" -lt 80 ]; then
    bad C9.1.1 "only $ntrace corpus traces (spec requires >= 80)"
elif [ "$crc" -ne 0 ]; then
    bad C9.1.1 "$(echo "$cout" | tail -1)"
else
    pass C9.1.1
fi

# --- C9.1.2: statement coverage >= 95% -------------------------------------
vout=$("$PY" -m refreconcile.corpus coverage "$VECTORS" --packs "$PACKS" \
    --min 95 2>&1); vrc=$?
echo "$vout"
if [ "$vrc" -eq 0 ]; then
    pass C9.1.2
else
    bad C9.1.2 "$(echo "$vout" | tail -1)"
fi

# --- C9.1.3: 10,000 seeded random traces accepted ---------------------------
rout=$("$PY" -m refreconcile.corpus randgen --count 10000 --seed 91009 \
    --packs "$PACKS" 2>&1); rrc=$?
echo "$rout"
if [ "$rrc" -eq 0 ]; then
    pass C9.1.3
else
    bad C9.1.3 "$(echo "$rout" | tail -1)"
fi

[ "$fail" -eq 0 ] && echo "M9.1 suite: all checks passed" \
    || echo "M9.1 suite: FAILURES" >&2
exit "$fail"
