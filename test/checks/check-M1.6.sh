#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# check-M1.6.sh — mutation suite and measurements.
#   C1.6.1  200 seeded valid bundles: both verifiers CLEAN-class, identical.
#   C1.6.2  >=1,000 mutants (>=100/class, fixed seed): both verifiers reject,
#           first error in the 03 §11 expected set, identical code sets,
#           class 5 never CLEAN*, no mutant byte-equal to its original.
#   C1.6.3  Measurements MM1.1-MM1.5 per 06 §12 against targets.
set -uo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

PY="$root/.tools/python/bin/python3"
GO="$root/.tools/bin/go"
if [ ! -x "$PY" ] || [ ! -x "$GO" ]; then
    echo "pinned toolchain missing: run make tools" >&2
    exit 2
fi
export PATH="$root/.tools/bin:$PATH"

WORK="$root/.check-work/m16"
mkdir -p "$WORK/suite"
fail=0

# C1.6.1 + C1.6.2: one suite run produces both (plus MM1.4/MM1.5 inputs).
if "$PY" test/mutgen/run_suite.py --seed "${M16_SEED:-1}" --bundles 200 \
        --per-class 112 --pool 48 --out "$WORK/suite"; then
    s161=$("$PY" -c 'import json,sys;print(json.load(open(sys.argv[1]))["C1.6.1"])' \
        "$WORK/suite/status.json" 2>/dev/null || echo False)
    s162=$("$PY" -c 'import json,sys;print(json.load(open(sys.argv[1]))["C1.6.2"])' \
        "$WORK/suite/status.json" 2>/dev/null || echo False)
else
    s161=False; s162=False
fi
if [ "$s161" = "True" ]; then
    echo "CHECK C1.6.1 PASS  200 seeded bundles CLEAN-class in both verifiers"
else
    echo "CHECK C1.6.1 FAIL  seeded clean-bundle differential"
    fail=1
fi
if [ "$s162" = "True" ]; then
    echo "CHECK C1.6.2 PASS  mutants rejected, first error in-class, verifiers agree"
else
    echo "CHECK C1.6.2 FAIL  mutation differential"
    fail=1
fi

# C1.6.3: measurements MM1.1-MM1.5 (05+ runs, median, CV, targets).
if "$PY" test/mutgen/measure.py --seed "${M16_SEED:-1}" \
        --mutations "$WORK/suite/mutations.json"; then
    echo "CHECK C1.6.3 PASS  measurements MM1.1-MM1.5 recorded, targets met"
else
    echo "CHECK C1.6.3 FAIL  measurements MM1.1-MM1.5"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "check-M1.6: suite PASS"
else
    echo "check-M1.6: suite FAIL" >&2
fi
exit "$fail"
