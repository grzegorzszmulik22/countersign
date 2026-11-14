#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M0.1 (repository and toolchain).
# Emits one "CHECK <id> PASS|FAIL" line per numbered check; exits non-zero if
# any check fails.
set -u
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
ROOT=$PWD
MAKE=${MAKE:-make}
fail=0

say() { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad() { say "$1" FAIL "$2"; fail=1; }

# --- C0.1.1: fresh clone — make tools lint test exits 0 ---------------------
clone=$(mktemp -d)
if git clone --quiet --local "$ROOT" "$clone/repo" 2>"$clone/clone.err"; then
    if ( cd "$clone/repo" && "$MAKE" tools >/dev/null 2>&1 \
            && "$MAKE" lint >>"$clone/log" 2>&1 \
            && "$MAKE" test >>"$clone/log" 2>&1 ); then
        pass C0.1.1
    else
        bad C0.1.1 "make tools/lint/test failed in fresh clone: $(tail -3 "$clone/log" 2>/dev/null | tr '\n' ' ')"
    fi
else
    bad C0.1.1 "git clone failed: $(cat "$clone/clone.err")"
fi
rm -rf "$clone"

# --- C0.1.2: every pinned tool reports the pinned version -------------------
if tools/verify-versions.sh >/tmp/c012.$$ 2>&1; then
    pass C0.1.2
else
    bad C0.1.2 "$(tail -3 /tmp/c012.$$ | tr '\n' ' ')"
fi
rm -f /tmp/c012.$$

# --- C0.1.3: git status --porcelain empty after make lint -------------------
if ! "$MAKE" lint >/tmp/c013.$$ 2>&1; then
    bad C0.1.3 "make lint failed: $(tail -3 /tmp/c013.$$ | tr '\n' ' ')"
else
    dirty=$(git status --porcelain -- . ':(exclude)evidence')
    if [ -z "$dirty" ]; then
        pass C0.1.3
    else
        bad C0.1.3 "lint left the tree dirty: $(echo "$dirty" | head -3 | tr '\n' ' ')"
    fi
fi
rm -f /tmp/c013.$$

# --- C0.1.4: countersign.dev and the module path only in internal/names/ ----
# 'countersign.dev' may appear in Go sources only under internal/names/.
offenders=$(git ls-files -co --exclude-standard -- '*.go' \
    | xargs grep -l 'countersign\.dev' 2>/dev/null \
    | grep -v '^internal/names/' || true)
# The module path may appear in Go sources only inside internal/names/ or as a
# quoted import path.
modoff=$(git ls-files -co --exclude-standard -- '*.go' \
    | xargs grep -n 'github\.com/countersign/countersign' 2>/dev/null \
    | grep -v '^internal/names/' \
    | grep -v '"github\.com/countersign/countersign' || true)
if [ -z "$offenders" ] && [ -z "$modoff" ]; then
    pass C0.1.4
else
    bad C0.1.4 "stray name strings: $offenders $modoff"
fi

# --- C0.1.5: make sysinfo prints the six required fields --------------------
if info=$("$MAKE" sysinfo 2>/dev/null); then
    ok=1
    for field in kernel cpu_model cores memory docker arch; do
        echo "$info" | grep -qE "^${field}: .+" || { ok=0; echo "missing field: $field"; }
    done
    [ "$ok" -eq 1 ] && pass C0.1.5 || bad C0.1.5 "sysinfo missing fields"
else
    bad C0.1.5 "make sysinfo failed"
fi

[ "$fail" -eq 0 ] && echo "M0.1 suite: all checks passed" || echo "M0.1 suite: FAILURES" >&2
exit "$fail"
