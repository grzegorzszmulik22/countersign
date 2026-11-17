#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M0.5 (check, sabotage and evidence tooling).
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

# --- C0.5.1: dummy chunk with passing suite + real sabotage -----------------
o1=$("$MAKE" check-DUMMY1 2>&1); c1=$?
o2=$("$MAKE" sabotage-DUMMY1 2>&1); c2=$?
if [ "$c1" -eq 0 ] && [ "$c2" -eq 0 ]; then
    pass C0.5.1
else
    bad C0.5.1 "check-DUMMY1=$c1 sabotage-DUMMY1=$c2: $(echo "$o1$o2" | tail -3 | tr '\n' ' ')"
fi

# --- C0.5.2: blind suite -> sabotage exits non-zero and names the patch -----
o=$("$MAKE" sabotage-DUMMY2 2>&1); c=$?
if [ "$c" -ne 0 ] && echo "$o" | grep -q 'corrupt-greeting'; then
    pass C0.5.2
elif [ "$c" -eq 0 ]; then
    bad C0.5.2 "sabotage-DUMMY2 returned green on an uncaught sabotage"
else
    bad C0.5.2 "non-zero exit but uncaught patch not named: $(echo "$o" | tail -3 | tr '\n' ' ')"
fi

# --- C0.5.3: one-byte change in a FROZEN-listed file breaks make regress ----
f=$(awk '{print $2}' spec/FROZEN.sha256 2>/dev/null | head -1)
if [ -z "$f" ] || [ ! -f "$f" ]; then
    bad C0.5.3 "no readable file listed in spec/FROZEN.sha256"
else
    cp "$f" /tmp/c053.$$
    printf 'x' >> "$f"
    o=$("$MAKE" regress 2>&1); c=$?
    mv /tmp/c053.$$ "$f"
    if [ "$c" -ne 0 ] && echo "$o" | grep -qi 'frozen\|FROZEN'; then
        # Restored: the frozen hashes must match again. C0.5.3 asks only that
        # tampering makes regress fail; a full second `make regress` here
        # recursed (regress runs M0.2, whose C0.2.2 runs check-M0 and so this
        # suite again) into seven nested regressions on one host.
        if tools/verify-frozen.sh >/tmp/c053r.$$ 2>&1; then
            pass C0.5.3
        else
            bad C0.5.3 "frozen hashes still differ after restore: $(tail -3 /tmp/c053r.$$ | tr '\n' ' ')"
        fi
        rm -f /tmp/c053r.$$
    else
        bad C0.5.3 "regress did not fail on tampered frozen file (exit $c)"
    fi
fi

# --- C0.5.4: evidence holds command, exit, duration, git commit, output -----
# Inspect the evidence dir the C0.5.1 check-DUMMY1 run actually reported.
# (ls -dt picks the newest DUMMY1 dir by mtime, but sabotage-DUMMY1 also
# writes evidence/DUMMY1/<ts>/sabotage — a race made this flaky.)
ev=$(echo "$o1" | grep -oE 'evidence/DUMMY1/[0-9A-Z]+' | head -1)
[ -n "$ev" ] && ev="$ev/"
if [ -z "$ev" ] || [ ! -d "$ev" ]; then
    bad C0.5.4 "no evidence dir for DUMMY1 (from check-DUMMY1 output)"
else
    ok=1
    for field in '"command"' '"exit_code"' '"duration_ms"' '"git_commit"'; do
        grep -q "$field" "$ev/result.json" 2>/dev/null || { ok=0; echo "missing $field in $ev/result.json"; }
    done
    [ -s "$ev/output.log" ] || { ok=0; echo "missing/nonempty output.log"; }
    [ "$ok" -eq 1 ] && pass C0.5.4 || bad C0.5.4 "evidence incomplete in $ev"
fi

[ "$fail" -eq 0 ] && echo "M0.5 suite: all checks passed" || echo "M0.5 suite: FAILURES" >&2
exit "$fail"
