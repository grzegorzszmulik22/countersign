#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# check.sh <chunk> — run one chunk's check suite (test/checks/check-<chunk>.sh),
# tee its output into evidence/<chunk>/<UTC>/ and write result.json there.
# Exit code is the suite's exit code.
set -uo pipefail
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"

chunk=${1:?usage: check.sh <chunk>}
root=$(git rev-parse --show-toplevel)
cd "$root"

suite="test/checks/check-${chunk}.sh"
if [ ! -f "$suite" ]; then
    echo "no check suite at $suite" >&2
    exit 2
fi

ts=$(date -u +%Y%m%dT%H%M%SZ)
dir="evidence/$chunk/$ts"
while [ -e "$dir" ]; do ts=$(date -u +%Y%m%dT%H%M%SZ); sleep 1; dir="evidence/$chunk/$ts"; done
mkdir -p "$dir"

git_commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)
git_dirty=no
[ -n "$(git status --porcelain 2>/dev/null)" ] && git_dirty=yes

start_ns=$(date +%s%N)
CS_CHECK_RUNNING=$chunk bash "$suite" 2>&1 | tee "$dir/output.log"
code=${PIPESTATUS[0]}
end_ns=$(date +%s%N)
duration_ms=$(( (end_ns - start_ns) / 1000000 ))

cat > "$dir/result.json" <<EOF
{
  "chunk": "$chunk",
  "command": "make check-$chunk (test/checks/check-$chunk.sh)",
  "started_utc": "$ts",
  "duration_ms": $duration_ms,
  "exit_code": $code,
  "git_commit": "$git_commit",
  "git_dirty": "$git_dirty"
}
EOF

tools/sysinfo.sh > "$dir/sysinfo.txt" 2>/dev/null || true

if [ "$code" -eq 0 ]; then
    echo "check-$chunk: PASS (evidence: $dir)"
else
    echo "check-$chunk: FAIL (exit $code, evidence: $dir)" >&2
fi
exit "$code"
