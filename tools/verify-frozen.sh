#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# verify-frozen.sh — enforce 06-agent-loop.md §7: every file listed in
# spec/FROZEN.sha256 must hash-match, and every spec source file (spec/0*.md,
# spec/milestones/*.md) must be listed there. Adding new files under
# test/vectors/ is allowed by the spec, so vector directories are verified
# only for the files listed.
set -uo pipefail

cd "$(dirname "$0")/.."
list=spec/FROZEN.sha256

[ -f "$list" ] || { echo "frozen: spec/FROZEN.sha256 missing"; exit 1; }

rc=0
if sha256sum --check --quiet < "$list" 2>&1; then
    echo "frozen: hashes match"
else
    echo "frozen: HASH MISMATCH" >&2
    rc=1
fi

# Spec files are frozen "from the start": any unlisted spec source file is a
# violation (they change only through §6 change requests).
listed=$(awk '{print $2}' "$list" | sort -u)
current=$(ls spec/0*.md spec/milestones/*.md 2>/dev/null | sort -u)
unlisted=$(comm -23 <(echo "$current") <(echo "$listed") || true)
if [ -n "$unlisted" ]; then
    echo "frozen: unlisted spec file(s): $unlisted" >&2
    rc=1
fi

exit "$rc"
