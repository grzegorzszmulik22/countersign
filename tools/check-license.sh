#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# check-license.sh — every covered source file must carry an Apache-2.0 SPDX
# header in its first lines. Covered: tracked or untracked (non-ignored)
# *.go, *.sh, *.py, *.mk, Makefile, *.yml, *.yaml — excluding spec/, evidence/
# and test/vectors/ (data).
set -uo pipefail

cd "$(dirname "$0")/.."

files=$(git ls-files -co --exclude-standard -- \
    '*.go' '*.sh' '*.py' '*.mk' 'Makefile' '*.yml' '*.yaml' \
    ':(exclude)spec/**' ':(exclude)evidence/**' ':(exclude)test/vectors/**')

missing=()
while IFS= read -r f; do
    [ -n "$f" ] || continue
    [ -f "$f" ] || continue
    head -8 "$f" | grep -q 'SPDX-License-Identifier: Apache-2.0' || missing+=("$f")
done <<< "$files"

if [ "${#missing[@]}" -gt 0 ]; then
    printf 'missing Apache-2.0 SPDX header: %s\n' "${missing[@]}" >&2
    exit 1
fi
echo "license headers: ok"
exit 0
