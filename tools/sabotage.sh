#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# sabotage.sh <chunk> — apply each patch in test/sabotage/<chunk>/ to a scratch
# copy of the repo, commit it there, and run `make check-<chunk>`. Every patch
# must make the check suite exit non-zero (06-agent-loop.md §4). Reports which
# check IDs caught each sabotage. Exits non-zero if any patch leaves the suite
# green, naming the uncaught patches.
set -uo pipefail
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"

chunk=${1:?usage: sabotage.sh <chunk>}
root=$(git rev-parse --show-toplevel)
cd "$root"

patchdir="test/sabotage/$chunk"
if [ ! -d "$patchdir" ] || ! ls "$patchdir"/*.patch >/dev/null 2>&1; then
    echo "no sabotage patches in $patchdir" >&2
    exit 2
fi

ts=$(date -u +%Y%m%dT%H%M%SZ)
evdir="evidence/$chunk/$ts/sabotage"
mkdir -p "$evdir"

uncaught=()
caught_count=0
for patch in "$patchdir"/*.patch; do
    name=$(basename "$patch" .patch)
    scratch="$root/.check-work/sabotage-$chunk-$name"
    rm -rf "$scratch"
    mkdir -p "$scratch"
    # Copy tracked content and the object store; reuse installed tools by symlink.
    git ls-files -zc | tar --null -cf - --files-from=- | tar -xf - -C "$scratch"
    cp -a .git "$scratch/.git"
    ln -sfn "$root/.tools" "$scratch/.tools"
    if ! git -C "$scratch" apply --whitespace=nowarn "$root/$patch" 2>"$evdir/$name.apply.log"; then
        echo "SABOTAGE $name: patch does not apply" >&2
        cat "$evdir/$name.apply.log" >&2
        uncaught+=("$name (patch does not apply)")
        continue
    fi
    git -C "$scratch" add -A >/dev/null 2>&1
    git -C "$scratch" -c user.name=sabotage -c user.email=sabotage@localhost \
        commit --no-verify -qm "sabotage: $name" >/dev/null 2>&1
    log="$evdir/$name.log"
    ( cd "$scratch" && "${MAKE:-make}" "check-$chunk" ) > "$log" 2>&1
    code=$?
    if [ "$code" -eq 0 ]; then
        echo "SABOTAGE $name: UNCAUGHT — check-$chunk stayed green" >&2
        uncaught+=("$name")
    elif ! grep -q '^CHECK .* FAIL' "$log"; then
        # Non-zero without a red CHECK line = the suite did not run (missing)
        # or died another way; that is a harness error, not a catch.
        echo "SABOTAGE $name: ERROR — suite produced no failing check (exit $code)" >&2
        uncaught+=("$name (suite error)")
    else
        caught_count=$((caught_count + 1))
        caught_by=$(grep -oE '^CHECK [A-Za-z0-9_.-]+ FAIL' "$log" | awk '{print $2}' | sort -u | tr '\n' ' ')
        echo "SABOTAGE $name: caught (exit $code)${caught_by:+ by $caught_by}"
    fi
done

echo "sabotage-$chunk: $caught_count caught, ${#uncaught[@]} uncaught (evidence: $evdir)"
if [ "${#uncaught[@]}" -gt 0 ]; then
    printf 'UNCAUGHT sabotage: %s\n' "${uncaught[@]}" >&2
    exit 1
fi
exit 0
