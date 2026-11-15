#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# verify-versions.sh — assert every pin in tools/versions.env is present and
# that every installed tool under ./.tools reports exactly the pinned version.
# Used by `make tools` (post-install gate) and by the M0.1 check suite.
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD
TOOLS=$ROOT/.tools

# shellcheck source=versions.env
. tools/versions.env
. tools/lib-pins.sh
pins_check_complete || exit 1

fail=0
chk() { # <label> <expected-substring> <actual-output>
    if printf '%s' "$3" | grep -qF "$2"; then
        printf 'version ok: %s\n' "$1"
    else
        printf 'version MISMATCH: %s (want %s, got %s)\n' "$1" "$2" "$3" >&2
        fail=1
    fi
}

chk go            "go${GO_VERSION} "              "$("$TOOLS/bin/go" version 2>&1)"
chk kind          "$KIND_VERSION"                 "$("$TOOLS/bin/kind" version 2>&1)"
chk kubectl       "$KUBECTL_VERSION"              "$("$TOOLS/bin/kubectl" version --client 2>&1)"
chk helm          "$HELM_VERSION"                 "$("$TOOLS/bin/helm" version 2>&1)"
chk golangci-lint "${GOLANGCI_LINT_VERSION#v} "   "$("$TOOLS/bin/golangci-lint" version 2>&1)"
chk python        "Python $PYTHON_VERSION"        "$("$TOOLS/python/bin/python3" --version 2>&1)"
chk node          "$NODE_VERSION"                 "$("$TOOLS/node/bin/node" --version 2>&1)"
# npm is bundled with the pinned node release; assert it runs and reports a
# semver (the node pin determines the npm version).
npmv="$(PATH="$TOOLS/bin:$PATH" "$TOOLS/bin/npm" --version 2>&1)"
if printf '%s' "$npmv" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+'; then
    printf 'version ok: npm %s\n' "$npmv"
else
    printf 'version MISMATCH: npm (bundled with %s, got %s)\n' "$NODE_VERSION" "$npmv" >&2
    fail=1
fi
chk cryptography  "$CRYPTOGRAPHY_VERSION"         "$("$TOOLS/python/bin/python3" -c 'import cryptography; print(cryptography.__version__)' 2>&1)"

# The wheel file pin must match the file we install from (cache).
cwheel="${CS_TOOLS_CACHE:-$HOME/.cache/countersign/tools}/$CRYPTOGRAPHY_WHEEL"
if [ -f "$cwheel" ]; then
    if echo "$CRYPTOGRAPHY_SHA256  $cwheel" | sha256sum -c --quiet; then
        echo "version ok: cryptography wheel sha256"
    else
        echo "sha256 MISMATCH: $CRYPTOGRAPHY_WHEEL" >&2
        fail=1
    fi
else
    echo "cryptography wheel not in cache ($cwheel)" >&2
    fail=1
fi

# Node image pin: format check only here; the image is pulled in M0.2.
if printf '%s' "$KIND_NODE_IMAGE" | grep -qE '^kindest/node:v[0-9.]+@sha256:[0-9a-f]{64}$'; then
    echo "version ok: kind node image pin format"
else
    echo "kind node image pin malformed: $KIND_NODE_IMAGE" >&2
    fail=1
fi

exit "$fail"
