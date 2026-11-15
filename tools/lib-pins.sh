#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Shared pin bookkeeping for install-tools.sh and verify-versions.sh.

CS_REQUIRED_PINS=(
    GO_VERSION GO_TARBALL GO_SHA256
    KIND_VERSION KIND_SHA256
    KUBECTL_VERSION KUBECTL_SHA256
    HELM_VERSION HELM_SHA256
    GOLANGCI_LINT_VERSION GOLANGCI_LINT_SHA256
    PYTHON_VERSION PYTHON_STANDALONE_BUILD PYTHON_TARBALL PYTHON_SHA256
    NODE_VERSION NODE_TARBALL NODE_SHA256
    LIBATOMIC_VERSION LIBATOMIC_DEB LIBATOMIC_URL LIBATOMIC_SHA256
    CRYPTOGRAPHY_VERSION CRYPTOGRAPHY_WHEEL CRYPTOGRAPHY_WHEEL_URL CRYPTOGRAPHY_SHA256
    KIND_NODE_IMAGE
)

# pins_check_complete fails when any required variable is missing or empty —
# this is what makes the `unpinned-tool` sabotage red.
pins_check_complete() {
    local missing=()
    local v
    for v in "${CS_REQUIRED_PINS[@]}"; do
        [ -n "${!v:-}" ] || missing+=("$v")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        printf 'versions.env: missing required pin(s): %s\n' "${missing[*]}" >&2
        return 1
    fi
    return 0
}
