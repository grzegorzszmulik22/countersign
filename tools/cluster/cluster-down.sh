#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# cluster-down.sh — `make cluster-down`: delete the kind cluster `countersign`
# and nothing else. Scoped strictly by name (06 §11; M0.2 denied list: no
# prune, no delete command not scoped to this cluster). Idempotent.
set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=lib.sh
. tools/cluster/lib.sh

cluster_lock

if cluster_exists; then
    kind delete cluster --name "$CLUSTER"
    rm -f "$KUBECONFIG"
    echo "cluster-down: '$CLUSTER' deleted"
else
    echo "cluster-down: cluster '$CLUSTER' absent (idempotent)"
fi
