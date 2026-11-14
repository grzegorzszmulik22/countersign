#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# cluster-up.sh — `make cluster-up`: create the kind cluster `countersign`
# (one control-plane + two workers, Calico CNI installed from the pinned
# manifest, namespaces of 02 §8). Idempotent: an existing healthy cluster is
# kept; manifests are re-applied and readiness re-verified. Refuses to run
# when a foreign kind cluster exists — `countersign` must be the only kind
# cluster on this host (lane rule, 06 §11).
set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=lib.sh
. tools/cluster/lib.sh

cluster_lock
mkdir -p "$(dirname "$KUBECONFIG")"

foreign=$(kind get clusters 2>/dev/null | grep -vx "$CLUSTER" || true)
if [ -n "$foreign" ]; then
    echo "cluster-up: other kind cluster(s) present: $foreign" >&2
    echo "cluster-up: the '$CLUSTER' cluster must be the only one here; refusing" >&2
    exit 1
fi

if cluster_exists; then
    echo "cluster-up: cluster '$CLUSTER' already exists (idempotent path)"
else
    echo "cluster-up: kind create cluster '$CLUSTER'"
    kind create cluster --name "$CLUSTER" \
        --config deploy/kind/kind-config.yaml \
        --image "$KIND_NODE_IMAGE" \
        --kubeconfig "$KUBECONFIG"
fi

# Verify the pinned CNI manifest has not drifted, then install.
echo "$CALICO_MANIFEST_SHA256  $CALICO_MANIFEST" | sha256sum -c --quiet
kubectl apply -f "$CALICO_MANIFEST" >/dev/null
kubectl apply -f deploy/kind/namespaces.yaml >/dev/null

# Load locally present images before waiting so CNI/test pods never pull.
IMAGES_SKIP_PULL=1 tools/cluster/images.sh || true

kubectl wait --for=condition=Ready node --all --timeout=300s >/dev/null
for sel in k8s-app=calico-node k8s-app=calico-kube-controllers k8s-app=kube-dns; do
    kubectl -n kube-system wait --for=condition=Ready pod -l "$sel" --timeout=300s >/dev/null
done

# If offline mode was requested earlier it is desired state: re-apply to any
# (re)created nodes.
if [ -f "$CLUSTER_STATE/offline-on" ]; then
    echo "cluster-up: offline flag set; re-applying node egress rules"
    tools/cluster/offline.sh on
fi

echo "cluster-up: ready"
kubectl get nodes -o wide
