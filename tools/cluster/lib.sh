#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for the M0.2 cluster scripts. Sourced, never executed.
# The kind cluster is a host-wide singleton named "countersign" (lane rule):
# every mutating script takes a host-wide flock so two lanes/regress runs
# cannot drive it concurrently.

CLUSTER=${CLUSTER:-countersign}
CLUSTER_STATE=${CLUSTER_STATE:-$HOME/.cache/countersign}
export CLUSTER CLUSTER_STATE

# Caller must have cd'd to the repository root before sourcing.
ROOT=$PWD
export PATH="$ROOT/.tools/bin:$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
export KUBECONFIG=${KUBECONFIG:-$ROOT/.kube/countersign}

# shellcheck source=../versions.env
. tools/versions.env
# shellcheck source=../images.env
. tools/images.env

# Serialize cluster mutations host-wide. Scripts skip locking when the caller
# (a check suite) already holds the lock (CS_CLUSTER_LOCK_HELD=1).
cluster_lock() {
    [ "${CS_CLUSTER_LOCK_HELD:-}" = "1" ] && return 0
    mkdir -p "$CLUSTER_STATE"
    exec 8>"$CLUSTER_STATE/cluster.lock"
    flock -w 3600 8 || { echo "could not acquire cluster lock" >&2; exit 1; }
    export CS_CLUSTER_LOCK_HELD=1
}

nodes() { kind get nodes --name "$CLUSTER" 2>/dev/null; }

cluster_exists() { kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; }

kcfg_val() { # kcfg_val podSubnet|serviceSubnet -> value from kind-config.yaml
    grep -E "^  $1:" deploy/kind/kind-config.yaml | awk '{print $2}' | tr -d '"'
}
POD_CIDR=$(kcfg_val podSubnet)
SVC_CIDR=$(kcfg_val serviceSubnet)
: "${POD_CIDR:?podSubnet missing from deploy/kind/kind-config.yaml}"
: "${SVC_CIDR:?serviceSubnet missing from deploy/kind/kind-config.yaml}"
