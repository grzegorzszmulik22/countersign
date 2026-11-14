#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# images.sh — `make images`: pull every pinned image by digest, tag it, and
# load it into the kind cluster when the cluster exists (06 §11: checks are
# hermetic; images are pulled once, pinned by digest, and loaded into kind).
#
# IMAGES_SKIP_PULL=1 loads whatever is already in the local docker store
# without pulling (used by cluster-up when the offline flag may be set).
set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=lib.sh
. tools/cluster/lib.sh

SKIP_PULL=${IMAGES_SKIP_PULL:-0}
CLUSTER_NAME=$CLUSTER   # may be overridden below
cluster_lock

pull_and_tag() { # $1 digest-ref  $2 tag
    if [ "$SKIP_PULL" != "1" ]; then
        docker pull -q "$1" >/dev/null
    fi
    if ! docker image inspect "$1" >/dev/null 2>&1; then
        echo "images: $1 not in local store (pull skipped or unavailable)" >&2
        return 1
    fi
    docker tag "$1" "$2" >/dev/null 2>&1 \
        || docker tag "$(docker image inspect -f '{{.Id}}' "$1")" "$2" >/dev/null
}

if [ "$SKIP_PULL" = "1" ]; then echo "images: skip-pull; tagging local digests"; else echo "images: digest refs -> tags"; fi
for i in "${!IMAGE_REFS[@]}"; do
    pull_and_tag "${IMAGE_REFS[$i]}" "${IMAGE_TAGS[$i]}"
    echo "  ${IMAGE_TAGS[$i]}"
done
if [ "$SKIP_PULL" != "1" ]; then
    docker pull -q "$KIND_NODE_IMAGE" >/dev/null || true
fi

if ! cluster_exists; then
    echo "images: cluster '$CLUSTER_NAME' absent; digests pulled, load skipped"
    exit 0
fi

node_have() { # node tag -> 0 when containerd already holds the tag
    docker exec "$1" ctr -n k8s.io images ls -q 2>/dev/null \
        | grep -qxF "$2"
}

for tag in "${IMAGE_TAGS[@]}"; do
    for n in $(nodes); do
        if node_have "$n" "$tag"; then
            echo "images: $tag already on $n"
        else
            # `kind load` fails on multi-arch indexes (ctr import --all-platforms
            # expects every platform's blobs). docker save | ctr import is the
            # equivalent scoped to the node's own platform.
            echo "images: load $tag -> $n"
            docker save "$tag" | docker exec -i "$n" \
                ctr -n k8s.io images import --digests - >/dev/null
        fi
    done
done
echo "images: done"
