#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# offline.sh on|off — `make offline-on` / `make offline-off`: node-level rules
# that drop egress from each kind node to anything outside the cluster's own
# ranges (pod CIDR, service CIDR, the node's docker network(s), loopback,
# established return traffic). This makes the workshop hermetic: nothing on a
# node — and therefore no pod — can reach the public internet.
#
# A desired-state flag at $CLUSTER_STATE/offline-on lets cluster-up re-apply
# the rules to (re)created nodes. Idempotent in both directions.
set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=lib.sh
. tools/cluster/lib.sh

cmd=${1:?usage: offline.sh on|off}
cluster_lock
mkdir -p "$CLUSTER_STATE"
FLAG="$CLUSTER_STATE/offline-on"

# Allowed egress destinations for one node: its docker network subnets plus
# the cluster pod/service CIDRs.
node_cidrs() { # node -> space-separated CIDR list
    local n=$1 nets s
    nets=$(docker inspect "$n" -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}')
    for s in $nets; do
        docker network inspect "$s" -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null
    done | tr '\n' ' '
    echo "$POD_CIDR $SVC_CIDR"
}

apply_rules() { # node -> install CS_OFFLINE chain + OUTPUT jump
    local n=$1 cidrs
    cidrs=$(node_cidrs "$n")
    docker exec -i "$n" bash -s -- "$cidrs" <<'EOS'
set -e
cidrs=$1
for fam in iptables ip6tables; do
    command -v "$fam" >/dev/null 2>&1 || continue
    "$fam" -N CS_OFFLINE 2>/dev/null || true
    "$fam" -F CS_OFFLINE
    "$fam" -A CS_OFFLINE -o lo -j RETURN
    "$fam" -A CS_OFFLINE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    for c in $cidrs; do
        case "$c:$fam" in
            *.*:iptables|*:*:ip6tables) "$fam" -A CS_OFFLINE -d "$c" -j RETURN ;;
        esac
    done
    "$fam" -A CS_OFFLINE -j DROP
    "$fam" -C OUTPUT -j CS_OFFLINE 2>/dev/null || "$fam" -I OUTPUT 1 -j CS_OFFLINE
done
EOS
}

remove_rules() { # node -> remove jump + chain
    local n=$1
    docker exec -i "$n" bash -s <<'EOS'
set -e
for fam in iptables ip6tables; do
    command -v "$fam" >/dev/null 2>&1 || continue
    while "$fam" -C OUTPUT -j CS_OFFLINE 2>/dev/null; do
        "$fam" -D OUTPUT -j CS_OFFLINE
    done
    "$fam" -F CS_OFFLINE 2>/dev/null || true
    "$fam" -X CS_OFFLINE 2>/dev/null || true
done
EOS
}

case "$cmd" in
    on)
        touch "$FLAG"
        ns=$(nodes || true)
        [ -n "$ns" ] || { echo "offline-on: no nodes (flag recorded)"; exit 0; }
        for n in $ns; do apply_rules "$n"; echo "offline-on: rules on $n"; done
        ;;
    off)
        for n in $(nodes || true); do remove_rules "$n"; echo "offline-off: rules removed on $n"; done
        rm -f "$FLAG"
        ;;
    *) echo "usage: offline.sh on|off" >&2; exit 2 ;;
esac
