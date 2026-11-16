#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# offline.sh on|off — `make offline-on` / `make offline-off`: node-level rules
# that drop egress from each kind node to anything that is not the cluster
# itself, in BOTH address families. Allowed: loopback, established/related
# return traffic, the other kind nodes' own addresses, the pod and service
# CIDRs, and (IPv6 only) link-local + link-scoped multicast so neighbour
# discovery keeps working. Everything else is dropped — the host side of the
# docker bridge included — so neither a node nor a pod can reach the host,
# the tailnet, or the public internet.
#
# The CS_OFFLINE chain is jumped from OUTPUT and FORWARD: OUTPUT covers the
# node's own traffic (and hostNetwork pods, which share the node netns);
# FORWARD covers egress from regular pods, whose packets are routed through
# the node rather than originating from it.
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

# Allowed egress destinations, resolved fresh on every apply: the cluster
# pod/service CIDRs plus every kind node container's own addresses on its
# docker network(s) — never the whole subnets, which would whitelist the
# host side of the bridge as well.
allowlist() { # -> space-separated IPs and CIDRs, both families
    local n
    for n in $(nodes); do
        docker inspect "$n" -f '{{range $k,$v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{$v.GlobalIPv6Address}}{{"\n"}}{{end}}'
    done | tr ' \n' ' '
    echo "$POD_CIDR $SVC_CIDR"
}

apply_rules() { # node -> install CS_OFFLINE chain + OUTPUT/FORWARD jumps
    local n=$1 cidrs
    cidrs=$(allowlist)
    docker exec -i "$n" bash -s -- "$cidrs" <<'EOS'
set -e
cidrs=$1
for fam in iptables ip6tables; do
    command -v "$fam" >/dev/null 2>&1 || continue
    "$fam" -N CS_OFFLINE 2>/dev/null || true
    "$fam" -F CS_OFFLINE
    "$fam" -A CS_OFFLINE -o lo -j RETURN
    "$fam" -A CS_OFFLINE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    if [ "$fam" = ip6tables ]; then
        "$fam" -A CS_OFFLINE -d fe80::/10 -j RETURN
        "$fam" -A CS_OFFLINE -d ff02::/16 -j RETURN
    fi
    for c in $cidrs; do
        case "$c:$fam" in
            *.*:iptables|*:*:ip6tables) "$fam" -A CS_OFFLINE -d "$c" -j RETURN ;;
        esac
    done
    "$fam" -A CS_OFFLINE -j DROP
    for hook in OUTPUT FORWARD; do
        "$fam" -C $hook -j CS_OFFLINE 2>/dev/null || "$fam" -I $hook 1 -j CS_OFFLINE
    done
done
EOS
}

remove_rules() { # node -> remove jumps + chain
    local n=$1
    docker exec -i "$n" bash -s <<'EOS'
set -e
for fam in iptables ip6tables; do
    command -v "$fam" >/dev/null 2>&1 || continue
    for hook in OUTPUT FORWARD; do
        while "$fam" -C $hook -j CS_OFFLINE 2>/dev/null; do
            "$fam" -D $hook -j CS_OFFLINE
        done
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
