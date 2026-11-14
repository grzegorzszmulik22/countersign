#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Check suite for chunk M0.2 (hermetic kind cluster).
# Emits one "CHECK <id> PASS|FAIL" line per numbered check; exits non-zero if
# any check fails.
#
# Checks (spec/milestones/M0-foundation.md):
#   C0.2.1  NetworkPolicy really enforced: deny-all egress blocks TCP, UDP and
#           DNS; after deletion all three succeed. Both workers + cross-node.
#   C0.2.2  `make offline-on` makes every kind node unable to reach a public
#           address and `make check-M0` still passes; `make offline-off`
#           restores connectivity.
#   C0.2.3  `make cluster-up` is idempotent and <= 5 min with images loaded.
#   C0.2.4  Probe+record /sys/kernel/btf/vmlinux and runtime classes on nodes.
#   C0.2.5  `make cluster-down` leaves every other docker container, image,
#           network and volume untouched.
#
# CS_M02_OFFLINE_INNER=1 marks a nested run inside C0.2.2's `make check-M0`:
# C0.2.2 then performs the node-offline probe only (no further recursion).
set -u
export PATH="$HOME/.local/bin:$HOME/.local/usr/bin:$PATH"
cd "$(dirname "$0")/../.."
ROOT=$PWD
export PATH="$ROOT/.tools/bin:$PATH"
export KUBECONFIG="$ROOT/.kube/countersign"
MAKE=${MAKE:-make}
INNER=${CS_M02_OFFLINE_INNER:-0}
CLUSTER=countersign
NS=netpol-test
PUBLIC_IP=1.1.1.1
PUBLIC_PORT=443
fail=0

say()  { printf 'CHECK %s %s%s\n' "$1" "$2" "${3:+ — $3}"; }
pass() { say "$1" PASS; }
bad()  { say "$1" FAIL "$2"; fail=1; }
note() { printf '  .. %s\n' "$*"; }

EVDIR=$(ls -dt evidence/M0.2/*/ 2>/dev/null | head -1 || true)
[ -n "${EVDIR:-}" ] || { EVDIR="evidence/M0.2/manual-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$EVDIR"; }

nodes() { kind get nodes --name "$CLUSTER" 2>/dev/null; }
k() { kubectl --kubeconfig "$KUBECONFIG" "$@"; }

# Serialize against other lanes/processes sharing this host's only cluster.
# Nested runs (inside this suite's own `make check-M0`/regress calls) skip the
# lock: their ancestor already holds it.
mkdir -p "$HOME/.cache/countersign"
if [ "${CS_CLUSTER_LOCK_HELD:-}" != "1" ]; then
    exec 9>"$HOME/.cache/countersign/cluster.lock"
    flock -w 3600 9 || { echo "could not acquire cluster lock" >&2; exit 2; }
    export CS_CLUSTER_LOCK_HELD=1
fi

# --------------------------------------------------------------------------
# Preamble: images pulled + loaded, cluster up. All checks need this.
# --------------------------------------------------------------------------
echo "== preamble: make images && make cluster-up =="
if ! "$MAKE" images 2>&1 || ! "$MAKE" cluster-up 2>&1; then
    for c in C0.2.1 C0.2.2 C0.2.3 C0.2.4 C0.2.5; do
        bad "$c" "cluster preamble failed (make images/cluster-up)"
    done
    exit 1
fi

# --- helpers ----------------------------------------------------------------
node_tcp_open() { # node ip port -> 0 when a TCP connection succeeds
    timeout 8 docker exec "$1" bash -c "exec 3<>/dev/tcp/$2/$3" 2>/dev/null
}

probe_tcp() { # client-pod server-ip -> 0 when HTTP fetch succeeds
    k -n "$NS" exec "$1" -- wget -T 4 -q -O- "http://$2:8080/" >/dev/null 2>&1
}
probe_udp() { # client-pod server-ip [retries] -> 0 when the UDP echo replies
    # agnhost netexec answers commands, not raw echo: send "echo <token>" and
    # require the token back. A bare "punt!" string is busybox nc reporting an
    # ICMP refusal, not a server reply, so it must not count as success.
    local out i n=${3:-1}
    for i in $(seq "$n"); do
        out=$(k -n "$NS" exec "$1" -- sh -c "echo 'echo cs-udp-probe' | timeout 8 nc -u -w 5 $2 8081" 2>/dev/null || true)
        case "$out" in *cs-udp-probe*) return 0;; esac
        sleep 1
    done
    return 1
}
probe_dns() { # client-pod -> 0 when cluster DNS resolves
    k -n "$NS" exec "$1" -- nslookup kubernetes.default.svc.cluster.local >/dev/null 2>&1
}

netpol_matrix() { # $1 = expect ("open"|"denied"); returns 0 when the matrix matches
    local want=$1 c ip ok=0 t u d
    for c in netpol-cli-w1 netpol-cli-w2; do
        for ip in "$S1" "$S2"; do
            probe_tcp "$c" "$ip" && t=open || t=blocked
            if [ "$want" = open ]; then probe_udp "$c" "$ip" 12 && u=open || u=blocked
            else probe_udp "$c" "$ip" 1 && u=open || u=blocked; fi
            if [ "$t" = "$want" ] && [ "$u" = "$want" ]; then
                note "$c -> $ip  tcp=$t udp=$u (want $want)"
            else
                note "MISMATCH $c -> $ip  tcp=$t udp=$u (want $want)"; ok=1
            fi
        done
        probe_dns "$c" && d=open || d=blocked
        if [ "$d" = "$want" ]; then note "$c dns=$d (want $want)";
        else note "MISMATCH $c dns=$d (want $want)"; ok=1; fi
    done
    return $ok
}

# --------------------------------------------------------------------------
# C0.2.1 — NetworkPolicy is really enforced
# --------------------------------------------------------------------------
echo "== C0.2.1: NetworkPolicy enforcement proof =="
c021=0
k create namespace "$NS" --dry-run=client -o yaml | k apply -f - >/dev/null
k -n "$NS" delete pods --all --wait --ignore-not-found >/dev/null 2>&1
cat <<EOF | k apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: netpol-srv-w1, namespace: $NS, labels: {app: netpol-srv}}
spec:
  nodeSelector: {kubernetes.io/hostname: countersign-worker}
  containers: [{name: srv, image: registry.k8s.io/e2e-test-images/agnhost:2.56,
    imagePullPolicy: IfNotPresent,
    args: ["netexec", "--http-port=8080", "--udp-port=8081"]}]
---
apiVersion: v1
kind: Pod
metadata: {name: netpol-srv-w2, namespace: $NS, labels: {app: netpol-srv}}
spec:
  nodeSelector: {kubernetes.io/hostname: countersign-worker2}
  containers: [{name: srv, image: registry.k8s.io/e2e-test-images/agnhost:2.56,
    imagePullPolicy: IfNotPresent,
    args: ["netexec", "--http-port=8080", "--udp-port=8081"]}]
---
apiVersion: v1
kind: Pod
metadata: {name: netpol-cli-w1, namespace: $NS, labels: {app: netpol-cli}}
spec:
  nodeSelector: {kubernetes.io/hostname: countersign-worker}
  containers: [{name: cli, image: busybox:1.37.0, imagePullPolicy: IfNotPresent,
    command: ["sleep", "3600"]}]
---
apiVersion: v1
kind: Pod
metadata: {name: netpol-cli-w2, namespace: $NS, labels: {app: netpol-cli}}
spec:
  nodeSelector: {kubernetes.io/hostname: countersign-worker2}
  containers: [{name: cli, image: busybox:1.37.0, imagePullPolicy: IfNotPresent,
    command: ["sleep", "3600"]}]
EOF
if ! k -n "$NS" wait --for=condition=Ready pod --all --timeout=180s >/dev/null 2>&1; then
    bad C0.2.1 "test pods did not become Ready"
else
    S1=$(k -n "$NS" get pod netpol-srv-w1 -o jsonpath='{.status.podIP}')
    S2=$(k -n "$NS" get pod netpol-srv-w2 -o jsonpath='{.status.podIP}')
    note "server pods: w1=$S1 w2=$S2"
    if [ -z "$S1" ] || [ -z "$S2" ]; then
        bad C0.2.1 "server pods have no IP"
    else
        note "applying deploy/kind/policies/deny-all-egress.yaml"
        k -n "$NS" apply -f deploy/kind/policies/deny-all-egress.yaml >/dev/null
        sleep 4
        netpol_matrix blocked || c021=1
        k -n "$NS" delete -f deploy/kind/policies/deny-all-egress.yaml >/dev/null
        sleep 8
        netpol_matrix open || c021=1
        if [ "$c021" -eq 0 ]; then pass C0.2.1
        else bad C0.2.1 "policy matrix mismatch (see MISMATCH lines)"; fi
    fi
fi
k -n "$NS" delete pods --all --wait --ignore-not-found >/dev/null 2>&1 || true

# --------------------------------------------------------------------------
# C0.2.4 — probe kernel BTF and runtime classes (record-only)
# --------------------------------------------------------------------------
echo "== C0.2.4: kernel/runtime probes =="
probe_json="$EVDIR/cluster-probes.json"
nodes_json=""
btf_all=true
for n in $(nodes); do
    if docker exec "$n" test -f /sys/kernel/btf/vmlinux 2>/dev/null; then btf=true; else btf=false; btf_all=false; fi
    nodes_json="${nodes_json:+$nodes_json, }{\"name\": \"$n\", \"btf_vmlinux\": $btf}"
    echo "node $n: /sys/kernel/btf/vmlinux present=$btf"
done
rcs=$(k get runtimeclasses -o name 2>/dev/null | sed 's|.*\/||' | tr '\n' ' ')
echo "runtimeclasses: ${rcs:-none}"
runtimes=""
for n in $(nodes); do
    rt=$(docker exec "$n" sh -c 'grep -oE "runtimes\.[a-zA-Z0-9_-]+" /etc/containerd/config.toml 2>/dev/null | sort -u | tr "\n" " "' 2>/dev/null || echo unknown)
    runtimes="${runtimes:+$runtimes; }$n: ${rt:-unknown}"
    echo "node $n containerd runtimes: ${rt:-unknown}"
done
printf '{\n  "check": "C0.2.4",\n  "nodes": [%s],\n  "runtimeclasses": "%s",\n  "containerd_runtimes": "%s",\n  "note": "recorded for M11 (BTF) and M4.7 (runtime classes); absence is data, not failure"\n}\n' \
    "$nodes_json" "${rcs:-none}" "$runtimes" > "$probe_json"
pass C0.2.4 "probes recorded to $probe_json"

# --------------------------------------------------------------------------
# C0.2.3 — cluster-up idempotent and <= 300 s, 5 samples
# --------------------------------------------------------------------------
echo "== C0.2.3: idempotent cluster-up timing =="
samples=()
c023=0
for i in 1 2 3 4 5; do
    t0=$(date +%s)
    if ! "$MAKE" cluster-up >/tmp/m02-c023.$i 2>&1; then c023=1; fi
    t1=$(date +%s)
    d=$((t1 - t0))
    samples+=("$d")
    note "run $i: ${d}s"
    [ "$d" -le 300 ] || c023=1
done
ready=$(k get nodes --no-headers 2>/dev/null | grep -c ' Ready ' || true)
[ "$ready" -eq 3 ] || { c023=1; note "only $ready/3 nodes Ready"; }
if [ "$c023" -eq 0 ]; then pass C0.2.3 "5 runs, samples: ${samples[*]}s"
else bad C0.2.3 "samples: ${samples[*]}s (limit 300s)"; fi

# --------------------------------------------------------------------------
# C0.2.2 — offline-on blocks node egress, check-M0 still passes, off restores
# --------------------------------------------------------------------------
echo "== C0.2.2: hermetic offline proof (inner=$INNER) =="
all_nodes_offline() { # 0 when every kind node cannot reach the public addr
    local n up=0
    for n in $(nodes); do
        node_tcp_open "$n" "$PUBLIC_IP" "$PUBLIC_PORT" && { note "node $n CAN reach $PUBLIC_IP"; up=1; }
    done
    return $up
}
all_nodes_online() { # 0 when every kind node can reach the public addr
    local n down=0
    for n in $(nodes); do
        node_tcp_open "$n" "$PUBLIC_IP" "$PUBLIC_PORT" || { note "node $n cannot reach $PUBLIC_IP"; down=1; }
    done
    return $down
}

if [ "$INNER" = "1" ]; then
    # Nested run inside an outer C0.2.2: offline-on is active; prove it and do
    # not recurse into another `make check-M0`.
    if all_nodes_offline; then pass C0.2.2 "inner run: all nodes offline"
    else bad C0.2.2 "inner run: a node reached $PUBLIC_IP under offline-on"; fi
else
    "$MAKE" offline-off >/dev/null 2>&1 || true
    if ! all_nodes_online; then
        bad C0.2.2 "node cannot reach $PUBLIC_IP before offline-on (cannot prove)"
    elif ! "$MAKE" offline-on; then
        bad C0.2.2 "make offline-on exited non-zero"
    elif ! all_nodes_offline; then
        "$MAKE" offline-off >/dev/null 2>&1 || true
        bad C0.2.2 "a node still reached $PUBLIC_IP after offline-on"
    elif ! CS_M02_OFFLINE_INNER=1 "$MAKE" check-M0; then
        "$MAKE" offline-off >/dev/null 2>&1 || true
        bad C0.2.2 "make check-M0 failed under offline-on"
    elif "$MAKE" offline-off && all_nodes_online; then
        pass C0.2.2 "nodes offline under offline-on; check-M0 green; restored"
    else
        bad C0.2.2 "node connectivity not restored after offline-off"
    fi
fi

# --------------------------------------------------------------------------
# C0.2.5 — cluster-down isolation, then restore
# --------------------------------------------------------------------------
echo "== C0.2.5: docker isolation of cluster-down =="
work=$(mktemp -d)
ours_volumes="$work/ours-volumes"
: > "$ours_volumes"
for cn in $(docker ps -aq --filter "label=io.x-k8s.kind.cluster=$CLUSTER" 2>/dev/null); do
    docker inspect -f '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{"\n"}}{{end}}' "$cn" >> "$ours_volumes" 2>/dev/null || true
done
sort -u -o "$ours_volumes" "$ours_volumes"
# cluster-down can only delete objects, so the isolation assertion is that
# every foreign object present before still exists after. Objects added or
# re-pointed by other lanes' concurrent activity are reported as notes, not
# failures. Images are compared by repo:tag name (a digest change means a
# foreign rebuild, which cluster-down cannot cause).
{ docker ps -a --format '{{.Names}}'; } | grep -vE '^countersign-' | sort > "$work/before.containers"
{ docker network ls --format '{{.Name}}'; } | grep -vxF 'kind' | sort > "$work/before.networks"
{ docker volume ls --format '{{.Name}}'; } | grep -vxF -f "$ours_volumes" | sort > "$work/before.volumes"
{ docker images --format '{{.Repository}}:{{.Tag}}'; } \
    | grep -vE 'kindest/node|quay\.io/calico/|registry\.k8s\.io/e2e-test-images/agnhost|busybox' \
    | sort -u > "$work/before.images"

t0=$(date +%s)
"$MAKE" cluster-down >/tmp/m02-c025.log 2>&1 || true
t1=$(date +%s)
note "cluster-down took $((t1 - t0))s"
left=$(kind get clusters 2>/dev/null | grep -xc "$CLUSTER" || true)
[ "$left" -eq 0 ] || bad C0.2.5 "cluster '$CLUSTER' still exists after cluster-down"

{ docker ps -a --format '{{.Names}}'; } | grep -vE '^countersign-' | sort > "$work/after.containers"
{ docker network ls --format '{{.Name}}'; } | grep -vxF 'kind' | sort > "$work/after.networks"
{ docker volume ls --format '{{.Name}}'; } | grep -vxF -f "$ours_volumes" | sort > "$work/after.volumes"
{ docker images --format '{{.Repository}}:{{.Tag}}'; } \
    | grep -vE 'kindest/node|quay\.io/calico/|registry\.k8s\.io/e2e-test-images/agnhost|busybox' \
    | sort -u > "$work/after.images"

isolation_ok=1
for kind_ in containers networks volumes images; do
    missing=$(comm -23 "$work/before.$kind_" "$work/after.$kind_")
    added=$(comm -13 "$work/before.$kind_" "$work/after.$kind_")
    if [ -n "$missing" ]; then
        isolation_ok=0
        note "docker $kind_ REMOVED by cluster-down:"
        printf '%s\n' "$missing" | sed 's/^/    - /' | head -15
    fi
    if [ -n "$added" ]; then
        note "docker $kind_ added concurrently during check (tolerated):"
        printf '%s\n' "$added" | sed 's/^/    + /' | head -10
    fi
    { printf 'missing after cluster-down:\n%s\nadded concurrently:\n%s\n' "$missing" "$added"; } > "$work/diff.$kind_"
done
cp "$work"/diff.* "$EVDIR/" 2>/dev/null || true
if [ "$left" -eq 0 ] && [ "$isolation_ok" -eq 1 ]; then
    pass C0.2.5 "no foreign docker object removed; cluster removed"
else
    bad C0.2.5 "foreign docker objects removed across cluster-down (see diffs)"
fi
rm -rf "$work"

# Restore the cluster (and reload images) so the suite leaves a usable state.
echo "== restore: make images && make cluster-up =="
"$MAKE" images >/dev/null 2>&1 || true
if ! "$MAKE" cluster-up; then
    note "WARNING: cluster restore failed after C0.2.5"
fi

# --------------------------------------------------------------------------
# Measurements (06 §12)
# --------------------------------------------------------------------------
if [ "${#samples[@]}" -gt 0 ]; then
    python3 - "${samples[@]}" > "$EVDIR/measurements.json" <<'PY'
import json, statistics, sys
s = [float(x) for x in sys.argv[1:]]
med = statistics.median(s)
cv = (statistics.pstdev(s) / statistics.mean(s)) if statistics.mean(s) else 0.0
print(json.dumps({
    "chunk": "M0.2",
    "check": "C0.2.3",
    "metric": "make cluster-up duration on existing cluster (idempotent)",
    "command": "make cluster-up",
    "unit": "seconds",
    "target": 300,
    "runs": len(s),
    "samples": s,
    "median": med,
    "coefficient_of_variation": round(cv, 4),
    "met": all(x <= 300 for x in s),
    "machine": "see sysinfo.txt in this evidence folder",
}, indent=2))
PY
    note "measurements written to $EVDIR/measurements.json"
fi

[ "$fail" -eq 0 ] && echo "M0.2 suite: all checks passed" || echo "M0.2 suite: FAILURES" >&2
exit "$fail"
