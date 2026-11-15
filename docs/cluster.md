<!-- Copyright 2026 The Countersign Authors
     SPDX-License-Identifier: Apache-2.0 -->

# The hermetic kind cluster (M0.2)

`countersign` is the workshop's only kind cluster: one control-plane node, two
workers, Calico v3.33.0 installed from the pinned manifest
`deploy/kind/calico-v3.33.0.yaml` so `NetworkPolicy` is really enforced
(proven by check C0.2.1). The four namespaces of the deployment topology are
applied on every `cluster-up`: `countersign-system`, `sandboxes`, `fixtures`,
`attacker`.

| Command | Behaviour |
|---|---|
| `make images` | Pulls every pinned image by digest (`tools/images.env`, plus `KIND_NODE_IMAGE` in `tools/versions.env`), tags it, and imports it into each node's containerd. Safe to run before the cluster exists; the load step then waits for `cluster-up`. |
| `make cluster-up` | Creates the cluster from `deploy/kind/kind-config.yaml` if absent, re-applies the Calico manifest (sha256-verified), the namespaces and locally present images, and waits for nodes, Calico and CoreDNS to be Ready. Idempotent. Refuses when a foreign kind cluster exists. |
| `make cluster-down` | `kind delete cluster --name countersign` — scoped to this cluster only. Idempotent. |
| `make offline-on` | Per node, installs an iptables **and** ip6tables `CS_OFFLINE` chain jumped to from `OUTPUT` **and** `FORWARD` (pod egress included): loopback, established/related, the peer nodes' own addresses, the pod CIDR (`192.168.0.0/16`), the service CIDR (`10.96.0.0/12`), and — IPv6 only — `fe80::/10` + `ff02::/16` (neighbour discovery) are returned; everything else is dropped, the host side of the docker bridge included. Desired-state flag at `~/.cache/countersign/offline-on`: `cluster-up` re-applies it to (re)created nodes. |
| `make offline-off` | Removes the chains and jumps on every node and clears the flag. |
| `make fixtures-up` | Cluster-up plus namespaces; fixture workloads arrive with M0.3. |

Notes:

- `kind load` is not used: `ctr import --all-platforms` fails on multi-arch
  image indexes. `make images` pipes `docker save` into each node's own
  `ctr images import`, which stores the tag and the digest name.
- Cluster operations take a host-wide flock (`~/.cache/countersign/cluster.lock`)
  because the cluster is a singleton shared by all lanes on this host.
- `check-M0.2` proves: NetworkPolicy deny-all blocks TCP/UDP/DNS and deletion
  restores them on both workers and across nodes (C0.2.1); under `offline-on`
  no node or pod can reach the public IPv4 internet or the host side of the
  docker bridge in either address family (a hostNetwork pod is the IPv6 pod
  probe — regular pods have no IPv6 address in this IPv4-only cluster), while
  intra-cluster peers stay reachable and `make check-M0` still passes (C0.2.2);
  `cluster-up` re-runs idempotently in seconds (C0.2.3); kernel BTF and
  runtime classes are probed and recorded (C0.2.4); `cluster-down` touches
  no foreign docker object (C0.2.5).
