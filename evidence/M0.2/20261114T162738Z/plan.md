# M0.2 Hermetic cluster — plan

- `deploy/kind/`: kind-config (1 cp + 2 workers, disableDefaultCNI, podSubnet 192.168.0.0/16), pinned Calico v3.33.0 manifest, namespaces.yaml (countersign-system, sandboxes, fixtures, attacker), policies/deny-all-egress.yaml.
- `tools/images.env`: digest pins (kindest/node already in versions.env; calico×3, agnhost, busybox) + calico manifest sha256.
- `tools/cluster/`: lib.sh (kubeconfig, node list, flock), cluster-up.sh, cluster-down.sh (only cluster `countersign`), images.sh (pull by digest, tag, kind load), offline.sh (per-node iptables OUTPUT drop except lo/established/pod/svc/kind-net; state flag in ~/.cache/countersign), fixtures-up.sh (namespaces only; workloads are M0.3).
- Makefile: add cluster-up/down, images, offline-on/off, fixtures-up targets (check-%/sabotage-% untouched).
- Checks first: `test/checks/check-M0.2.sh` (C0.2.1 netpol TCP/UDP/DNS deny then allow, both workers + cross-node; C0.2.2 offline-on blocks node egress + `make check-M0` green, inner-run env guard; C0.2.3 5× idempotent cluster-up ≤300s → measurements.json; C0.2.4 BTF + RuntimeClass probes recorded; C0.2.5 docker state diff across down/up) and `test/checks/check-M0.sh` (runs every check-M0.*.sh). First test: C0.2.1 suite failing with "cluster absent".
- Sabotages: allow-all-policy (patch deny-all-egress.yaml), offline-noop (patch offline.sh). Docs: docs/cluster.md.
