# M0.2 reopen — IPv6 + full-width offline closure

Supervisor review: C0.2.2 must prove offline mode closes every route out of
the cluster in every address family. Today an offline.sh that installs only
iptables rules passes C0.2.2 (only 1.1.1.1/IPv4 probed). Real exposure on
this host: kind docker net has IPv6 (fc00:f853:ccd:e793::/64) and the host
holds a tailnet IPv6 route.

Additional gaps found while probing (evidence: this dir):
- pod -> host bridge IPv4 172.18.0.1:22 was OPEN under the old rules:
  FORWARD was never hooked, and whole docker subnets were whitelisted.
- The old ip6tables chain whitelisted fc00:f853:ccd:e793::/64 (incl. the
  host bridge); v6 was only accidentally dead because ND (ff02/fe80) was
  dropped.

## Design

offline.sh:
- allowlist = loopback, ESTABLISHED/RELATED, peer node IPs (v4+v6, resolved
  per apply), pod CIDR, service CIDR, and (v6) fe80::/10 + ff02::/16 so
  neighbour discovery keeps working. Everything else DROP.
- CS_OFFLINE jumped from OUTPUT and FORWARD (pod egress covered too).

check-M0.2.sh C0.2.2:
- start host-side listeners on the kind bridge addrs (python http.server on
  172.18.0.1:18080 and fc00:f853:ccd:e793::1:18081, discovered dynamically).
- probe matrix, all must be OPEN pre-offline / CLOSED post-offline:
    node -> 1.1.1.1:443           (v4 public)
    node -> bridge v4 :18080      (v4 host)
    node -> bridge v6 :18081      (v6 host)
    regular pod -> bridge v4      (pod egress, FORWARD path)
    hostNetwork pod -> bridge v6  (pod-level IPv6; regular pods have no v6
                                   address in this v4-only cluster)
- never SKIP: if any probe cannot be made to work pre-offline -> FAIL.
- also assert peers still reachable (kubelet :10250, v4+v6) under offline:
  proves isolation is surgical, catches a drop-everything sabotage.
- inner run asserts closed + peers alive (no further recursion).

Sabotage: add offline-v4-only.patch (apply installs only iptables); keep
offline-noop, regenerate offline-on + allow-all-policy as needed.

Verified live before editing: all probes OPEN pre-offline, all CLOSED with
the new chain on countersign-worker, peers reachable.
