# M4. Kubernetes integration

**Goal.** Label a pod and it becomes a protected sandbox: no direct egress, no DNS, no service-account token, placeholders instead of secrets, all traffic through the broker, a sealed and verifiable session at the end. Installed by one Helm chart.

**Properties advanced.** P2 (mediated egress, proven against packet capture). P1 and P3 end to end.

**Normative references.** `02` §2, §3, §6, §8; `03` (`session.open`, `session.seal`).

**Expected results.**
- From inside a protected pod, every way out other than the broker fails.
- Packet capture finds no flow without a ledger record (H3).
- A pod using standard clients works without knowing Countersign exists.

**Measurements [T].**

| ID | Metric | Target |
|---|---|---|
| MM4.1 | Flows in packet capture without a ledger record, over ≥ 10,000 flows | 0 (H3) |
| MM4.2 | Bytes received by `sink` from a protected pod across the escape matrix | 0 |
| MM4.3 | Added pod start-up time (admission to container start) | p50 ≤ 1.5 s, p99 ≤ 4 s |
| MM4.4 | 50 sandboxes created concurrently, each making 200 requests | 100% correct session attribution; 0 cross-session records |
| MM4.5 | Client compatibility matrix (C4.2.4) | 9 of 9 clients work |

**Milestone-wide denied.** Sidecar or in-pod proxy designs. Transparent redirection. Our own CNI or CNI plugins. Service-mesh integration. Multi-cluster. An operator that manages agent lifecycles. Broker horizontal scaling. Custom runtime classes. Pod security admission replacement.

---

## M4.1 Custom resources and session lifecycle

**Build.** CRDs `SessionPolicy`, `McpContract` (namespaced) and `Session` (namespaced, written only by the controller: pod UID, pod IP, policy digest, token hash, state). `cscontroller`: on a pod labelled `countersign.dev/policy=<name>`, create the session, ask the broker (internal mTLS gRPC) to open it (CA, placeholders), append `session.open`; on pod IP assignment, bind it; on pod deletion or completion, wait for in-flight effects (≤ 10 s), collect emitter heads, append `session.seal`, trigger a checkpoint. Principal comes from annotation `countersign.dev/principal` set by the platform and is recorded with `method: annotation` (identity integration is D4).

**Checks.**
- C4.1.1 Pod lifecycle produces exactly one `session.open` first and one `session.seal` last; the exported bundle verifies.
- C4.1.2 Pod deleted during in-flight requests: seal is written after those effects' results or marks them dangling; verifier reports accordingly.
- C4.1.3 Controller restart mid-session: no second `session.open`; seal still correct.
- C4.1.4 Broker restart mid-session: the session resumes (CA restored from the system-namespace Secret), a new broker emitter instance starts a new chain, the seal lists both with `clean: false` for the first; verdict carries `W_UNCLEAN_EMITTER` only.
- C4.1.5 Pod IP reuse: a new pod receiving a just-released IP is never attributed to the old session (test by forcing reuse).
- C4.1.6 Missing or invalid `SessionPolicy` → pod admission denied with a clear message.

**Sabotage.** `seal-before-inflight-done`; `bind-by-ip-only-after-delete` (stale IP mapping kept); `duplicate-session-open-on-restart`.

**Denied.** Sessions spanning several pods. Long-lived sessions surviving pod replacement. Reading principal identity from tokens.

## M4.2 Admission webhook

**Build.** Mutating webhook (fail-closed: `failurePolicy: Fail`) for labelled pods. Mutations: proxy and CA environment variables of `02` §3 on **every** container including init and ephemeral ones; read-only volume with the CA bundle; placeholder environment variables; `automountServiceAccountToken: false`; `dnsPolicy: None` with empty resolvers; `enableServiceLinks: false`. Validations (reject): `hostNetwork`, `hostPID`, `hostIPC`, privileged containers, `NET_ADMIN`/`NET_RAW` capabilities, host-path volumes, a pre-set proxy or CA variable that conflicts.

**Checks.**
- C4.2.1 Mutated pod spec matches a golden file for three input pods (single container, init + main, with pre-existing env).
- C4.2.2 Each rejected feature is rejected, one test each.
- C4.2.3 Webhook unavailable → labelled pods cannot be created; unlabelled pods are unaffected.
- C4.2.4 **Client compatibility matrix**, each making an HTTPS request to `echo` from a protected pod with no client-specific configuration beyond the injected environment: `curl`, `wget`, `git`, `pip`, `npm`, Python `requests`, Python `urllib`, Node `fetch` (with the environment switch the pinned Node version needs, injected by the webhook), Go `net/http`. Record any client needing more than environment variables as a finding.
- C4.2.5 `kubectl debug` ephemeral container in a protected pod gets the same environment and is equally confined.

**Sabotage.** `webhook-skips-init-containers`; `webhook-fail-open`; `allow-hostnetwork`.

**Denied.** Injecting any binary, shim or library into the sandbox image. Modifying images. An `LD_PRELOAD` approach.

## M4.3 Network lockdown

**Build.** The controller maintains, per namespace with protected pods, a `NetworkPolicy` selecting them: egress only to the broker pods on TCP 3128; ingress denied, except from the broker for sessions with `scenario: mcp-server`. A startup self-test job per node proves enforcement (as M0.2) and the broker refuses to open sessions on a node where it failed.

**Checks: the escape matrix**, run from a protected pod as root with the tools installed. Every row must fail to deliver bytes to `sink` or the target, and must leave the broker's safety intact:

| # | Attempt |
|---|---|
| 1 | TCP to `sink` by IP, ports 80, 443, 9000 |
| 2 | UDP to `sink` 9001; QUIC-shaped packets to 443 |
| 3 | DNS over UDP and TCP to cluster DNS, to `sink`, to a public resolver address |
| 4 | DNS over HTTPS through the proxy to a non-granted resolver |
| 5 | ICMP echo with payload |
| 6 | IPv6 to `sink` |
| 7 | `169.254.169.254` directly |
| 8 | Kubernetes API server by cluster IP and by node IP |
| 9 | Another sandbox pod; a fixture pod; the node's kubelet port |
| 10 | Broker ports other than 3128; the ledger volume path; the controller |
| 11 | Unsetting proxy variables and connecting directly |
| 12 | `CONNECT` through the proxy to: `sink:9000`, `localhost`, the broker's own service, the Kubernetes API, a private address |
| 13 | Proxy request with a `Host` header differing from the `CONNECT` target |
| 14 | Using another session's proxy token |

- C4.3.1 All 14 rows fail as specified; MM4.2 = 0.
- C4.3.2 Each row that touches the broker produces a denial record; rows blocked by the network policy produce none (they are M11's job) and that absence is asserted so M11 can flip it.
- C4.3.3 Deleting the generated `NetworkPolicy` by hand: the controller restores it within 5 s and emits a Kubernetes event; the broker denies that namespace's sessions while it is absent.

**Sabotage.** `netpol-allows-dns`; `netpol-allows-cluster-cidr`; `no-reconcile-on-netpol-delete`.

**Denied.** Relying on the sandbox image lacking tools. Egress gateways. Node firewall rules written by the controller.

## M4.4 Broker in cluster mode

**Build.** Session table from `Session` objects (watch) plus the internal open/close calls; Kubernetes-Secret-backed credential store (`countersign-system` only; RBAC denies everything else); resolver override only under the `fixtures` tag.

**Checks.**
- C4.4.1 MM4.4.
- C4.4.2 RBAC audit: the broker's service account can read Secrets only in `countersign-system`; the controller cannot read credential Secrets at all; nothing in `sandboxes` can read anything (`kubectl auth can-i` matrix as golden output).
- C4.4.3 A request from a pod IP with no bound session → `NO_SESSION`, even with a valid token copied from another pod.
- C4.4.4 M2 and M3 suites re-run against the in-cluster broker (same expectations).

**Sabotage.** `broker-reads-secrets-cluster-wide` (C4.4.2 fails); `session-lookup-by-token-only`.

**Denied.** Admin HTTP endpoints on the broker beyond health and metrics. Dynamic policy reload within a session (a policy change applies to new sessions).

## M4.5 Helm chart and `csctl`

**Build.** `deploy/helm/countersign`: CRDs, controller, broker, webhook with generated certificates, RBAC, ledger volume. `csctl`: `sessions list|show`, `bundle export <session> -o file`, `keys manifest`, `verify` (shells to `csverify`).

**Checks.**
- C4.5.1 `helm install` on an empty kind cluster, then one labelled pod, then `csctl bundle export` and `csverify` → `CLEAN`, scripted end to end.
- C4.5.2 `helm template` output passes `kubeconform` and a policy check: no cluster-admin, no wildcard RBAC verbs, all containers non-root with read-only root filesystem and dropped capabilities.
- C4.5.3 `helm uninstall` removes everything it created except the ledger volume (kept deliberately, stated in notes).
- C4.5.4 Release-build images contain no fixture code (as C0.3.4).

**Sabotage.** `chart-grants-cluster-admin`; `broker-runs-as-root`.

**Denied.** An operator-lifecycle-manager bundle. Kustomize overlays. Chart options for alternative topologies.

## M4.6 Completeness against packet capture

**Build.** A capture DaemonSet (fixtures tag only) recording on the protected pods' interfaces. A workload generator driving ≥ 10,000 flows from 10 sandboxes: allowed, denied, aborted, large, streamed, plus the escape matrix. A comparer that, for each TCP connection established from a sandbox IP in the capture, requires destination = broker:3128 and at least one ledger record with that client port in that session; and for each ledger record requires a captured connection.

**Checks.**
- C4.6.1 MM4.1 = 0 in both directions (no flow without record, no record without flow).
- C4.6.2 The comparer's self-test: with one ledger record deleted from a copy, it reports exactly that flow.
- C4.6.3 Captured established connections to anything other than the broker: 0.

**Sabotage.** `drop-record-for-aborted-connections`; `comparer-ignores-denied`.

**Denied.** Shipping packet capture in the product. Deep packet inspection.

## M4.7 `agent-sandbox` adapter

**Build.** Verify the upstream project's API group, kinds and current version (`06` §8), pin it, install its CRDs in the test cluster. Make a `Sandbox` (and a claim from a template) whose pod template carries the label come out protected. If a gVisor or microVM runtime class is available (C0.2.4), run the same suite under it.

**Checks.**
- C4.7.1 A sandbox created through the upstream API is protected: escape matrix and compatibility matrix pass.
- C4.7.2 Deleting the sandbox object seals the session.
- C4.7.3 Under an alternative runtime class: same results, or `SKIPPED-ENV` with the probe output.
- C4.7.4 Countersign works with the upstream CRDs absent (plain pods).

**Sabotage.** `adapter-drops-label-on-claim`.

**Denied.** Forking or patching the upstream project. Proposing upstream API changes (a human does that later).

---

## Exit: human gate G2

The exit review must include the full escape-matrix output, the RBAC matrix, and the H3 comparer report. The reviewer is asked: is anything in the trusted computing base larger than it needs to be?
