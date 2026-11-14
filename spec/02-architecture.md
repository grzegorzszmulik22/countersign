# 02. Architecture

## 1. Components

| Binary | Role | Runs | Emitter role |
|---|---|---|---|
| `csbroker` | The only door. Explicit forward proxy; terminates TLS from the sandbox with a per-session certificate authority; classifies and decides every request; injects credentials; routes staged writes to the world service; inspects inference and MCP traffic; charges budgets; serves the boundary endpoint; in replay mode answers from tape. | Deployment, 1 replica | `broker` |
| `csworld` | The world service. Per session: the staging journal, shadow git remotes, the deferred-send outbox, the prior-state vault, the tape. Builds changesets and review documents, evaluates invariants, coordinates commit, undo, probation and world groups, issues attestations. Reaches upstreams **only through the broker**. | Deployment, 1 replica, persistent volume | `world` |
| `cscontroller` | Watches pods and sandbox objects; opens and seals sessions; generates the network policy; hosts the admission webhook. | Deployment | `controller` |
| `csledger` | Append-only store behind mutual-TLS gRPC: per-session records, the global Merkle log, checkpoints, bundle export. In-process inside the broker for M1–M4; a service from M5. | Deployment, persistent volume | signs checkpoints with the `log` key |
| `csreview` | Review API and one static page: shows the world-diff, collects the passkey signature. | Deployment (M6) | none; the reviewer's passkey signs |
| `csobserver` | Turns Tetragon process and connect events into signed records. | DaemonSet (M11) | `observer` |
| `csctl` | Operator CLI: sessions, worlds, commit, undo, ratify, replay, what-if, policy learning, bundle export. | Anywhere | none |
| `csverify` | Offline verifier, reconciler, what-if evaluator, attestation checker. | Anywhere, no cluster | none |
| `ref/python/*` | Independent reference implementations for differential testing: `refverify`, `refreconcile`, `refclassify`, `refcommit`, `refwhatif`. Standard library plus `cryptography`. | Test time | none |

Test-only binaries (M0): `scriptagent`, `mockllm`, `fakehub`, `fakereg`, `fakemsg`, `sink`, `echo`, `mcpdemo`.

## 2. The life of a session (scenario S1)

```
 1. Pod created with label countersign.dev/policy=<name>
 2. Webhook mutates it: proxy env, CA bundle, placeholders, no service-account token, no DNS
 3. Controller opens session S and world W; network policy applied; session.open recorded
 4. Agent → broker: POST model endpoint           class control → forwarded; tool-use blocks become intent records
 5. Agent → broker: git fetch                     class safe    → world service syncs from upstream (through the broker) and serves
                                                                  the overlay: real refs + the agent's staged refs
 6. Agent → broker: git push                      class staged  → received by the shadow remote; stage.entry recorded;
                                                                  the real remote sees nothing
 7. Agent → broker: PATCH an issue                class compensable → prior state captured, write forwarded, post state captured
 8. Agent → broker: POST a payment                class irreversible → held; one-entry changeset; needs a signature
 9. Agent → broker: POST countersign.internal/v1/commit   (or the session ends, or a barrier is hit)
10. World service: changeset → invariants → automatic commit, or a review document for a human
11. Reviewer signs the changeset root with a passkey
12. World service applies each selected entry through the broker, each guarded by its precondition; attestations issued
13. Pod gone → sandbox.terminated. World closed → session.seal → checkpoint
14. csctl bundle export S → csverify → verdict.     Later: csctl undo S → an undo session with its own bundle
```

Scenario S2 runs the same machinery for an MCP server pod. Calls into it are serialized; its egress during a call is checked against its contract and its writes are journalled in the **caller's** world (`05` §12).

## 3. Sandbox-to-broker contract

| Mechanism | Value |
|---|---|
| Proxy | `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` and lowercase variants set to `http://cs:<token>@<broker ClusterIP>:3128` (an IP, because the sandbox has no DNS); `NO_PROXY` empty |
| Session identification | Source pod IP resolved against the session table **and** `Proxy-Authorization: Basic` with user `cs` and the session proxy token as password. Both must agree. The token identifies the sandbox and grants nothing beyond its own policy |
| Trust store | Per-session CA certificate mounted read-only; `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `PIP_CERT`, `AWS_CA_BUNDLE` point to system roots plus the session CA |
| Credentials | Environment variables hold placeholders `csph_<8 hex session>_<grant id>_<22 base62>`. Real values live only in the broker |
| DNS | `dnsPolicy: None`, no resolvers. The broker resolves names |
| Network policy | Egress only to the broker on TCP 3128. Ingress denied, except from the broker for `scenario: mcp-server` |
| Kubernetes API | No service-account token |
| Boundary endpoint | The name `countersign.internal`, reachable only through the proxy and answered by the broker itself (`05` §15). Read-only description of the session's rules and world, plus a commit request |

The world service is a second kind of proxy client. It authenticates to the broker's proxy port with a per-session **world token** over mutual TLS, and its requests carry `actor: world`. They pass the same grant matching, credential injection and write-ahead recording as the sandbox's, with one difference: they are never staged.

## 4. Keys

| Key | Algorithm | Holder | Used for |
|---|---|---|---|
| Emitter keys (`broker`, `controller`, `world`, `observer`) | Ed25519 | Each component, from a Kubernetes Secret | Signing DSSE envelopes |
| Log key | Ed25519 | `csledger` | Signing checkpoints. Must differ from every emitter key |
| Attestor key | Ed25519 | `csworld` | Signing output statements. Must differ from every emitter key |
| Session CA | ECDSA P-256 | Broker memory; in Kubernetes also a Secret in `countersign-system` | Minting leaf certificates for that session |
| World data key | AES-256-GCM, one per world | `csworld`, wrapped by a cluster key in a Secret | Encrypting staged request bodies and prior states at rest |
| Tape recipient key | X25519 public key supplied by the operator | Private half held **outside** the cluster | Wrapping each session's tape key, so recorded content is readable only by its holder |
| Reviewer keys | WebAuthn (ES256 or EdDSA) | The reviewer's authenticator | Signing commit decisions, ratifications, revocations, undo requests |
| Delegate keys | Ed25519 | An outside reviewer service, never a Countersign component | Signing commit decisions within the limits of `05` §8 |
| Key manifest | none | Published `keys.json` | Maps key IDs to public keys, roles and validity; in every bundle |

All private-key use goes through `internal/keys.Signer`.

## 5. Technology choices (fixed)

| Area | Choice | Reason |
|---|---|---|
| Language | Go, version pinned in M0.1 | Kubernetes ecosystem, static binaries |
| Proxy | Custom Go forward proxy on `net/http` and `golang.org/x/net/http2` | Full control of write-ahead ordering, classification and stream inspection |
| Git stager | The stock `git` binary: `git http-backend` to serve the shadow remote, `git push --force-with-lease` to apply | The reference implementation of the protocol; no reimplementation of pack handling |
| Envelope | DSSE v1 carrying an in-toto Statement v1 | Existing, widely implemented |
| Log | RFC 6962 Merkle hashing; C2SP `tlog-checkpoint` in signed-note format | Compatible with public witness tooling |
| Changeset root | RFC 6962 Merkle root over RFC 8785 canonical entry objects | One 32-byte value a reviewer signs; subsets provable |
| Review signature | WebAuthn assertion | A phishing-resistant signature people already have |
| Record body | JSON. Signed bytes are the DSSE payload as stored | Debuggable; no canonicalization needed for signatures |
| Policy | YAML documents of kind `SessionPolicy`, `McpContract` | Small and declarative |
| Kubernetes | controller-runtime; admission webhook; Helm chart | Standard |
| Process events | Tetragon as shipped (M11) | No custom eBPF |
| Encryption at rest | AES-256-GCM with per-world and per-tape data keys | Standard library |
| Reference implementations | Python 3.12+, standard library plus `cryptography` | Independent toolchain |
| Test cluster | kind, three nodes, a CNI that enforces NetworkPolicy; enforcement proven by test | Hermetic |

Anything version-specific taken from memory is checked upstream when pinned (`06` §8).

## 6. Failure behaviour (fail-closed)

| Failure | Required behaviour |
|---|---|
| Ledger append fails or exceeds 500 ms | Request denied `502 LEDGER_UNAVAILABLE`. Nothing forwarded |
| Session cannot be identified | `407 NO_SESSION` |
| Policy missing or invalid | Pod admission rejected |
| World service unavailable | `safe` and `control` requests continue. Every write is denied `WORLD_UNAVAILABLE`, including `compensable` and `irreversible` ones, because their prior state and review cannot be recorded |
| Broker restarts | In-flight requests fail; sessions resume from ledger state; effects with no result are reported as dangling |
| World service restarts mid-commit | On restart it reads the ledger. Entries with `commit.applied` are done. An entry whose apply effect was recorded but has no result is marked `unknown` and is **never** retried automatically |
| Inference response cannot be parsed | Bytes still flow unchanged; `intent.unparsed` written; no intent opens |
| Observer unhealthy (M11) | Per policy: `required` denies new connections; `optional` records a gap |
| Review service down | Reviews wait until their expiry; nothing commits |
| Tape store full or failing, tape enabled | Per policy `tape.onFailure`: `deny` (default) or `continue-unrecorded` with a gap record |
| Sandbox ends with staged entries | Per policy `world.onSessionEnd`: `hold` (default: the world stays open for review until `world.reviewTtl`) or `abort` |

## 7. Repository layout

```
cmd/{csbroker,csworld,cscontroller,csledger,csreview,csobserver,csctl,csverify}/
internal/
  evidence/  mlog/  ledger/  keys/            (M1)
  proxy/                                      (M2)
  policy/  creds/                             (M3)
  classify/      reversibility classes, autonomy              (M5)
  world/         journal, lifecycle, groups, encrypted stores (M5)
  stager/git/    shadow remote, overlay, apply                (M5, M6)
  commit/        changeset, review document, invariants, apply (M6)
  review/        WebAuthn, challenges                          (M6)
  boundary/      countersign.internal, problem documents       (M6)
  undo/          prior state, compensation, probation          (M7)
  stager/outbox/ deferred sends, provisional IDs               (M7)
  inspect/       anthropic, openai, mcp                        (M8)
  reconcile/     engine, rule packs, contracts                 (M9)
  taint/                                                       (M10)
  observe/                                                     (M11)
  whatif/  tape/  replay/                                      (M12)
  budget/  attest/                                             (M13)
ref/python/      refverify, refreconcile, refclassify, refcommit, refwhatif
api/             JSON Schemas, CRDs, protobuf
deploy/helm/countersign/
test/{vectors,sabotage,fixtures,e2e}/
bench/{perf,effectbench}/
spec/            this folder (copied in at M0.1)
evidence/        check outputs, one folder per chunk run
```

## 8. Deployment topology (kind)

- `countersign-system`: broker, world service (volume), ledger (volume), controller, review service; from M11 the observer DaemonSet.
- `sandboxes`: protected pods.
- `fixtures`: `mockllm`, `fakehub`, `fakereg`, `fakemsg`, `echo`, `mcpdemo`.
- `attacker`: `sink`.

Fixture and attacker services are reached under realistic host names through a broker-side resolver override and a test root CA, available only in builds with the `fixtures` tag.

## 9. Naming

Working name `countersign`; API group `countersign.dev`; Go module `github.com/countersign/countersign` (placeholder); boundary host `countersign.internal`. All appear only as constants in `internal/names/names.go` and Helm values.
