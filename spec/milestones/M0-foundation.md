# M0. Foundation

**Goal.** A reproducible, hermetic workshop: pinned tools, a kind cluster whose network policy is proven to work, fixture services that play the outside world, a scripted agent, and the check/sabotage/evidence machinery of `06`.

**Properties advanced.** None directly. Every later claim depends on this being trustworthy.

**Expected result.** From a fresh clone on the build host (`06` §11): `make tools images cluster-up fixtures-up check-M0` succeeds with the network disabled after `make images`, in under 15 minutes.

**Milestone-wide denied.** Any product code. Hosted CI configuration. Docker Compose alternatives to kind. Installing tools globally. A second cluster flavour (k3d, minikube).

---

## M0.1 Repository and toolchain

**Build.**
- Repository at `~/src/countersign` on the build host (already created, with `spec/` inside). Layout of `02` §7. Copy this `spec/` folder in. Apache-2.0 `LICENSE`; licence header check.
- `tools/versions.env` pins: Go, kind, kubectl, Helm, golangci-lint, Python (3.12 or newer), the `cryptography` wheel (with hash), and the node image digest. Pick current stable releases, record the upstream release page for each in evidence.
- `make tools` installs into `./.tools/`. Targets: `tools`, `lint`, `test`, `clean`, `sysinfo`, `regress`.
- `internal/names/names.go` holds the project name, API group and module path constants.

**Checks.**
- C0.1.1 Fresh clone: `make tools lint test` exits 0.
- C0.1.2 `./.tools/bin/go version` equals the pinned version; same for every pinned tool.
- C0.1.3 `git status --porcelain` is empty after `make lint` (nothing reformatted).
- C0.1.4 The strings `countersign.dev` and the module path appear in Go sources only in `internal/names/` and import paths.
- C0.1.5 `make sysinfo` prints kernel, CPU model, core count, memory, Docker version, CPU architecture.

**Sabotage.** `unformatted-file` (lint must fail); `missing-licence-header` (lint must fail); `unpinned-tool` (remove one pin; `make tools` must fail).

**Denied.** Vendoring dependencies. A custom build system. More than one Go module.

## M0.2 Hermetic cluster

**Build.**
- `make cluster-up` creates kind cluster `countersign`: one control-plane node, two workers, a CNI that enforces `NetworkPolicy` (installed from pinned manifests). `make cluster-down` deletes only that cluster.
- `make images` pulls every image by digest and loads it into kind. `make offline-on|off` adds or removes node-level rules that drop traffic to anything outside the cluster's own ranges.
- Namespaces of `02` §8.

**Checks.**
- C0.2.1 **Network policy is really enforced.** Pod A under a deny-all egress policy cannot reach pod B over TCP, cannot reach it over UDP, and cannot resolve DNS. After the policy is deleted all three succeed. Run on both worker nodes and across nodes.
- C0.2.2 With `make offline-on`, a node cannot reach a public address, and `make check-M0` still passes.
- C0.2.3 `make cluster-up` is idempotent and completes in ≤ 5 minutes [T] with images already loaded.
- C0.2.4 Probe and record: `/sys/kernel/btf/vmlinux` present on nodes (needed by M11); available runtime classes (needed by M4.7). Absence is recorded now, not discovered later.
- C0.2.5 `make cluster-down` leaves every other Docker container, image, network and volume on the machine untouched (compare listings before and after).

**Sabotage.** `allow-all-policy` (replace the deny-all policy in the proof with allow-all; C0.2.1 must fail); `offline-noop` (make `offline-on` do nothing; C0.2.2 must fail).

**Denied.** Any `docker system prune`, or delete command not scoped to the `countersign` cluster. Service mesh. Ingress controller.

## M0.3 Fixture services

All in `test/fixtures/`, built only with tag `fixtures`, each serving TLS from a **test root CA** and exposing `GET /__observed` (JSON list of everything received), `GET /__state` (a deterministic digest of all externally visible state, used by the **world oracle** from M5 on) and `POST /__reset`.

| Fixture | Plays | Must do |
|---|---|---|
| `echo` | A generic upstream | Echo method, path, headers, body digest; `/sse?n=&interval_ms=` emits n timed events; `/bytes?n=` streams n bytes; `/status/<code>`; HTTP/1.1 and HTTP/2; WebSocket echo |
| `sink` | The attacker | Listeners: HTTPS 443, HTTP 80, raw TCP 9000, UDP 9001, DNS 53 (UDP and TCP, answers every name), ICMP capture. Records every byte received with protocol and source |
| `fakehub` | A code host | Git smart HTTP that works with the real `git` client (clone, fetch, push) on repositories `acme/widgets` and `attacker/loot`; token auth; REST endpoints for issues and comments (GET, POST, PATCH, DELETE) with ETags and `If-Match`, pull requests (creation fails unless the branch exists on the real remote), and releases; `/debug/echo` returns request headers in the body; records the token and repository of every request; can seed an issue or comment containing an injection string; a test-only API through which a **third party** changes refs and resources; an optional `pre-receive` hook slot (used by M13.4) |
| `fakereg` | Package registries | PyPI simple index and file downloads; npm registry metadata and tarballs; a clean package set and one `evilpkg` whose install script runs a configurable command; a docs page at `/docs/` that can carry an injection string |
| `fakemsg` | A send-only messaging API | `POST /api/messages` returns an ID; replies reference a parent ID; honours an idempotency header; records every message |
| `mockllm` | Model providers | Serves a scenario transcript turn by turn in **Anthropic Messages** (streaming and non-streaming) and **OpenAI Responses and Chat Completions** shapes; validates that each incoming request carries the tool results the transcript expects; `/v1/files` accepts any key and records which key uploaded what; `--variant` (planted behavioural changes) and `--conditional` (follows an instruction only if a marker is in the context) modes for M12 |
| `mcpdemo` | An MCP server | Streamable HTTP transport; tools `create_record` (POSTs to `fakehub`), `search` (GET), `annotated_reader` (`readOnlyHint: true`); misbehaviour switches: `idle-phone-home`, `extra-post`, `lying-annotation`, off by default |

**Checks.**
- C0.3.1 Each fixture has a self-test proving every listed behaviour, including a real `git clone` and `git push` against `fakehub` and a real `pip install` and `npm install` against `fakereg`.
- C0.3.2 `sink` reports the exact bytes sent over each of its six listeners.
- C0.3.3 `mockllm` output for the reference transcript is byte-identical to `test/vectors/transcripts/reference.*` in all three API shapes.
- C0.3.4 A release build (`go build` without the `fixtures` tag) contains none of the fixture packages and none of the resolver-override code (check symbols).
- C0.3.5 For every fixture, `/__state` is identical across two reads, unchanged by any read-only request, and changed by every kind of write the fixture supports.

**Sabotage.** `sink-drops-udp` (C0.3.2 fails); `fixtures-in-release` (remove the build tag from one fixture; C0.3.4 fails).

**Denied.** Using real GitHub, PyPI, npm or model endpoints. Recording real traffic that contains real credentials. A fixture that depends on another repository.

## M0.4 Scripted agent

**Build.** `scriptagent`: a minimal agent loop in a sandbox image (non-root, with git, curl, Python, pip, Node, npm). It calls the model endpoint, executes tool-use blocks (`Bash`, `WebFetch`, `Read`, `Write`, and MCP tools through a real MCP client), sends tool results back, and stops when the model stops. It honours standard proxy and CA environment variables only; it contains **no** Countersign-specific code. Rogue switches for class D: `--rogue=extra-effect` (one extra credentialed request not asked for by the model), `--rogue=undeclared-mcp` (an extra `tools/call`, or altered arguments).

**Checks.**
- C0.4.1 Replaying the reference transcript three times produces the identical ordered list of requests at the fixtures.
- C0.4.2 Parallel tool calls in one turn run concurrently (overlapping intervals observed at `echo`).
- C0.4.3 Two concurrent conversations (`--subagent`) interleave model calls.
- C0.4.4 Each rogue switch produces exactly its one extra request.
- C0.4.5 Source scan: the agent imports nothing from `internal/` and reads no `COUNTERSIGN_*` variable.

**Sabotage.** `agent-ignores-tool-result` (C0.4.1 fails because `mockllm` rejects the next turn).

**Denied.** Making the scripted agent "smart". Any retry logic beyond what scenario E18 needs.

## M0.5 Check, sabotage and evidence tooling

**Build.** `make check-<chunk>` (runs the chunk's suite, tees output to `evidence/<chunk>/<UTC>/`, writes `result.json`); `make sabotage-<chunk>` (per `06` §4); `make regress`; frozen-hash verification (`06` §7); a linter for `PROGRESS.md` rows.

**Checks.**
- C0.5.1 A dummy chunk with a passing suite and a real sabotage: `check` green, `sabotage` green.
- C0.5.2 A dummy chunk whose suite ignores the sabotage: `sabotage` exits non-zero and names the uncaught patch.
- C0.5.3 Changing one byte of a file listed in `FROZEN.sha256` makes `make regress` fail.
- C0.5.4 Evidence folder contains command line, exit code, duration, git commit and full output.

**Sabotage.** `sabotage-runner-always-green` (C0.5.2 fails).

**Denied.** A test-reporting web page. Flaky-test retries: a check that passes only on retry is a failing check.

---

## Exit

Exit review per `06` §3. No human gate.
