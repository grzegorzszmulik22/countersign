# Countersign

An egress broker for AI agents that writes signed evidence before anything leaves the sandbox.

Today's agent sandboxes draw the boundary around the process. Countersign draws it around consequences: every effect an
unmodified agent has on the outside world passes one broker that holds the secrets, records a signed, write-ahead
evidence record, and can stage the effect so nothing becomes real until one reviewed, signed commit. No model sits in the
decision path, and anyone with the public keys can verify a session offline.

> **Status: under active construction.** About 20 of the 90+ specification chunks are merged, covering the evidence
> core, the local-mode broker, the policy and credential layer, and the reconciliation reference. Staging, commit and
> undo (M5–M7) are not built yet. Nothing here is ready for production use.

## What works today

| Area | Built | Where |
|---|---|---|
| Evidence core | Signed record format, hash chains, Merkle log, bundle export, an offline verifier (`csverify`) | `internal/evidence`, `internal/ledger`, `cmd/csverify` |
| Independent verifier | A Python bundle verifier written from the specification alone, checked against Go on every bundle (in review, not yet on `main`) | `ref/python/refverify` |
| Broker (local mode) | Intercepting proxy with TLS interception, sessions, streaming digests | `internal/proxy`, `cmd/csbroker` |
| Policy and credentials | Grant matching (incl. git smart-HTTP scoping), placeholder credentials, pinning, response scrubbing | `internal/policy`, `internal/creds` |
| Local runner | `cs run -- <agent>` in a rootless namespace whose only way out is the broker | `internal/runner`, `cmd/cs` |
| Reconciliation | Declared-vs-observed engine with a Python reference implementation | `internal/reconcile`, `ref/python/refreconcile` |

## How it is verified

The project is specification-first. Every chunk in `spec/milestones/` lists its checks, its measurements and its
**sabotages**: deliberate breakages the test suite must catch. A chunk counts as done only when:

1. every check it lists passes on a fresh clone, and
2. its own sabotages are caught, and
3. a supervisor review on a fresh clone catches a further set of sabotages the implementer never saw.

Each decision procedure has two independent implementations (Go and Python) that must agree. Thresholds, test vectors
and expected verdicts change only through a recorded change request (`spec/CHANGE_REQUESTS/`).

## How it was built

The code is written by AI coding agents (Devin, and DeepSeek through opencode) working in parallel lanes against the
specification, under adversarial supervision: no lane's "done" is accepted until an independent review with unseen
sabotages passes. The lane branches in this repository are that work in progress; `main` holds only reviewed merges.
`spec/PROGRESS.md` records every merge, with the review findings.

## Quick start

Requires Linux; `cs run` also needs unprivileged user namespaces. The Go toolchain is pinned and downloaded by
`make tools`. Directories under `cmd/` and `internal/` for later milestones are placeholders.

```sh
make tools      # pinned toolchain into .tools/
make test       # unit tests
make regress    # every merged chunk's checks and sabotages
go run ./cmd/csverify --help
```

## Repository layout

| Path | Contents |
|---|---|
| `spec/` | The specification: thesis, threat model, architecture, evidence format, policy, transactions, milestones |
| `cmd/`, `internal/` | Go implementation |
| `ref/python/` | Independent Python reference implementations |
| `test/` | Check scripts, vectors and fixtures per chunk |
| `evidence/` | Raw check and measurement output recorded at each merge |

## License

[Apache-2.0](LICENSE).
