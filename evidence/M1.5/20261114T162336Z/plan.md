# M1.5 plan — Python reference verifier (refverify)

Scope: `ref/python/refverify` implementing V1–V11 and V15 of spec 03 §10 from
the spec text + upstream standards only. No reads/writes of `internal/`,
`cmd/` or any Go. Stdlib + `cryptography` only. C1.5.2 stays BLOCKED (no
csverify / golden bundles in this lane); a lane-local derived-vector check
(C1.5.5) stands in until the Go lane lands.

Files:
- `ref/python/refverify/{__init__,__main__,cli}.py` — CLI: `python3 -m
  refverify <bundle.tar> --keys keys.json` → `{"verdict","world","errors",
  "warnings","findings","stats"}`; exit 0 only for CLEAN/CLEAN_WITH_DENIALS.
- `ref/python/refverify/{dsse,records,mlog,note,keys,bundle,verify}.py` —
  PAE, strict JSON (dup keys, non-UTF-8, non-canonical b64 rejected), strict
  record schema (§2/§4), RFC 6962 hashing + RFC 9162 §2.1.3.2 inclusion-proof
  verify, C2SP signed-note/tlog-checkpoint, manifest handling, tar checks.
- `test/refverify/{genbundle.py,cases.py}` — lane-local bundle generator and
  ~40 derived vectors (every E_* code, every warning, every verdict).
- `test/checks/check-M1.5.sh` — C1.5.1 import scan, C1.5.2 differential
  (BLOCKED-detect), C1.5.3 no-Go scan, C1.5.4 RFC/C2SP vectors, C1.5.5
  derived bundle vectors.
- `test/sabotage/M1.5/py-skip-chain-check.patch`; `docs/refverify.md`.

First test written: C1.5.4 Merkle vectors (published MTH values) — fails while
`refverify` does not exist. Then the check suite, confirmed failing for the
right reason before implementing.
