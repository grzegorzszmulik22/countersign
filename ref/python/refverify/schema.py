# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""Record-type schemas, transcribed from spec 03 §4. Unknown predicate fields,
unknown body fields and unknown ``type`` values are E_SCHEMA (§2).

Field spec values: "str" | "int" | "bool" | "num" | "ts" | "hex64" | "any" |
"anymap" | ("enum", set) | ("list", item) | ("obj", {field: spec}) where a
field name ending in "?" is optional and may be null.
"""
from .errors import VerifyError
from . import strict

REASONS = {
    "OK", "STAGED", "NO_SESSION", "NO_GRANT", "DENY_GRANT", "AUTONOMY_DENY",
    "NO_INTENT", "UNDECLARED_TOOL_CALL", "REVIEW_REQUIRED", "REVIEW_REJECTED",
    "REVIEW_TIMEOUT", "BARRIER", "TAINTED_DENY", "FOREIGN_CREDENTIAL",
    "PLACEHOLDER_MISUSE", "LIMIT_BODY", "LIMIT_URL", "LIMIT_RATE",
    "BUDGET_LEAK", "BUDGET_WRITES", "REF_NOT_ALLOWED", "PROTOCOL_DENIED",
    "SMUGGLING_SUSPECT", "UPSTREAM_BLOCKED", "UPSTREAM_TLS",
    "LEDGER_UNAVAILABLE", "WORLD_UNAVAILABLE", "OBSERVER_REQUIRED",
    "WORLD_CLOSED", "GROUP_SUPERSEDED", "CONTRACT_VIOLATION",
    "EFFECT_OUTSIDE_CALL", "ANNOTATION_VIOLATION", "REPLAY_DIVERGENCE",
}

_ROLES = {"broker", "controller", "world", "observer"}

_DECISION = ("obj", {
    "action": ("enum", {"allow", "deny", "hold", "stage"}),
    "reason": ("enum", REASONS),
    "requires": ("enum", {"allow", "intent", "review", "deny"}),
    "grant?": "str",
    "credentials": ("list", "any"),
    "would_deny?": "bool"})

_CLIENT = ("obj", {"ip": "str", "port": "int"})

_WEBAUTHN = ("obj", {"key_id": "str", "authenticator_data": "str",
                     "client_data_json": "str", "signature": "str"})

SCHEMA = {
    # ---------------------------------------------------------- §4.1
    "session.open": {
        "kind": ("enum", {"agent", "mcp-server", "undo", "replay"}),
        "parent_session?": "str",
        "parent_seal_hash?": "hex64",
        "principal": ("obj", {"subject": "str", "issuer": "str",
                              "method": "str"}),
        "sandbox": ("obj", {"namespace": "str", "pod": "str",
                            "pod_uid": "str", "node": "str",
                            "runtime_class?": "str",
                            "image_digest": "str"}),
        "mode": ("enum", {"enforce", "audit", "learn"}),
        "policy_digest": "hex64",
        "contract_digests": ("list", "hex64"),
        "ca_cert_sha256": "hex64",
        "log_origin": "str",
        "world": ("obj", {"id": "str", "group?": "str"}),
        "start": ("obj", {"workspace?": "str"}),
        "tape": ("obj", {"enabled": "bool", "recipient_key_id?": "str"}),
        "replay?": ("obj", {"source_session": "str", "mode": "str"}),
    },
    "sandbox.terminated": {"reason": "str"},
    "world.rewound": {"to_journal_seq": "int",
                      "dropped_entries": ("list", "str"),
                      "undo_id?": "str"},
    "world.closed": {
        "outcome": ("enum", {"committed", "aborted", "partial", "superseded",
                             "expired", "empty"}),
        "commits": ("list", "str")},
    "session.seal": {
        "reason": "str",
        "emitters": ("list", ("obj", {"emitter": "str", "final_eseq": "int",
                                      "head_hash": "hex64", "clean": "bool"})),
        "counts": ("obj", {"effects": "int", "intents": "int",
                           "denials": "int", "entries": "int",
                           "commits": "int"})},
    "emitter.seal": {"final": ("enum", {True})},

    # ---------------------------------------------------------- §4.2
    "effect.http": {
        "effect_id": "str", "actor": ("enum", {"sandbox", "world"}),
        "purpose?": ("enum", {"sync", "apply", "prestate", "poststate",
                              "compensate", "probe"}),
        "for?": "str",
        "conn_id": "str", "client": _CLIENT,
        "request": ("obj", {
            "method": "str", "scheme": "str", "authority": "str",
            "path": "str", "query_sha256": "hex64", "query_len": "int",
            "header_names": ("list", "str"), "body_sha256?": "hex64",
            "body_len?": "int", "body_deferred": "bool"}),
        "request_digest?": "hex64",
        "class": ("enum", {"control", "safe", "staged", "compensable",
                           "irreversible"}),
        "decision": _DECISION,
        "attribution": ("obj", {
            "level": ("enum", {"CONTROL", "EXACT", "WINDOW", "STANDING",
                               "NONE"}),
            "intents": ("list", "str"),
            "lineage": ("enum", {"owned", "unowned", "unknown", "off"}),
            "owner?": "str"}),
        "taint": ("list", "str"),
        "budget": ("obj", {"leak_bytes": "int", "writes": "int"}),
        "inspect": ("enum", {"none", "inference", "mcp"})},
    "effect.http.result": {
        "effect_id": "str",
        "served_by": ("enum", {"upstream", "world", "boundary", "replay"}),
        "status?": "int",
        "response": ("obj", {"header_names": ("list", "str"),
                             "body_sha256": "hex64", "body_len": "int"}),
        "request_body": ("obj", {"sha256": "hex64", "len": "int"}),
        "upstream?": ("obj", {"ip": "str", "port": "int",
                              "tls_version?": "str", "cert_sha256?": "hex64"}),
        "timing": ("obj", {"total_ms": "num", "ttfb_ms": "num"}),
        "scrubbed": "bool", "error?": "str"},
    "effect.tunnel": {
        "effect_id": "str", "authority": "str", "sni?": "str",
        "kind": ("enum", {"passthrough", "websocket"}),
        "decision": _DECISION},
    "effect.tunnel.result": {
        "effect_id": "str", "bytes_up": "int", "bytes_down": "int",
        "duration_ms": "num", "error?": "str"},
    "effect.denied": {"conn_id": "str", "client": _CLIENT,
                      "authority?": "str", "reason": "str", "detail": "str"},
    "effect.exec": {"exec_id": "str", "parent_exec_id?": "str", "pid": "int",
                    "binary": "str",
                    "argv_sha256": ("list", "hex64"),
                    "argv_truncated": "bool", "uid": "int"},
    "effect.connect": {"exec_id": "str", "pid": "int",
                       "dst": ("obj", {"ip": "str", "port": "int"}),
                       "src_port": "int", "proto": "str",
                       "outcome": ("enum", {"to-broker", "blocked"})},
    "observer.gap": {"from": "int", "to": "int", "reason": "str"},

    # ---------------------------------------------------------- §4.3
    "stage.entry": {"entry_id": "str", "journal_seq": "int",
                    "via_effect": "str", "via_session?": "str",
                    "via_record_hash?": "hex64", "entry": "anymap",
                    "entry_sha256": "hex64", "supersedes?": "str"},
    "prestate.captured": {"for_effect": "str", "for_session?": "str",
                          "when": ("enum", {"before", "after"}),
                          "via_effect": "str", "status": "int",
                          "state_sha256": "hex64", "len": "int",
                          "etag?": "str"},
    "commit.requested": {
        "commit_id": "str",
        "trigger": ("enum", {"agent", "operator", "session-end", "barrier",
                             "held-effect"}),
        "entries": ("list", "str"), "changeset_root": "hex64",
        "review_sha256": "hex64",
        "invariants": ("list", ("obj", {"name": "str", "pass": "bool",
                                        "detail": "str"})),
        "auto_eligible": "bool", "expires_at": "ts"},
    "commit.decision": {
        "commit_id": "str",
        "decision": ("enum", {"commit", "reject", "timeout"}),
        "by": ("enum", {"auto", "human", "delegate"}),
        "selected": ("list", "str"), "selected_root": "hex64",
        "review_sha256": "hex64", "expires_at": "ts",
        "probation?": ("obj", {"until": "ts",
                               "on_expiry": ("enum", {"keep", "revert"})}),
        "webauthn?": _WEBAUTHN,
        "delegate?": ("obj", {"key_id": "str", "signature": "str"})},
    "commit.applied": {
        "commit_id": "str", "entry_id": "str",
        "outcome": ("enum", {"applied", "conflict", "failed", "unknown"}),
        "via_effect?": "str",
        "precondition": ("obj", {"kind": "str", "expected": "any",
                                 "observed": "any"}),
        "id_map?": "anymap"},
    "commit.closed": {
        "commit_id": "str",
        "outcome": ("enum", {"committed", "partial", "rejected", "expired",
                             "rolled-back"})},
    "probation.ratified": {"commit_id": "str", "webauthn": _WEBAUTHN},
    "undo.requested": {
        "undo_id": "str",
        "scope": ("enum", {"session", "commit", "effect"}),
        "targets": ("list", "str"),
        "trigger": ("enum", {"operator", "probation-expired",
                             "probation-revoked", "group-superseded",
                             "commit-failure", "rewind"}),
        "webauthn?": _WEBAUTHN},
    "undo.applied": {
        "undo_id": "str", "target": "str",
        "outcome": ("enum", {"restored", "conflict", "not-compensable",
                             "failed"}),
        "via_effect?": "str",
        "precondition": ("obj", {"expected": "any", "observed": "any"})},
    "undo.closed": {"undo_id": "str", "restored": "int", "conflicts": "int",
                    "not_compensable": "int", "failed": "int"},
    "attestation.issued": {
        "commit_id": "str", "entry_id": "str",
        "subject": ("obj", {"kind": "str", "name": "str",
                            "digest": "anymap"}),
        "statement_sha256": "hex64"},

    # ---------------------------------------------------------- §4.4
    "intent.declared": {
        "intent_id": "str", "source": ("enum", {"inference", "mcp"}),
        "provider": "str", "model?": "str", "via_effect": "str",
        "tool": "str", "class": "str",
        "executor": ("enum", {"sandbox", "provider"}),
        "input_sha256": "hex64", "input_len": "int",
        "input_preview?": "str", "anchor_sha256?": "hex64"},
    "intent.result": {
        "intent_id": "str", "via_effect": "str",
        "closed_by": ("enum", {"tool_result", "seal", "timeout"}),
        "content_sha256?": "hex64", "content_len?": "int",
        "is_error?": "bool"},
    "intent.unparsed": {"via_effect": "str", "provider": "str",
                        "detail": "str"},
    "context.observed": {
        "via_effect": "str", "provider": "str", "model?": "str",
        "block_count": "int", "context_sha256": "hex64",
        "new_blocks": ("list", ("obj", {"index": "int", "role": "str",
                                        "kind": "str", "sha256": "hex64",
                                        "len": "int", "intent_id?": "str"}))},
    "taint.added": {"label": "str",
                    "source": ("enum", {"effect", "provider-tool", "initial"}),
                    "source_effect?": "str", "source_grant?": "str"},
    "mcp.call.begin": {"call_id": "str", "caller_session": "str",
                       "caller_world": "str", "caller_effect": "str",
                       "tool": "str", "arguments_sha256": "hex64",
                       "contract_args": "anymap"},
    "mcp.call.end": {"call_id": "str", "is_error": "bool",
                     "result_sha256": "hex64"},
    "mcp.tools": {"server": "str",
                  "tools": ("list", ("obj", {"name": "str",
                                             "annotations": "anymap",
                                             "schema_sha256": "hex64"}))},
    "replay.divergence": {
        "position": "int",
        "expected?": ("obj", {"effect_id": "str",
                              "request_digest": "hex64"}),
        "observed": ("obj", {"method": "str", "authority": "str",
                             "path": "str", "request_digest?": "hex64",
                             "class": "str"}),
        "policy_decision": "str"},
}

COMMON_FIELDS = {"v", "type", "id", "session", "emitter", "eseq", "eprev",
                 "ts", "body"}


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _check(v, spec, where, record):
    if spec == "any":
        return
    if spec == "anymap":
        if not isinstance(v, dict):
            raise VerifyError("E_SCHEMA", f"{where}: not an object", record)
        return
    if isinstance(spec, tuple):
        tag = spec[0]
        if tag == "enum":
            # bools are ints in Python: require an exact type match too so
            # 1 does not satisfy ("enum", {True}).
            if not any(type(v) is type(m) and v == m for m in spec[1]):
                raise VerifyError("E_SCHEMA",
                                  f"{where}: {v!r} not in {sorted(spec[1])}",
                                  record)
            return
        if tag == "list":
            if not isinstance(v, list):
                raise VerifyError("E_SCHEMA", f"{where}: not a list", record)
            for i, item in enumerate(v):
                _check(item, spec[1], f"{where}[{i}]", record)
            return
        if tag == "obj":
            if not isinstance(v, dict):
                raise VerifyError("E_SCHEMA", f"{where}: not an object", record)
            for fname in v:
                base = fname + "?" if fname + "?" in spec[1] else fname
                if base not in spec[1]:
                    raise VerifyError("E_SCHEMA",
                                      f"{where}: unknown field {fname!r}",
                                      record)
            for fname, fspec in spec[1].items():
                optional = fname.endswith("?")
                key = fname[:-1] if optional else fname
                if key not in v:
                    if not optional:
                        raise VerifyError("E_SCHEMA",
                                          f"{where}: missing {key!r}", record)
                    continue
                val = v[key]
                if val is None and optional:
                    continue
                _check(val, fspec, f"{where}.{key}", record)
            return
        raise VerifyError("E_SCHEMA", f"{where}: bad spec {spec!r}", record)
    if spec == "str":
        if not isinstance(v, str):
            raise VerifyError("E_SCHEMA", f"{where}: not a string", record)
    elif spec == "int":
        if not _is_int(v):
            raise VerifyError("E_SCHEMA", f"{where}: not an integer", record)
    elif spec == "num":
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise VerifyError("E_SCHEMA", f"{where}: not a number", record)
    elif spec == "bool":
        if not isinstance(v, bool):
            raise VerifyError("E_SCHEMA", f"{where}: not a boolean", record)
    elif spec == "hex64":
        strict.check_hex(v, 64, where, record)
    elif spec == "ts":
        strict.parse_ts(v, where, record)
    else:
        raise VerifyError("E_SCHEMA", f"{where}: bad spec {spec!r}", record)


def validate(predicate, record=None):
    """Validate common predicate fields + per-type body. Returns
    (type, emitter_role, eseq, eprev, ts_(sec,nanos), body)."""
    if not isinstance(predicate, dict):
        raise VerifyError("E_SCHEMA", "predicate: not an object", record)
    unknown = set(predicate) - COMMON_FIELDS
    if unknown:
        raise VerifyError("E_SCHEMA",
                          f"predicate: unknown fields {sorted(unknown)}", record)
    for req in ("v", "type", "id", "session", "emitter", "eseq", "eprev",
                "ts", "body"):
        if req not in predicate:
            raise VerifyError("E_SCHEMA", f"predicate: missing {req!r}", record)
    if predicate["v"] != 1 or not _is_int(predicate["v"]):
        raise VerifyError("E_SCHEMA", "predicate.v != 1", record)
    rtype = predicate["type"]
    if not isinstance(rtype, str) or rtype not in SCHEMA:
        raise VerifyError("E_SCHEMA", f"unknown record type {rtype!r}", record)
    if not isinstance(predicate["id"], str) or not predicate["id"]:
        raise VerifyError("E_SCHEMA", "predicate.id: not a string", record)
    if not isinstance(predicate["session"], str) or not predicate["session"]:
        raise VerifyError("E_SCHEMA", "predicate.session: not a string", record)
    em = predicate["emitter"]
    parts = em.split("/", 1) if isinstance(em, str) else []
    if len(parts) != 2 or parts[0] not in _ROLES or not parts[1]:
        raise VerifyError("E_SCHEMA",
                          f"emitter {em!r}: must be <role>/<instance> with role "
                          f"in {sorted(_ROLES)}", record)
    if not _is_int(predicate["eseq"]) or predicate["eseq"] < 0:
        raise VerifyError("E_SCHEMA", "eseq: not a non-negative int", record)
    strict.check_hex(predicate["eprev"], 64, "eprev", record)
    ts = strict.parse_ts(predicate["ts"], "ts", record)
    body = predicate["body"]
    if not isinstance(body, dict):
        raise VerifyError("E_SCHEMA", "body: not an object", record)
    _check(body, ("obj", SCHEMA[rtype]), "body", record)
    if rtype == "effect.exec" and len(body.get("argv_sha256", [])) > 64:
        raise VerifyError("E_SCHEMA", "argv_sha256: more than 64 entries",
                          record)
    if rtype == "effect.http" and body.get("actor") == "sandbox" \
            and body.get("purpose") is not None:
        raise VerifyError("E_SCHEMA",
                          "purpose is world-actor-only but actor is sandbox",
                          record)
    return rtype, parts[0], predicate["eseq"], predicate["eprev"], ts, body
