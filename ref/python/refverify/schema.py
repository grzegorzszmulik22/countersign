# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""Record and body field schemas of spec 03 §4, as typed-decode tables.

Each entry maps a record type to the strict shape of its body: field name →
JSON type. Unknown fields, wrong JSON types and bad scalars are rejected by
``strict.go_typed``; ``cs:"enum"``/format tags are documentation, not decode
rules.
"""

_STR = "str"
_INT = "int"
_I64 = "int64"
_U64 = "uint64"
_F64 = "float64"
_BOOL = "bool"
_RAW = "raw"
_B64 = "b64"


def _o(inner):
    return ("opt", inner)


def _ls(inner, gt):
    return ("list", inner, gt)


def _mp(inner, gt):
    return ("map", inner, gt)


def _st(name, fields):
    return ("struct", name, "evidence." + name, fields)


_STRS = _ls(_STR, "[]string")

CLIENT = _st("Client", (("ip", _STR), ("port", _I64)))
DECISION = _st("Decision", (
    ("action", _STR), ("reason", _STR), ("requires", _STR),
    ("grant", _o(_STR)), ("credentials", _STRS), ("would_deny", _o(_STR))))
ATTRIBUTION = _st("Attribution", (
    ("level", _STR), ("intents", _STRS), ("lineage", _STR),
    ("owner", _o(_STR))))
BUDGET = _st("Budget", (("leak_bytes", _U64), ("writes", _U64)))
HTTP_REQUEST = _st("HTTPRequest", (
    ("method", _STR), ("scheme", _STR), ("authority", _STR), ("path", _STR),
    ("query_sha256", _STR), ("query_len", _U64), ("header_names", _STRS),
    ("body_sha256", _o(_STR)), ("body_len", _o(_U64)),
    ("body_deferred", _BOOL)))
HTTP_RESPONSE = _st("HTTPResponse", (
    ("header_names", _STRS), ("body_sha256", _STR), ("body_len", _U64)))
REQUEST_BODY_REF = _st("RequestBodyRef", (("sha256", _STR), ("len", _U64)))
UPSTREAM_REF = _st("UpstreamRef", (
    ("ip", _STR), ("port", _I64), ("tls_version", _o(_STR)),
    ("cert_sha256", _o(_STR))))
TIMING = _st("Timing", (("total_ms", _F64), ("ttfb_ms", _F64)))
CONNECT_DST = _st("ConnectDst", (("ip", _STR), ("port", _I64)))
PRINCIPAL = _st("Principal", (
    ("subject", _STR), ("issuer", _STR), ("method", _STR)))
SANDBOX_REF = _st("SandboxRef", (
    ("namespace", _STR), ("pod", _STR), ("pod_uid", _STR), ("node", _STR),
    ("runtime_class", _o(_STR)), ("image_digest", _STR)))
WORLD_REF = _st("WorldRef", (("id", _STR), ("group", _o(_STR))))
SESSION_START = _st("SessionStart", (("workspace", _RAW),))
TAPE_CONF = _st("TapeConf", (
    ("enabled", _BOOL), ("recipient_key_id", _o(_STR))))
REPLAY_CONF = _st("ReplayConf", (
    ("source_session", _STR), ("mode", _STR)))
SEAL_EMITTER = _st("SealEmitter", (
    ("emitter", _STR), ("final_eseq", _U64), ("head_hash", _STR),
    ("clean", _BOOL)))
SEAL_COUNTS = _st("SealCounts", (
    ("effects", _U64), ("intents", _U64), ("denials", _U64),
    ("entries", _U64), ("commits", _U64)))
CONTEXT_BLOCK = _st("ContextBlock", (
    ("index", _I64), ("role", _STR), ("kind", _STR), ("sha256", _STR),
    ("len", _U64), ("intent_id", _o(_STR))))
MCP_TOOL = _st("MCPTool", (
    ("name", _STR), ("annotations", _RAW), ("schema_sha256", _STR)))
DIVERGENCE_EXPECTED = _st("DivergenceExpected", (
    ("effect_id", _STR), ("request_digest", _STR)))
DIVERGENCE_OBSERVED = _st("DivergenceObserved", (
    ("method", _STR), ("authority", _STR), ("path", _STR),
    ("request_digest", _o(_STR)), ("class", _STR)))
PROBATION_WINDOW = _st("ProbationWindow", (
    ("until", _STR), ("on_expiry", _STR)))
WEBAUTHN_ASSERT = _st("WebAuthnAssert", (
    ("key_id", _STR), ("authenticator_data", _STR),
    ("client_data_json", _STR), ("signature", _STR)))
DELEGATE_SIG = _st("DelegateSig", (("key_id", _STR), ("signature", _STR)))
INVARIANT_RESULT = _st("InvariantResult", (
    ("name", _STR), ("pass", _BOOL), ("detail", _STR)))
PRECONDITION = _st("Precondition", (
    ("kind", _STR), ("expected", _RAW), ("observed", _RAW)))
UNDO_PRECONDITION = _st("UndoPrecondition", (
    ("expected", _RAW), ("observed", _RAW)))
ATTEST_SUBJECT = _st("AttestSubject", (
    ("kind", _STR), ("name", _STR),
    ("digest", _mp(_STR, "map[string]string"))))


def _body(name, fields):
    return _st(name, fields)


BODIES = {
    "session.open": _body("SessionOpenBody", (
        ("kind", _STR), ("parent_session", _o(_STR)),
        ("parent_seal_hash", _o(_STR)), ("principal", PRINCIPAL),
        ("sandbox", SANDBOX_REF), ("mode", _STR), ("policy_digest", _STR),
        ("contract_digests", _STRS), ("ca_cert_sha256", _STR),
        ("log_origin", _STR), ("world", WORLD_REF), ("start", SESSION_START),
        ("tape", TAPE_CONF), ("replay", _o(REPLAY_CONF)))),
    "sandbox.terminated": _body("SandboxTerminatedBody", (("reason", _STR),)),
    "world.rewound": _body("WorldRewoundBody", (
        ("to_journal_seq", _U64), ("dropped_entries", _STRS),
        ("undo_id", _o(_STR)))),
    "world.closed": _body("WorldClosedBody", (
        ("outcome", _STR), ("commits", _STRS))),
    "session.seal": _body("SessionSealBody", (
        ("reason", _STR), ("emitters", _ls(SEAL_EMITTER,
                                           "[]evidence.SealEmitter")),
        ("counts", SEAL_COUNTS))),
    "emitter.seal": _body("EmitterSealBody", (("final", _BOOL),)),
    "effect.http": _body("EffectHTTPBody", (
        ("effect_id", _STR), ("actor", _STR), ("purpose", _o(_STR)),
        ("for", _o(_STR)), ("conn_id", _STR), ("client", CLIENT),
        ("request", HTTP_REQUEST), ("request_digest", _o(_STR)),
        ("class", _STR), ("decision", DECISION),
        ("attribution", ATTRIBUTION), ("taint", _STRS), ("budget", BUDGET),
        ("inspect", _STR))),
    "effect.http.result": _body("EffectHTTPResultBody", (
        ("effect_id", _STR), ("served_by", _STR), ("status", _o(_I64)),
        ("response", HTTP_RESPONSE), ("request_body", REQUEST_BODY_REF),
        ("upstream", _o(UPSTREAM_REF)), ("timing", TIMING),
        ("scrubbed", _U64), ("error", _o(_STR)))),
    "effect.tunnel": _body("EffectTunnelBody", (
        ("effect_id", _STR), ("authority", _STR), ("sni", _o(_STR)),
        ("kind", _STR), ("decision", DECISION))),
    "effect.tunnel.result": _body("EffectTunnelResultBody", (
        ("effect_id", _STR), ("bytes_up", _U64), ("bytes_down", _U64),
        ("duration_ms", _F64), ("error", _o(_STR)))),
    "effect.denied": _body("EffectDeniedBody", (
        ("conn_id", _STR), ("client", CLIENT), ("authority", _o(_STR)),
        ("reason", _STR), ("detail", _STR))),
    "effect.exec": _body("EffectExecBody", (
        ("exec_id", _STR), ("parent_exec_id", _o(_STR)), ("pid", _I64),
        ("binary", _STR), ("argv_sha256", _STRS), ("argv_truncated", _BOOL),
        ("uid", _I64))),
    "effect.connect": _body("EffectConnectBody", (
        ("exec_id", _STR), ("pid", _I64), ("dst", CONNECT_DST),
        ("src_port", _I64), ("proto", _STR), ("outcome", _STR))),
    "observer.gap": _body("ObserverGapBody", (
        ("from", _U64), ("to", _U64), ("reason", _STR))),
    "intent.declared": _body("IntentDeclaredBody", (
        ("intent_id", _STR), ("source", _STR), ("provider", _STR),
        ("model", _o(_STR)), ("via_effect", _STR), ("tool", _STR),
        ("class", _STR), ("executor", _STR), ("input_sha256", _STR),
        ("input_len", _U64), ("input_preview", _o(_STR)),
        ("anchor_sha256", _o(_STR)))),
    "intent.result": _body("IntentResultBody", (
        ("intent_id", _STR), ("via_effect", _STR), ("closed_by", _STR),
        ("content_sha256", _o(_STR)), ("content_len", _o(_U64)),
        ("is_error", _o(_BOOL)))),
    "intent.unparsed": _body("IntentUnparsedBody", (
        ("via_effect", _STR), ("provider", _STR), ("detail", _STR))),
    "context.observed": _body("ContextObservedBody", (
        ("via_effect", _STR), ("provider", _STR), ("model", _o(_STR)),
        ("block_count", _U64), ("context_sha256", _STR),
        ("new_blocks", _ls(CONTEXT_BLOCK, "[]evidence.ContextBlock")))),
    "taint.added": _body("TaintAddedBody", (
        ("label", _STR), ("source", _STR), ("source_effect", _o(_STR)),
        ("source_grant", _o(_STR)))),
    "mcp.call.begin": _body("MCPCallBeginBody", (
        ("call_id", _STR), ("caller_session", _STR), ("caller_world", _STR),
        ("caller_effect", _STR), ("tool", _STR),
        ("arguments_sha256", _STR), ("contract_args", _RAW))),
    "mcp.call.end": _body("MCPCallEndBody", (
        ("call_id", _STR), ("is_error", _BOOL), ("result_sha256", _STR))),
    "mcp.tools": _body("MCPToolsBody", (
        ("server", _STR), ("tools", _ls(MCP_TOOL, "[]evidence.MCPTool")))),
    "replay.divergence": _body("ReplayDivergenceBody", (
        ("position", _U64), ("expected", _o(DIVERGENCE_EXPECTED)),
        ("observed", DIVERGENCE_OBSERVED), ("policy_decision", _STR))),
    "stage.entry": _body("StageEntryBody", (
        ("entry_id", _STR), ("journal_seq", _U64), ("via_effect", _STR),
        ("via_session", _o(_STR)), ("via_record_hash", _o(_STR)),
        ("entry", _RAW), ("entry_sha256", _STR), ("supersedes", _o(_STR)))),
    "prestate.captured": _body("PrestateCapturedBody", (
        ("for_effect", _STR), ("for_session", _o(_STR)), ("when", _STR),
        ("via_effect", _STR), ("status", _I64), ("state_sha256", _STR),
        ("len", _U64), ("etag", _o(_STR)))),
    "commit.requested": _body("CommitRequestedBody", (
        ("commit_id", _STR), ("trigger", _STR), ("entries", _STRS),
        ("changeset_root", _STR), ("review_sha256", _STR),
        ("invariants", _ls(INVARIANT_RESULT, "[]evidence.InvariantResult")),
        ("auto_eligible", _BOOL), ("expires_at", _STR))),
    "commit.decision": _body("CommitDecisionBody", (
        ("commit_id", _STR), ("decision", _STR), ("by", _STR),
        ("selected", _STRS), ("selected_root", _STR),
        ("review_sha256", _STR), ("expires_at", _STR),
        ("probation", _o(PROBATION_WINDOW)), ("webauthn", _o(WEBAUTHN_ASSERT)),
        ("delegate", _o(DELEGATE_SIG)))),
    "commit.applied": _body("CommitAppliedBody", (
        ("commit_id", _STR), ("entry_id", _STR), ("outcome", _STR),
        ("via_effect", _o(_STR)), ("precondition", PRECONDITION),
        ("id_map", _mp(_STR, "map[string]string")))),
    "commit.closed": _body("CommitClosedBody", (
        ("commit_id", _STR), ("outcome", _STR))),
    "probation.ratified": _body("ProbationRatifiedBody", (
        ("commit_id", _STR), ("webauthn", WEBAUTHN_ASSERT))),
    "undo.requested": _body("UndoRequestedBody", (
        ("undo_id", _STR), ("scope", _STR), ("targets", _STRS),
        ("trigger", _STR), ("webauthn", _o(WEBAUTHN_ASSERT)))),
    "undo.applied": _body("UndoAppliedBody", (
        ("undo_id", _STR), ("target", _STR), ("outcome", _STR),
        ("via_effect", _o(_STR)), ("precondition", UNDO_PRECONDITION))),
    "undo.closed": _body("UndoClosedBody", (
        ("undo_id", _STR), ("restored", _U64), ("conflicts", _U64),
        ("not_compensable", _U64), ("failed", _U64))),
    "attestation.issued": _body("AttestationIssuedBody", (
        ("commit_id", _STR), ("entry_id", _STR), ("subject", ATTEST_SUBJECT),
        ("statement_sha256", _STR))),
}

# Envelope / statement / predicate shapes.
SIGNATURE = _st("Signature", (("keyid", _STR), ("sig", _B64)))
ENVELOPE = _st("Envelope", (
    ("payloadType", _STR), ("payload", _B64),
    ("signatures", _ls(SIGNATURE, "[]evidence.Signature"))))
SUBJECT = _st("Subject", (
    ("name", _STR), ("digest", _mp(_STR, "map[string]string"))))
STATEMENT = _st("Statement", (
    ("_type", _STR), ("subject", _ls(SUBJECT, "[]evidence.Subject")),
    ("predicateType", _STR), ("predicate", _RAW)))
PREDICATE = ("struct", "predicateJSON", "evidence.predicateJSON", (
    ("v", _INT), ("type", _STR), ("id", _STR), ("session", _STR),
    ("emitter", _STR), ("eseq", _U64), ("eprev", _STR), ("ts", _STR),
    ("body", _RAW)))

# Bundle-level files.
INDEX_ENTRY = ("struct", "IndexEntry", "ledger.IndexEntry", (
    ("log_index", _U64), ("inclusion_proof", _STRS)))
INDEX = ("list", INDEX_ENTRY, "[]ledger.IndexEntry")
BUNDLE_MANIFEST = ("struct", "BundleManifest", "ledger.BundleManifest", (
    ("bundle_version", _INT), ("session", _STR), ("log_origin", _STR),
    ("created", _STR)))
KEYS_ENTRY = ("struct", "ManifestEntry", "keys.ManifestEntry", (
    ("key_id", _STR), ("role", _STR), ("public_key", _STR),
    ("not_before", _STR), ("not_after", _o(_STR)), ("rp_id", _o(_STR)),
    ("origins", _STRS)))
KEYS_MANIFEST = ("list", KEYS_ENTRY, "keys.Manifest")
