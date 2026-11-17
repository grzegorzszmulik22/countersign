# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""Seeded generator of valid evidence bundles (spec 03 §11, M1.6).

Each session is a random mix of 5–500 records over 1–3 emitters, built
from the same spec-derived fabricator as the C1.5.5 vectors — never from
refverify and never from Go sources. Structure refs (via_effect, for,
intent_id, entry_id, commit_id, undo_id, call_id) only ever point at
records that already exist, so every generated bundle must verify CLEAN
or CLEAN_WITH_DENIALS under both verifiers.

Determinism: all choices come from random.Random(seed); record ids and
timestamps are also seed-derived so reruns reproduce byte-identical
bundles.
"""
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "refverify"))

import genbundle as G  # noqa: E402


class Gen:
    """A seeded valid-session builder on top of genbundle.Session."""

    OTHER = ("broker", "world", "observer")

    def __init__(self, seed, n_records=None, n_emitters=None):
        self.rng = random.Random(seed)
        roles = ["controller"]
        if n_emitters is None:
            n_emitters = self.rng.randint(1, 3)
        extra = list(self.OTHER)
        self.rng.shuffle(extra)
        roles += extra[:n_emitters - 1]
        self.s = G.Session(roles=roles, seed=seed)
        self.n_target = n_records or self.rng.randint(5, 500)
        self.effects = []        # http effect ids with results pending allowed
        self.unresulted = []     # http effects without a result yet
        self.tunnels = []
        self.intents = []
        self.entries = []
        self.commits_req = []
        self.commits_dec = []
        self.undos = []
        self.calls = []
        self.denials = 0

    # -- primitives -------------------------------------------------------
    def _pick(self, xs):
        return self.rng.choice(xs) if xs else None

    def _emitter(self, pref):
        have = [r for r in self.s.roles if r != "controller"]
        return pref if pref in have else (self.rng.choice(have)
                                          if have else "controller")

    def http_effect(self, purpose=None, for_=None, result=True):
        i = len(self.effects) + len(self.unresulted) + 1
        role = self._emitter("broker")
        eid = self.s.effect(i, result=False, purpose=purpose, for_=for_,
                            actor="world" if purpose == "apply" else "sandbox",
                            role=role)
        self.effects.append(eid)
        if result:
            self.s.effect_result(eid, role=role)
        else:
            self.unresulted.append(eid)
        return eid

    def tunnel(self, result=True):
        eid = self.s.eid("tun")
        self.s.emit(self._emitter("broker"), "effect.tunnel", {
            "effect_id": eid, "authority": "a.example", "kind": "passthrough",
            "decision": {"action": "allow", "reason": "OK",
                         "requires": "allow", "credentials": []}})
        self.tunnels.append(eid)
        if result:
            self.s.emit(self._emitter("broker"), "effect.tunnel.result", {
                "effect_id": eid, "bytes_up": 1, "bytes_down": 2,
                "duration_ms": 3.5})
        return eid

    def intent(self):
        via = self._pick(self.effects + self.tunnels)
        if via is None:
            return None
        iid = self.s.eid("int")
        self.s.emit(self._emitter("broker"), "intent.declared", {
            "intent_id": iid, "source": "inference", "provider": "prov",
            "via_effect": via, "tool": "tool", "class": "http",
            "executor": "sandbox",
            "input_sha256": G.sha_hex(b"in"), "input_len": 1})
        self.intents.append(iid)
        if self.rng.random() < 0.7:
            self.s.emit(self._emitter("broker"), "intent.result", {
                "intent_id": iid, "via_effect": via,
                "closed_by": "tool_result"})
        return iid

    def denied(self):
        self.denials += 1
        self.s.emit(self._emitter("broker"), "effect.denied", {
            "conn_id": self.s.eid("cd"), "authority": "x.example",
            "client": {"ip": "10.1.1.1", "port": 1},
            "reason": "DENY_GRANT", "detail": "policy"})

    def observer_pair(self):
        if "observer" not in self.s.roles:
            return
        xid = self.s.eid("ex")
        self.s.emit("observer", "effect.exec", {
            "exec_id": xid, "pid": self.rng.randint(2, 4000),
            "binary": "/bin/x", "argv_sha256": [G.sha_hex(b"a")],
            "argv_truncated": False, "uid": 1000})
        self.s.emit("observer", "effect.connect", {
            "exec_id": xid, "pid": 1,
            "dst": {"ip": "10.0.0.9", "port": 443},
            "src_port": 4000, "proto": "tcp", "outcome": "to-broker"})

    def observer_gap(self):
        if "observer" in self.s.roles:
            self.s.emit("observer", "observer.gap", {
                "from": 1, "to": 2, "reason": "restart"})

    def context_observed(self):
        via = self._pick(self.effects + self.tunnels)
        if via is None:
            return
        self.s.emit(self._emitter("broker"), "context.observed", {
            "via_effect": via, "provider": "p", "block_count": 1,
            "context_sha256": G.sha_hex(b"ctx"), "new_blocks": []})

    def intent_unparsed(self):
        via = self._pick(self.effects + self.tunnels)
        if via is None:
            return
        self.s.emit(self._emitter("broker"), "intent.unparsed", {
            "via_effect": via, "provider": "p", "detail": "d"})

    def taint(self):
        self.s.emit(self._emitter("broker"), "taint.added", {
            "label": "pii", "source": "effect",
            "source_effect": self._pick(self.effects)})

    def mcp(self):
        via = self._pick(self.effects + self.tunnels)
        cid = self.s.eid("mcp")
        self.s.emit(self._emitter("broker"), "mcp.call.begin", {
            "call_id": cid, "caller_session": self.s.sid,
            "caller_world": self.s.sid, "caller_effect": via or "x",
            "tool": "t", "arguments_sha256": G.sha_hex(b"ar"),
            "contract_args": {}})
        self.calls.append(cid)
        if self.rng.random() < 0.8:
            self.s.emit(self._emitter("broker"), "mcp.call.end", {
                "call_id": cid, "is_error": False,
                "result_sha256": G.sha_hex(b"r")})

    def mcp_tools(self):
        self.s.emit(self._emitter("broker"), "mcp.tools", {
            "server": "s", "tools": []})

    def replay_div(self):
        self.s.emit(self._emitter("broker"), "replay.divergence", {
            "position": 1,
            "observed": {"method": "GET", "authority": "a",
                         "path": "/", "class": "safe"},
            "policy_decision": "allow"})

    def stage_commit(self):
        """stage.entry → commit flow → optional apply effect."""
        via = self._pick(self.effects + self.tunnels)
        if via is None or "world" not in self.s.roles:
            return None
        ent = self.s.stage_entry(via)
        self.entries.append(ent)
        cid = self.s.eid("com")
        self.s.emit("world", "commit.requested", {
            "commit_id": cid, "trigger": "agent", "entries": [ent],
            "changeset_root": G.sha_hex(b"cs"),
            "review_sha256": G.sha_hex(b"rev"),
            "invariants": [{"name": "i", "pass": True, "detail": ""}],
            "auto_eligible": True, "expires_at": G.ts(999999)})
        self.commits_req.append(cid)
        self.s.emit("world", "commit.decision", {
            "commit_id": cid, "decision": "commit", "by": "auto",
            "selected": [ent], "selected_root": G.sha_hex(b"cs"),
            "review_sha256": G.sha_hex(b"rev"), "expires_at": G.ts(999999)})
        self.commits_dec.append(cid)
        if self.rng.random() < 0.6:
            eff = self.http_effect(purpose="apply", for_=cid, result=True)
            self.s.emit("world", "commit.applied", {
                "commit_id": cid, "entry_id": ent, "outcome": "applied",
                "via_effect": eff,
                "precondition": {"kind": "etag", "expected": "\"e\"",
                                 "observed": "\"e\""}})
        self.s.emit("world", "commit.closed",
                    {"commit_id": cid, "outcome": "committed"})
        return cid

    def prestate(self):
        """prestate.captured before some still-unresulted http effect."""
        eff = self._pick(self.unresulted)
        via = self._pick(self.effects)
        if eff is None or via is None or "world" not in self.s.roles:
            return
        self.s.emit("world", "prestate.captured", {
            "for_effect": eff, "when": "before", "via_effect": via,
            "status": 200, "state_sha256": G.sha_hex(b"st"), "len": 4})

    def undo(self):
        cid = self._pick(self.commits_dec)
        if cid is None or "world" not in self.s.roles:
            return
        uid = self.s.eid("und")
        self.s.emit("world", "undo.requested", {
            "undo_id": uid, "scope": "commit", "targets": [cid],
            "trigger": "operator"})
        self.undos.append(uid)
        self.s.emit("world", "undo.applied", {
            "undo_id": uid, "target": self._pick(self.entries) or cid,
            "outcome": "restored",
            "precondition": {"expected": "\"e\"", "observed": "\"e\""}})
        self.s.emit("world", "undo.closed", {
            "undo_id": uid, "restored": 1, "conflicts": 0,
            "not_compensable": 0, "failed": 0})

    def attestation(self):
        ent = self._pick(self.entries)
        cid = self._pick(self.commits_dec)
        if ent is None or "world" not in self.s.roles:
            return
        self.s.emit("world", "attestation.issued", {
            "commit_id": cid or "k", "entry_id": ent,
            "subject": {"kind": "file", "name": ent,
                        "digest": {"sha256": G.sha_hex(b"d")}},
            "statement_sha256": G.sha_hex(b"st")})

    def probation(self):
        cid = self._pick(self.commits_dec)
        if cid is None or "world" not in self.s.roles:
            return
        self.s.emit("world", "probation.ratified", {
            "commit_id": cid,
            "webauthn": {"key_id": "k", "authenticator_data": "a",
                         "client_data_json": "c", "signature": "s"}})

    def rewound(self):
        if "world" in self.s.roles:
            self.s.emit("world", "world.rewound", {
                "to_journal_seq": 1, "dropped_entries": []})

    def terminated(self):
        self.s.emit("controller", "sandbox.terminated",
                    {"reason": "done"})

    FLOWS = ("http", "tunnel", "intent", "denied", "observer", "gap",
             "context", "unparsed", "taint", "mcp", "tools", "replay",
             "commit", "prestate", "undo", "attest", "probation", "rewind",
             "terminated")

    def build(self):
        self.s.open()
        weights = {"http": 30, "tunnel": 4, "intent": 8, "denied": 6,
                   "observer": 4, "gap": 1, "context": 4, "unparsed": 2,
                   "taint": 4, "mcp": 4, "tools": 1, "replay": 2,
                   "commit": 10, "prestate": 4, "undo": 3, "attest": 3,
                   "probation": 2, "rewind": 1, "terminated": 1}
        wts = [weights[f] for f in self.FLOWS]
        actions = {
            "http": lambda: self.http_effect(
                result=self.rng.random() < 0.9),
            "tunnel": lambda: self.tunnel(
                result=self.rng.random() < 0.9),
            "intent": self.intent, "denied": self.denied,
            "observer": self.observer_pair, "gap": self.observer_gap,
            "context": self.context_observed,
            "unparsed": self.intent_unparsed, "taint": self.taint,
            "mcp": self.mcp, "tools": self.mcp_tools,
            "replay": self.replay_div, "commit": self.stage_commit,
            "prestate": self.prestate, "undo": self.undo,
            "attest": self.attestation, "probation": self.probation,
            "rewind": self.rewound, "terminated": self.terminated,
        }
        guard = 0
        while len(self.s.lines) < self.n_target - 4 and guard < 100000:
            guard += 1
            actions[self.rng.choices(self.FLOWS, wts)[0]]()
        # Resolve any unresulted effects so the bundle is CLEAN-class
        # (W_DANGLING would still be a CLEAN verdict; resolve for tidy).
        for eid in list(self.unresulted):
            self.s.effect_result(eid, role=self._emitter("broker"))
            self.unresulted.remove(eid)
        if "world" in self.s.roles:
            self.s.close_world(commits=self.commits_dec,
                               outcome="committed")
        else:
            self.s.emit("controller", "world.closed",
                        {"outcome": "empty", "commits": []})
        self.s.emitter_seals()
        self.s.seal()
        return self.s


def session(seed, n_records=None, n_emitters=None):
    """Seeded session → (Session, files, keys)."""
    g = Gen(seed, n_records=n_records, n_emitters=n_emitters)
    s = g.build()
    return s, s.files(), s.key_manifest()
