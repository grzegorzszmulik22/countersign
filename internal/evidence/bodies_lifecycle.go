// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package evidence

import "encoding/json"

// Record bodies of 03 §4.1 — session and world lifecycle.
// cs tags drive the JSON-Schema generator (tools/schemagen) and the sample
// populator (internal/evidence/evtest); they are not used at run time.

func init() {
	registerBody("session.open", func() any { return &SessionOpenBody{} })
	registerBody("sandbox.terminated", func() any { return &SandboxTerminatedBody{} })
	registerBody("world.rewound", func() any { return &WorldRewoundBody{} })
	registerBody("world.closed", func() any { return &WorldClosedBody{} })
	registerBody("session.seal", func() any { return &SessionSealBody{} })
	registerBody("emitter.seal", func() any { return &EmitterSealBody{} })
}

type Principal struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
	Method  string `json:"method"`
}

type SandboxRef struct {
	Namespace    string  `json:"namespace"`
	Pod          string  `json:"pod"`
	PodUID       string  `json:"pod_uid"`
	Node         string  `json:"node"`
	RuntimeClass *string `json:"runtime_class"`
	ImageDigest  string  `json:"image_digest"`
}

type WorldRef struct {
	ID    string  `json:"id" cs:"ulid"`
	Group *string `json:"group"`
}

type SessionStart struct {
	Workspace json.RawMessage `json:"workspace"`
}

type TapeConf struct {
	Enabled        bool    `json:"enabled"`
	RecipientKeyID *string `json:"recipient_key_id"`
}

type ReplayConf struct {
	SourceSession string `json:"source_session" cs:"ulid"`
	Mode          string `json:"mode" cs:"enum:exact|model|intervene"`
}

type SessionOpenBody struct {
	Kind            string       `json:"kind" cs:"enum:agent|mcp-server|undo|replay"`
	ParentSession   *string      `json:"parent_session" cs:"ulid"`
	ParentSealHash  *string      `json:"parent_seal_hash" cs:"hex64"`
	Principal       Principal    `json:"principal"`
	Sandbox         SandboxRef   `json:"sandbox"`
	Mode            string       `json:"mode" cs:"enum:enforce|audit|learn"`
	PolicyDigest    string       `json:"policy_digest" cs:"hex64"`
	ContractDigests []string     `json:"contract_digests" cs:"hex64"`
	CACertSHA256    string       `json:"ca_cert_sha256" cs:"hex64"`
	LogOrigin       string       `json:"log_origin"`
	Boundary        *string      `json:"boundary" cs:"enum:enforced|cooperative"`
	World           WorldRef     `json:"world"`
	Start           SessionStart `json:"start"`
	Tape            TapeConf     `json:"tape"`
	Replay          *ReplayConf  `json:"replay"`
}

type SandboxTerminatedBody struct {
	Reason string `json:"reason"`
}

type WorldRewoundBody struct {
	ToJournalSeq   uint64   `json:"to_journal_seq"`
	DroppedEntries []string `json:"dropped_entries"`
	UndoID         *string  `json:"undo_id"`
}

type WorldClosedBody struct {
	Outcome string   `json:"outcome" cs:"enum:committed|aborted|partial|superseded|expired|empty"`
	Commits []string `json:"commits"`
}

type SealEmitter struct {
	Emitter   string `json:"emitter" cs:"emitter"`
	FinalEseq uint64 `json:"final_eseq"`
	HeadHash  string `json:"head_hash" cs:"hex64"`
	Clean     bool   `json:"clean"`
}

type SealCounts struct {
	Effects uint64 `json:"effects"`
	Intents uint64 `json:"intents"`
	Denials uint64 `json:"denials"`
	Entries uint64 `json:"entries"`
	Commits uint64 `json:"commits"`
}

type SessionSealBody struct {
	Reason   string        `json:"reason"`
	Emitters []SealEmitter `json:"emitters"`
	Counts   SealCounts    `json:"counts"`
}

type EmitterSealBody struct {
	Final bool `json:"final"`
}
