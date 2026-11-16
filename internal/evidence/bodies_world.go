// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package evidence

import "encoding/json"

// Record bodies of 03 §4.3 — the world.

func init() {
	registerBody("stage.entry", func() any { return &StageEntryBody{} })
	registerBody("prestate.captured", func() any { return &PrestateCapturedBody{} })
	registerBody("commit.requested", func() any { return &CommitRequestedBody{} })
	registerBody("commit.decision", func() any { return &CommitDecisionBody{} })
	registerBody("commit.applied", func() any { return &CommitAppliedBody{} })
	registerBody("commit.closed", func() any { return &CommitClosedBody{} })
	registerBody("probation.ratified", func() any { return &ProbationRatifiedBody{} })
	registerBody("undo.requested", func() any { return &UndoRequestedBody{} })
	registerBody("undo.applied", func() any { return &UndoAppliedBody{} })
	registerBody("undo.closed", func() any { return &UndoClosedBody{} })
	registerBody("attestation.issued", func() any { return &AttestationIssuedBody{} })
}

type StageEntryBody struct {
	EntryID       string          `json:"entry_id"`
	JournalSeq    uint64          `json:"journal_seq"`
	ViaEffect     string          `json:"via_effect"`
	ViaSession    *string         `json:"via_session" cs:"ulid"`
	ViaRecordHash *string         `json:"via_record_hash" cs:"hex64"`
	Entry         json.RawMessage `json:"entry" cs:"raw"`
	EntrySHA256   string          `json:"entry_sha256" cs:"hex64"`
	Supersedes    *string         `json:"supersedes"`
}

type PrestateCapturedBody struct {
	ForEffect   string  `json:"for_effect"`
	ForSession  *string `json:"for_session" cs:"ulid"`
	When        string  `json:"when" cs:"enum:before|after"`
	ViaEffect   string  `json:"via_effect"`
	Status      int64   `json:"status"`
	StateSHA256 string  `json:"state_sha256" cs:"hex64"`
	Len         uint64  `json:"len"`
	Etag        *string `json:"etag"`
}

type InvariantResult struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
}

type CommitRequestedBody struct {
	CommitID      string            `json:"commit_id"`
	Trigger       string            `json:"trigger" cs:"enum:agent|operator|session-end|barrier|held-effect"`
	Entries       []string          `json:"entries"`
	ChangesetRoot string            `json:"changeset_root" cs:"hex64"`
	ReviewSHA256  string            `json:"review_sha256" cs:"hex64"`
	Invariants    []InvariantResult `json:"invariants"`
	AutoEligible  bool              `json:"auto_eligible"`
	ExpiresAt     string            `json:"expires_at" cs:"ts"`
}

type ProbationWindow struct {
	Until    string `json:"until" cs:"ts"`
	OnExpiry string `json:"on_expiry" cs:"enum:keep|revert"`
}

// WebAuthnAssert carries the fields of a WebAuthn assertion recorded in
// commit.decision, undo.requested and probation.ratified (03 §4.3). The
// binary values are standard base64.
type WebAuthnAssert struct {
	KeyID             string `json:"key_id"`
	AuthenticatorData string `json:"authenticator_data"`
	ClientDataJSON    string `json:"client_data_json"`
	Signature         string `json:"signature"`
}

type DelegateSig struct {
	KeyID     string `json:"key_id" cs:"hex32"`
	Signature string `json:"signature"`
}

type CommitDecisionBody struct {
	CommitID     string           `json:"commit_id"`
	Decision     string           `json:"decision" cs:"enum:commit|reject|timeout"`
	By           string           `json:"by" cs:"enum:auto|human|delegate"`
	Selected     []string         `json:"selected"`
	SelectedRoot string           `json:"selected_root" cs:"hex64"`
	ReviewSHA256 string           `json:"review_sha256" cs:"hex64"`
	ExpiresAt    string           `json:"expires_at" cs:"ts"`
	Probation    *ProbationWindow `json:"probation"`
	WebAuthn     *WebAuthnAssert  `json:"webauthn"`
	Delegate     *DelegateSig     `json:"delegate"`
}

// Precondition is the apply/compensation guard recorded with commit.applied
// (03 §4.3). Expected and Observed are values defined by the stager
// (05 §9–§10) and stay uninterpreted here.
type Precondition struct {
	Kind     string          `json:"kind"`
	Expected json.RawMessage `json:"expected" cs:"raw"`
	Observed json.RawMessage `json:"observed" cs:"raw"`
}

type CommitAppliedBody struct {
	CommitID     string            `json:"commit_id"`
	EntryID      string            `json:"entry_id"`
	Outcome      string            `json:"outcome" cs:"enum:applied|conflict|failed|unknown"`
	ViaEffect    *string           `json:"via_effect"`
	Precondition Precondition      `json:"precondition"`
	IDMap        map[string]string `json:"id_map" cs:"nullable"`
}

type CommitClosedBody struct {
	CommitID string `json:"commit_id"`
	Outcome  string `json:"outcome" cs:"enum:committed|partial|rejected|expired|rolled-back"`
}

type ProbationRatifiedBody struct {
	CommitID string         `json:"commit_id"`
	WebAuthn WebAuthnAssert `json:"webauthn"`
}

type UndoRequestedBody struct {
	UndoID   string          `json:"undo_id"`
	Scope    string          `json:"scope" cs:"enum:session|commit|effect"`
	Targets  []string        `json:"targets"`
	Trigger  string          `json:"trigger" cs:"enum:operator|probation-expired|probation-revoked|group-superseded|commit-failure|rewind"`
	WebAuthn *WebAuthnAssert `json:"webauthn"`
}

// UndoPrecondition lacks the kind field of Precondition (03 §4.3 lists only
// expected and observed for undo.applied).
type UndoPrecondition struct {
	Expected json.RawMessage `json:"expected" cs:"raw"`
	Observed json.RawMessage `json:"observed" cs:"raw"`
}

type UndoAppliedBody struct {
	UndoID       string           `json:"undo_id"`
	Target       string           `json:"target"`
	Outcome      string           `json:"outcome" cs:"enum:restored|conflict|not-compensable|failed"`
	ViaEffect    *string          `json:"via_effect"`
	Precondition UndoPrecondition `json:"precondition"`
}

type UndoClosedBody struct {
	UndoID         string `json:"undo_id"`
	Restored       uint64 `json:"restored"`
	Conflicts      uint64 `json:"conflicts"`
	NotCompensable uint64 `json:"not_compensable"`
	Failed         uint64 `json:"failed"`
}

type AttestSubject struct {
	Kind   string            `json:"kind"`
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type AttestationIssuedBody struct {
	CommitID        string        `json:"commit_id"`
	EntryID         string        `json:"entry_id"`
	Subject         AttestSubject `json:"subject"`
	StatementSHA256 string        `json:"statement_sha256" cs:"hex64"`
}
