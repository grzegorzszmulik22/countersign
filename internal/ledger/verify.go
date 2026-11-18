// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"

	"fmt"
	"sort"
	"strings"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/mlog"
)

// Finding is one error, warning, or finding row of the verifier output.
type Finding struct {
	Code   string `json:"code"`
	Index  *int   `json:"index,omitempty"`
	Detail string `json:"detail"`
}

// VerifyResult is the csverify JSON output of 03 §10.
type VerifyResult struct {
	Verdict  string         `json:"verdict"`
	Boundary *string        `json:"boundary"`
	World    string         `json:"world"`
	Errors   []Finding      `json:"errors"`
	Warnings []Finding      `json:"warnings"`
	Findings []Finding      `json:"findings"`
	Stats    map[string]any `json:"stats"`
}

func errf(code, detail string, args ...any) Finding {
	return Finding{Code: code, Detail: fmt.Sprintf(detail, args...)}
}

func errfAt(code string, i int, detail string, args ...any) Finding {
	f := errf(code, detail, args...)
	f.Index = &i
	return f
}

// VerifyBundle runs V1–V11 and V15 of 03 §10 over bundle bytes and a
// trusted manifest (--keys). V12–V13 (M6) and V14 (M13) are out of scope.
func VerifyBundle(data []byte, trusted keys.Manifest) *VerifyResult {
	res := &VerifyResult{
		World: "open", Stats: map[string]any{},
		Errors: []Finding{}, Warnings: []Finding{}, Findings: []Finding{},
	}
	// V1 — archive well-formed; required entries present; none extra.
	members, err := ReadBundle(data)
	if err != nil {
		res.Errors = append(res.Errors, errf("E_BUNDLE", "%v", err))
		res.Verdict = "INVALID"
		return res
	}
	return VerifyBundle2(members, trusted)
}

// VerifyBundle2 runs V2–V11 + V15 over already-parsed bundle members.
func VerifyBundle2(members map[string][]byte, trusted keys.Manifest) *VerifyResult {
	res := &VerifyResult{
		World: "open", Stats: map[string]any{},
		Errors: []Finding{}, Warnings: []Finding{}, Findings: []Finding{},
	}
	addErr := func(f Finding) { res.Errors = append(res.Errors, f) }
	man, err := parseManifest(members["manifest.json"])
	if err != nil {
		addErr(errf("E_BUNDLE", "%v", err))
		res.Verdict = "INVALID"
		return res
	}
	res.Stats["session"] = man.Session

	// V2 — every line is a strict DSSE envelope + statement + predicate.
	rawLines := bytes.Split(bytes.TrimSuffix(members["records.jsonl"], []byte("\n")), []byte("\n"))
	if len(members["records.jsonl"]) == 0 {
		rawLines = nil
	}
	recs := make([]decLine, len(rawLines))
	for i, line := range rawLines {
		env, _, r, err := evidence.DecodeRecordLine(line)
		if err != nil {
			addErr(errfAt("E_SCHEMA", i, "%v", err))
			continue
		}
		recs[i] = decLine{line, env, r, true}
	}
	res.Stats["records"] = len(rawLines)

	// V3 — signature under a trusted key, role match, validity window.
	for i, d := range recs {
		if !d.ok {
			continue
		}
		if err := keys.VerifyRecord(d.env, d.rec, trusted); err != nil {
			code := "E_SIG"
			if strings.HasPrefix(err.Error(), "E_KEY") {
				code = "E_KEY"
			}
			addErr(errfAt(code, i, "%v", err))
		}
	}

	// V4 — subject digest and per-record session equal the manifest's.
	wantSubj := evidence.SessionSubject(man.Session).Digest["sha256"]
	for i, d := range recs {
		if !d.ok {
			continue
		}
		st, serr := evidence.UnmarshalStatement(d.env.Payload)
		if serr == nil && (len(st.Subject) != 1 || st.Subject[0].Digest["sha256"] != wantSubj) {
			addErr(errfAt("E_SESSION", i, "subject digest %q ≠ bundle session", subjDig(st)))
		}
		if d.rec.Session != man.Session {
			addErr(errfAt("E_SESSION", i, "record session %q ≠ %q", d.rec.Session, man.Session))
		}
	}

	// V5 — per-emitter chains.
	cc := evidence.NewChainChecker()
	for i, d := range recs {
		if !d.ok {
			continue
		}
		if err := cc.Add(d.env, d.rec); err != nil {
			addErr(errfAt("E_CHAIN", i, "%v", err))
		}
	}
	heads := map[string]evidence.ChainHead{}
	for _, h := range cc.Heads() {
		heads[h.Emitter] = h
	}
	res.Stats["emitters"] = len(heads)

	// V6 — checkpoint signed by a log key that is no emitter/attestor key;
	// origin matches the bundle's log_origin.
	cp, err := mlog.ParseCheckpoint(members["checkpoint.txt"], trusted)
	if err != nil {
		addErr(errf("E_CHECKPOINT", "%v", err))
	} else if cp.Origin != man.LogOrigin {
		addErr(errf("E_CHECKPOINT", "origin %q ≠ %q", cp.Origin, man.LogOrigin))
	}
	if cp != nil {
		res.Stats["tree_size"] = cp.Size
	}

	// V7 — every inclusion proof verifies; log_index strictly increasing.
	ix, err := ParseIndex(members["index.json"])
	if err != nil {
		addErr(errf("E_BUNDLE", "%v", err))
	} else if len(ix) != len(rawLines) {
		addErr(errf("E_BUNDLE", "index.json has %d entries for %d records", len(ix), len(rawLines)))
	} else {
		var prev int64 = -1
		for i, e := range ix {
			if int64(e.LogIndex) <= prev {
				addErr(errfAt("E_INCLUSION", i, "log_index %d not strictly increasing", e.LogIndex))
			}
			prev = int64(e.LogIndex)
			if cp == nil {
				continue
			}
			proof := make([][]byte, len(e.InclusionProof))
			pok := true
			for j, p := range e.InclusionProof {
				b, err := base64.StdEncoding.DecodeString(p)
				if err != nil || len(b) != 32 {
					addErr(errfAt("E_INCLUSION", i, "proof node %d malformed", j))
					pok = false
					break
				}
				proof[j] = b
			}
			if !pok {
				continue
			}
			if e.LogIndex >= cp.Size {
				addErr(errfAt("E_INCLUSION", i, "log_index %d ≥ checkpoint size %d", e.LogIndex, cp.Size))
				continue
			}
			leaf := mlog.HashLeaf(recs[i].line)
			if err := mlog.VerifyInclusion(e.LogIndex, cp.Size, leaf, proof, cp.Root); err != nil {
				addErr(errfAt("E_INCLUSION", i, "%v", err))
			}
		}
	}

	// V8 — first record is session.open; policy and contracts match digests.
	sealed := false
	var openBody *evidence.SessionOpenBody
	if len(recs) == 0 || !recs[0].ok || recs[0].rec.Type != "session.open" {
		addErr(errf("E_OPEN", "first record is not session.open"))
	} else {
		openBody, _ = recs[0].rec.Body.(*evidence.SessionOpenBody)
		res.Boundary = openBody.Boundary
	}
	if openBody != nil {
		if pol, ok := members["policy.yaml"]; !ok || fmt.Sprintf("%x", sha256.Sum256(pol)) != openBody.PolicyDigest {
			addErr(errf("E_POLICY", "policy.yaml digest ≠ policy_digest %s", openBody.PolicyDigest))
		}
		var contractFiles []string
		for name := range members {
			if strings.HasPrefix(name, "contracts/") {
				contractFiles = append(contractFiles, name)
			}
		}
		sort.Strings(contractFiles)
		got := make([]string, len(contractFiles))
		for i, name := range contractFiles {
			got[i] = fmt.Sprintf("%x", sha256.Sum256(members[name]))
		}
		want := append([]string(nil), openBody.ContractDigests...)
		sort.Strings(want)
		if !equalStrs(got, want) {
			addErr(errf("E_POLICY", "contract digests %v ≠ %v", got, want))
		}
	}

	// V9 — world.closed exists, then session.seal as the last controller
	// record. Otherwise verdict UNSEALED (not an error).
	var sealBody *evidence.SessionSealBody
	worldClosed := false
	lastController := -1
	for i, d := range recs {
		if !d.ok {
			continue
		}
		role, _, _ := evidence.EmitterRole(d.rec.Emitter)
		if role == "controller" {
			lastController = i
		}
		if d.rec.Type == "world.closed" {
			worldClosed = true
			if b, ok := d.rec.Body.(*evidence.WorldClosedBody); ok {
				res.World = b.Outcome
			}
		}
	}
	if lastController >= 0 && recs[lastController].rec.Type == "session.seal" {
		sealBody, _ = recs[lastController].rec.Body.(*evidence.SessionSealBody)
	}
	sealed = worldClosed && sealBody != nil

	// V10 — for each emitter in the seal: final_eseq and head_hash equal the
	// chain's head; no emitter missing; nothing after a sealed head.
	if sealBody != nil {
		claimed := map[string]bool{}
		sealRec := recs[lastController].rec
		for _, se := range sealBody.Emitters {
			claimed[se.Emitter] = true
			h, ok := heads[se.Emitter]
			if !ok {
				addErr(errf("E_SEAL", "seal claims unknown emitter %s", se.Emitter))
				continue
			}
			// The sealing emitter cannot carry its own record hash inside
			// the seal; its entry describes the chain head immediately
			// before session.seal.
			if se.Emitter == sealRec.Emitter {
				if se.FinalEseq+1 != h.FinalEseq || !strings.EqualFold(se.HeadHash, sealRec.Eprev) {
					addErr(errf("E_SEAL", "sealer head %s eseq %d hash %s ≠ pre-seal %d %s",
						se.Emitter, se.FinalEseq, se.HeadHash, h.FinalEseq, sealRec.Eprev))
				}
				continue
			}
			if se.FinalEseq != h.FinalEseq || !strings.EqualFold(se.HeadHash, h.HeadHash) {
				addErr(errf("E_SEAL", "seal head %s eseq %d hash %s ≠ chain %d %s",
					se.Emitter, se.FinalEseq, se.HeadHash, h.FinalEseq, h.HeadHash))
			}
		}
		for e := range heads {
			if !claimed[e] {
				addErr(errf("E_SEAL", "emitter %s missing from session.seal", e))
			}
		}
	}

	// V11 — structure rules of 03 §4.5 in log order.
	addErrs := verifyStructure(recs, lastController)
	res.Errors = append(res.Errors, addErrs...)

	// V15 — warnings.
	res.Warnings = verifyWarnings(recs, sealBody, heads)

	// Verdict, most severe first: INVALID → UNSEALED → LEARN → VIOLATIONS →
	// CLEAN_WITH_DENIALS → CLEAN (03 §10).
	switch {
	case len(res.Errors) > 0:
		res.Verdict = "INVALID"
	case !sealed:
		res.Verdict = "UNSEALED"
	case openBody != nil && openBody.Mode == "learn":
		res.Verdict = "LEARN"
	case hasDenial(recs):
		res.Verdict = "CLEAN_WITH_DENIALS"
	default:
		res.Verdict = "CLEAN"
	}
	return res
}

func subjDig(st *evidence.Statement) string {
	if len(st.Subject) == 0 {
		return ""
	}
	return st.Subject[0].Digest["sha256"]
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
