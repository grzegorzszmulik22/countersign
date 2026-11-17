// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/mlog"
)

// Bundle member names of 03 §7. Order is deterministic (sorted).
var requiredEntries = []string{
	"manifest.json", "keys.json", "records.jsonl", "index.json", "checkpoint.txt",
}

// optionalEntry reports whether a tar member name is permitted beyond the
// required set.
func optionalEntry(name string) bool {
	if name == "policy.yaml" || name == "cosignatures.txt" {
		return true
	}
	for _, p := range []string{"contracts/", "reviews/", "attestations/"} {
		if len(name) > len(p) && name[:len(p)] == p {
			return true
		}
	}
	return false
}

// IndexEntry is index.json: the log index and inclusion proof of one record.
type IndexEntry struct {
	LogIndex       uint64   `json:"log_index"`
	InclusionProof []string `json:"inclusion_proof"` // base64, 32 bytes each
}

// BundleManifest is manifest.json.
type BundleManifest struct {
	BundleVersion int    `json:"bundle_version"`
	Session       string `json:"session"`
	LogOrigin     string `json:"log_origin"`
	Created       string `json:"created"`
}

// ExportBundle produces the deterministic tar of 03 §7 for one session.
// extras supplies policy.yaml / contracts/*.yaml / reviews/*.json /
// attestations/*.json bytes whose digests the records name. The checkpoint
// covers session.seal when present, else the current tree size.
func (l *Ledger) ExportBundle(session string, m keys.Manifest, extras map[string][]byte) ([]byte, error) {
	idxs, err := l.SessionIndices(session)
	if err != nil {
		return nil, err
	}
	if len(idxs) == 0 {
		return nil, fmt.Errorf("session %s has no records", session)
	}
	lines := make([][]byte, len(idxs))
	types := make([]string, len(idxs))
	for i, idx := range idxs {
		lines[i], err = l.Line(idx)
		if err != nil {
			return nil, err
		}
		_, _, r, err := evidence.DecodeRecordLine(lines[i])
		if err != nil {
			return nil, fmt.Errorf("log index %d undecodable: %w", idx, err)
		}
		types[i] = r.Type
	}

	// The checkpoint covers session.seal when the session is sealed;
	// otherwise the current head. Deterministic: a pure function of content.
	cpSize := l.tree.Size()
	lastTS := ""
	sealIdx := uint64(0)
	sealed := false
	for i, t := range types {
		_, _, r, _ := evidence.DecodeRecordLine(lines[i])
		lastTS = r.TS
		if t == "session.seal" {
			sealIdx = idxs[i]
			sealed = true
		}
	}
	if sealed {
		cpSize = sealIdx + 1
	}
	cp := &mlog.Checkpoint{Origin: l.origin, Size: cpSize,
		Root: l.treeRootAt(cpSize)}
	var cpData []byte
	if p := filepath.Join(l.dir, cpDir, fmt.Sprintf("%d.txt", cpSize)); fileExists(p) {
		if cpData, err = os.ReadFile(p); err != nil {
			return nil, err
		}
	} else if l.signer != nil {
		if cpData, err = mlog.SignCheckpoint(cp, l.signer); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("no stored checkpoint and no signer")
	}

	index := make([]IndexEntry, len(idxs))
	for i, idx := range idxs {
		p, err := l.inclusionAt(idx, cpSize)
		if err != nil {
			return nil, err
		}
		proof := make([]string, len(p))
		for j, h := range p {
			proof[j] = base64.StdEncoding.EncodeToString(h)
		}
		index[i] = IndexEntry{LogIndex: idx, InclusionProof: proof}
	}
	keysJSON, err := keys.MarshalManifest(m)
	if err != nil {
		return nil, err
	}
	manJSON, err := json.Marshal(BundleManifest{
		BundleVersion: 1, Session: session,
		LogOrigin: l.origin, Created: lastTS,
	})
	if err != nil {
		return nil, err
	}
	manJSON = append(manJSON, '\n')
	idxJSON, err := json.Marshal(index)
	if err != nil {
		return nil, err
	}
	idxJSON = append(idxJSON, '\n')
	var recBuf bytes.Buffer
	for _, line := range lines {
		recBuf.Write(line)
		recBuf.WriteByte('\n')
	}

	members := map[string][]byte{
		"manifest.json":  manJSON,
		"keys.json":      keysJSON,
		"records.jsonl":  recBuf.Bytes(),
		"index.json":     idxJSON,
		"checkpoint.txt": cpData,
	}
	for name, data := range extras {
		if !optionalEntry(name) {
			return nil, fmt.Errorf("extra member %q not permitted in a bundle", name)
		}
		members[name] = data
	}
	return writeTar(members)
}

// treeRootAt returns MTH over the first n stored leaf hashes.
func (l *Ledger) treeRootAt(n uint64) [32]byte {
	data, err := os.ReadFile(filepath.Join(l.dir, hashesFile))
	if err != nil || uint64(len(data)) < n*32 {
		// Fall back to the in-memory tree only when it is exactly the target.
		if l.tree.Size() == n {
			return l.tree.Root()
		}
		return [32]byte{}
	}
	leaves := make([][32]byte, n)
	for i := uint64(0); i < n; i++ {
		copy(leaves[i][:], data[i*32:i*32+32])
	}
	return mlog.RootOf(leaves)
}

// inclusionAt returns the audit path of idx in the size-n tree, generated
// from stored leaf hashes.
func (l *Ledger) inclusionAt(idx, n uint64) ([][]byte, error) {
	data, err := os.ReadFile(filepath.Join(l.dir, hashesFile))
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) < n*32 || idx >= n {
		return nil, fmt.Errorf("inclusion proof for %d in tree %d impossible", idx, n)
	}
	leaves := make([][32]byte, n)
	for i := uint64(0); i < n; i++ {
		copy(leaves[i][:], data[i*32:i*32+32])
	}
	return mlog.InclusionOf(leaves, idx)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// writeTar serializes members sorted by name with zeroed mtime/uid/gid —
// deterministic by construction (03 §7). A failed header or member write
// would corrupt the archive, so every tar.Writer error propagates.
func writeTar(members map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(members))
	for n := range members {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range names {
		data := members[n]
		if err := tw.WriteHeader(&tar.Header{
			Name: n, Mode: 0o644, Size: int64(len(data)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			return nil, fmt.Errorf("tar header for %q: %w", n, err)
		}
		if _, err := tw.Write(data); err != nil {
			return nil, fmt.Errorf("tar member %q: %w", n, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("tar close: %w", err)
	}
	return buf.Bytes(), nil
}

// Bundle reader limits (03 §10 V1): a verifier must never allocate more
// memory than the input could legitimately contain, so a declared member
// size is checked against the bytes remaining AND against hard caps.
const (
	// MaxMemberBytes bounds one tar member's payload.
	MaxMemberBytes int64 = 256 << 20 // 256 MiB
	// MaxTotalBytes bounds the sum of member payloads.
	MaxTotalBytes int64 = 1 << 30 // 1 GiB
	// MaxMembers bounds the member count of an archive.
	MaxMembers = 4096
)

// countingReader reports how many bytes have been consumed.
type countingReader struct {
	r *bytes.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// ReadBundle parses a bundle tar into its members. Malformed archives —
// truncated headers or members, bad checksums, trailing garbage, members
// whose declared size exceeds the remaining input or the documented
// limits — plus missing required entries and unknown extra entries are
// all E_BUNDLE-class errors surfaced as *BundleError. The reader never
// allocates more than the bytes actually present.
func ReadBundle(data []byte) (map[string][]byte, error) {
	if len(data) == 0 {
		return nil, &BundleError{"empty bundle"}
	}
	cr := &countingReader{r: bytes.NewReader(data)}
	tr := tar.NewReader(cr)
	members := map[string][]byte{}
	var order []string
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, &BundleError{fmt.Sprintf("malformed archive: %v", err)}
		}
		if len(order) >= MaxMembers {
			return nil, &BundleError{fmt.Sprintf("more than %d members", MaxMembers)}
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, &BundleError{fmt.Sprintf("member %q is not a regular file", hdr.Name)}
		}
		if _, dup := members[hdr.Name]; dup {
			return nil, &BundleError{fmt.Sprintf("duplicate member %q", hdr.Name)}
		}
		if hdr.Size < 0 {
			return nil, &BundleError{fmt.Sprintf("member %q: negative size %d", hdr.Name, hdr.Size)}
		}
		if hdr.Size > MaxMemberBytes {
			return nil, &BundleError{fmt.Sprintf("member %q: size %d exceeds %d-byte limit", hdr.Name, hdr.Size, MaxMemberBytes)}
		}
		if remaining := int64(len(data)) - cr.n; hdr.Size > remaining {
			return nil, &BundleError{fmt.Sprintf("member %q: declared size %d exceeds %d bytes remaining", hdr.Name, hdr.Size, remaining)}
		}
		if total+hdr.Size > MaxTotalBytes {
			return nil, &BundleError{fmt.Sprintf("members exceed %d-byte total limit", MaxTotalBytes)}
		}
		buf := make([]byte, hdr.Size)
		if _, err := readFull(tr, buf); err != nil {
			return nil, &BundleError{fmt.Sprintf("member %q: %v", hdr.Name, err)}
		}
		total += hdr.Size
		members[hdr.Name] = buf
		order = append(order, hdr.Name)
	}
	// V1: nothing but zero padding may follow the end-of-archive marker;
	// the tar reader itself stops at the marker and would not see it.
	if tail := data[cr.n:]; len(tail) > 0 {
		for _, b := range tail {
			if b != 0 {
				return nil, &BundleError{"trailing garbage after end of archive"}
			}
		}
	}
	for _, req := range requiredEntries {
		if _, ok := members[req]; !ok {
			return nil, &BundleError{fmt.Sprintf("missing required member %q", req)}
		}
	}
	for _, name := range order {
		ok := optionalEntry(name)
		for _, req := range requiredEntries {
			if name == req {
				ok = true
			}
		}
		if !ok {
			return nil, &BundleError{fmt.Sprintf("unexpected member %q", name)}
		}
	}
	if _, err := parseManifest(members["manifest.json"]); err != nil {
		return nil, &BundleError{err.Error()}
	}
	return members, nil
}

// BundleError is the E_BUNDLE error class.
type BundleError struct{ msg string }

func (e *BundleError) Error() string { return e.msg }

// parseManifest strictly decodes manifest.json.
func parseManifest(data []byte) (*BundleManifest, error) {
	var m BundleManifest
	if err := strictJSON(data, &m); err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	if m.BundleVersion != 1 || m.Session == "" || m.LogOrigin == "" || m.Created == "" {
		return nil, fmt.Errorf("manifest.json missing required fields")
	}
	return &m, nil
}

func readFull(tr *tar.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := tr.Read(buf[n:])
		n += m
		if err != nil {
			if n == len(buf) {
				return n, nil
			}
			return n, err
		}
	}
	return n, nil
}

// ParseIndex strictly decodes index.json.
func ParseIndex(data []byte) ([]IndexEntry, error) {
	var ix []IndexEntry
	if err := strictJSON(data, &ix); err != nil {
		return nil, fmt.Errorf("index.json: %w", err)
	}
	for _, e := range ix {
		for _, p := range e.InclusionProof {
			b, err := base64.StdEncoding.DecodeString(p)
			if err != nil || len(b) != 32 {
				return nil, fmt.Errorf("index.json: proof node not 32-byte base64")
			}
		}
	}
	return ix, nil
}

// strictJSON is the bundle-reader's strict decoder: unknown fields rejected.
func strictJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing JSON")
	}
	return nil
}
