// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package mlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"github.com/countersign/countersign/internal/keys"
)

// Checkpoint is a C2SP tlog-checkpoint: origin, tree size, root hash,
// carried in a signed note (03 §6).
type Checkpoint struct {
	Origin string
	Size   uint64
	Root   [32]byte
}

// Text is the note body: three newline-terminated lines.
func (c *Checkpoint) Text() []byte {
	return []byte(fmt.Sprintf("%s\n%d\n%s\n",
		c.Origin, c.Size, base64.StdEncoding.EncodeToString(c.Root[:])))
}

// noteKeyHash is the signed-note key hash: first 4 bytes of
// SHA-256(name ‖ "\n" ‖ 0x01 ‖ pubkey) (x/mod sumdb/note § "key hash").
func noteKeyHash(name string, pub []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write([]byte{0x01}) // algEd25519
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

// SignCheckpoint emits the signed-note form:
//
//	<origin>\n<size>\n<b64root>\n
//	\n
//	— <origin> <b64(keyhash4 ‖ sig)>\n
func SignCheckpoint(c *Checkpoint, signer keys.Signer) ([]byte, error) {
	if c.Origin == "" {
		return nil, errors.New("checkpoint needs an origin")
	}
	text := c.Text()
	sig := signer.Sign(text)
	kh := noteKeyHash(c.Origin, signer.Public())
	var hbuf [4]byte
	binary.BigEndian.PutUint32(hbuf[:], kh)
	var b bytes.Buffer
	b.Write(text)
	b.WriteString("\n— ")
	b.WriteString(c.Origin)
	b.WriteByte(' ')
	b.WriteString(base64.StdEncoding.EncodeToString(append(hbuf[:], sig...)))
	b.WriteByte('\n')
	return b.Bytes(), nil
}

// ParseCheckpoint decodes a signed-note checkpoint and verifies its single
// signature against the manifest (V6): the key must carry role `log` and
// must not be any emitter or attestor key.
func ParseCheckpoint(data []byte, m keys.Manifest) (*Checkpoint, error) {
	text, rest, ok := bytes.Cut(data, []byte("\n\n"))
	if !ok || !bytes.HasPrefix(rest, []byte("— ")) {
		return nil, errors.New("malformed checkpoint: no signature block")
	}
	msg := append(text, '\n')
	siglines := bytes.Split(bytes.TrimSuffix(rest, []byte("\n")), []byte("\n"))
	if len(siglines) != 1 {
		return nil, errors.New("checkpoint must carry exactly one signature")
	}
	line := bytes.TrimPrefix(siglines[0], []byte("— "))
	name, b64s, ok := bytes.Cut(line, []byte(" "))
	if !ok {
		return nil, errors.New("malformed signature line")
	}
	raw, err := base64.StdEncoding.DecodeString(string(b64s))
	if err != nil || len(raw) != 4+ed25519.SignatureSize {
		return nil, errors.New("malformed signature bytes")
	}
	keyHash, sig := binary.BigEndian.Uint32(raw[:4]), raw[4:]

	var cp Checkpoint
	lines := bytes.Split(msg, []byte("\n"))
	if len(lines) != 4 || len(lines[3]) != 0 {
		return nil, errors.New("checkpoint body must be exactly three lines")
	}
	cp.Origin = string(lines[0])
	if cp.Origin == "" || string(name) != cp.Origin {
		return nil, errors.New("checkpoint signer name must be the origin")
	}
	if cp.Size, err = strconv.ParseUint(string(lines[1]), 10, 64); err != nil {
		return nil, fmt.Errorf("bad tree size: %w", err)
	}
	root, err := base64.StdEncoding.DecodeString(string(lines[2]))
	if err != nil || len(root) != 32 {
		return nil, errors.New("bad root hash")
	}
	copy(cp.Root[:], root)

	// V6: find the manifest key that produced this signature line.
	for _, e := range m {
		pub, err := e.Public()
		if err != nil {
			return nil, err
		}
		if noteKeyHash(cp.Origin, pub) != keyHash {
			continue
		}
		if e.Role != "log" {
			return nil, fmt.Errorf("checkpoint key %s has role %q, want log", e.KeyID, e.Role)
		}
		if !ed25519.Verify(pub, msg, sig) {
			return nil, errors.New("checkpoint signature invalid")
		}
		return &cp, nil
	}
	return nil, errors.New("checkpoint signed by an unknown key")
}
