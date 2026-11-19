// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/countersign/countersign/internal/evidence"
	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/ledger"
	"github.com/countersign/countersign/internal/names"
	"github.com/countersign/countersign/internal/policy"
	"github.com/countersign/countersign/internal/proxy"
)

// defaultPolicy is used when --policy is not given: an
// allow-everything-listed test policy (one credential-less wildcard grant).
var defaultPolicy = "apiVersion: " + names.APIGroup + `/v1alpha1
kind: SessionPolicy
metadata: {name: cs-run-default}
spec:
  mode: enforce
  grants:
    - id: all
      action: allow
      match: {hosts: ["*"]}
`

// session holds everything one run needs between setup and seal.
type session struct {
	id       string
	token    string
	dataDir  string
	runDir   string
	boundary string
	signers  map[string]keys.Signer

	polBytes []byte
	pol      *policy.SessionPolicy

	manifest keys.Manifest
	led      *ledger.Ledger
	ctl      *chainEmitter
	brokerEm *chainEmitter
	worldEm  *chainEmitter
	bridge   *bridgeSink
	worldID  string

	broker       *proxy.Server
	brokerAddr   string
	brokerCancel context.CancelFunc
	relay        *unixRelay
	sessDir      string
	caPath       string
	caPEM        []byte
	placeholders map[string]string // env name → csph_ value
	ambient      []string          // environment the command inherits
	command      []string
	logf         func(string, ...any)
}

func newSession(ctx context.Context, opt Options, dataDir string, ambient []string, boundary string) (*session, error) {
	logf := opt.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	s := &session{
		id:       evidence.NewULID(nil),
		dataDir:  dataDir,
		boundary: boundary,
		worldID:  evidence.NewULID(nil),
		ambient:  ambient,
		command:  opt.Command,
		logf:     logf,
	}
	tok := make([]byte, 16)
	if _, err := rand.Read(tok); err != nil {
		return nil, err
	}
	s.token = hex.EncodeToString(tok)

	// Policy: read the file or synthesise the default.
	var polBytes []byte
	var err error
	if opt.PolicyFile != "" {
		polBytes, err = os.ReadFile(opt.PolicyFile)
		if err != nil {
			return nil, fmt.Errorf("policy: %w", err)
		}
	} else {
		polBytes = []byte(defaultPolicy)
	}
	s.polBytes = polBytes
	if s.pol, err = policy.Load(polBytes); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if s.placeholders, err = placeholdersFor(s.pol, s.id); err != nil {
		return nil, err
	}

	// Runner keys: four persistent Ed25519 signers under the data dir.
	if err := s.loadKeys(); err != nil {
		return nil, err
	}

	// Ledger (the csledger file store role).
	origin := logOrigin(dataDir)
	s.led, err = ledger.Open(filepath.Join(dataDir, "ledger"), origin, s.signer("log"))
	if err != nil {
		return nil, fmt.Errorf("ledger: %w", err)
	}
	s.ctl = newChainEmitter(keys.NewEmitter("controller", s.id, s.signer("controller")), s.led)
	s.brokerEm = newChainEmitter(keys.NewEmitter("broker", s.id, s.signer("broker")), s.led)
	s.worldEm = newChainEmitter(keys.NewEmitter("world", s.id, s.signer("world")), s.led)
	s.bridge = newBridge(s.brokerEm)

	// Session table for the broker's local mode.
	s.sessDir = filepath.Join(dataDir, "sessions", s.id)
	if err := os.MkdirAll(s.sessDir, 0o700); err != nil {
		return nil, err
	}
	polPath := filepath.Join(s.sessDir, "policy.yaml")
	if err := os.WriteFile(polPath, polBytes, 0o600); err != nil {
		return nil, err
	}
	table := "sessions:\n" +
		fmt.Sprintf("  - id: %s\n    token: %s\n    client_ip: 127.0.0.1\n    policy: %s\n",
			s.id, s.token, polPath)
	// The credential store (M3.2) is read only from the hidden data
	// directory, which the sandbox sees as an empty tmpfs: a store passed
	// by path from anywhere else would stay readable inside the sandbox.
	// A policy with credentialed grants and no store fails closed in the
	// broker at session open.
	credPath := filepath.Join(dataDir, CredentialsFile)
	switch _, err := os.Stat(credPath); {
	case err == nil:
		table += fmt.Sprintf("    credentials: %s\n", credPath)
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("credentials: %w", err)
	}
	sessFile := filepath.Join(s.sessDir, "sessions.yaml")
	if err := os.WriteFile(sessFile, []byte(table), 0o600); err != nil {
		return nil, err
	}

	// csbroker --local, in-process via the public API.
	recordsDir := filepath.Join(dataDir, "broker")
	if err := os.MkdirAll(recordsDir, 0o700); err != nil {
		return nil, err
	}
	blog, err := os.OpenFile(filepath.Join(recordsDir, "broker.log"),
		os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	srv, err := proxy.NewServer(proxy.Config{
		SessionsFile: sessFile,
		RecordsDir:   recordsDir,
		Sink:         s.bridge,
		// broker.log is diagnostics only — the proxy API gives no
		// error return for log writes, and a full disk must not
		// take the session down through the logging path.
		Logf: func(f string, a ...any) { _, _ = fmt.Fprintf(blog, f+"\n", a...) },
	})
	if err != nil {
		return nil, fmt.Errorf("broker: %w", err)
	}
	s.broker = srv
	brokerCtx, cancel := context.WithCancel(context.Background())
	s.brokerCancel = cancel
	addr, err := srv.Serve(brokerCtx, "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("broker listen: %w", err)
	}
	s.brokerAddr = addr.String()

	// Sandbox-visible run dir with the session CA.
	if opt.RunDir != "" {
		s.runDir = opt.RunDir
		if err := os.MkdirAll(s.runDir, 0o755); err != nil {
			return nil, err
		}
	} else {
		s.runDir, err = os.MkdirTemp("", "cs-run-*")
		if err != nil {
			return nil, err
		}
	}
	s.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Session(s.id).CACert().Raw})
	s.caPath = filepath.Join(s.runDir, "session-ca.pem")
	if err := os.WriteFile(s.caPath, s.caPEM, 0o644); err != nil {
		return nil, err
	}

	// session.open — first record of the session, boundary declared.
	caSum := sha256.Sum256(srv.Session(s.id).CACert().Raw)
	caDigest := hex.EncodeToString(caSum[:])
	open := &evidence.SessionOpenBody{
		Kind:            "agent",
		ParentSession:   nil,
		ParentSealHash:  nil,
		Principal:       localPrincipal(),
		Sandbox:         localSandbox(),
		Mode:            sessionMode(s.pol),
		PolicyDigest:    s.pol.DigestHex(),
		ContractDigests: []string{},
		CACertSHA256:    caDigest,
		LogOrigin:       origin,
		Boundary:        &boundary,
		World:           evidence.WorldRef{ID: s.worldID},
		Start:           evidence.SessionStart{Workspace: json.RawMessage("null")},
		Tape:            evidence.TapeConf{Enabled: false},
	}
	if err := s.ctl.emit("session.open", open); err != nil {
		return nil, fmt.Errorf("session.open: %w", err)
	}
	return s, nil
}

// spawnAndWait launches the command under the chosen boundary and waits
// for it or for ctx cancellation. On cancellation it drives the kill
// sequence (SIGINT → grace → SIGKILL) before returning.
func (s *session) spawnAndWait(ctx context.Context) (code int, interrupted bool, err error) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var cmd *sandboxCmd
	if s.boundary == boundaryEnforced {
		cmd, err = s.spawnEnforced(runCtx)
	} else {
		cmd, err = s.spawnCooperative(runCtx, s.ambient)
	}
	if err != nil {
		return 0, false, err
	}
	done := make(chan struct{})
	go func() { cmd.wait(); close(done) }()

	select {
	case <-done:
		if err := cmd.envWriteErr(); err != nil {
			return 0, false, fmt.Errorf("ambient env to sandbox: %w", err)
		}
		return cmd.exitCode(), false, nil
	case <-ctx.Done():
		interrupted = true
		cmd.interrupt(done)
		if err := cmd.envWriteErr(); err != nil {
			return 0, true, fmt.Errorf("ambient env to sandbox: %w", err)
		}
		code = cmd.exitCode()
		if code <= 0 {
			code = 130
		}
		return code, true, nil
	}
}

// sealAndBundle writes the closing records and exports the session
// bundle under <dataDir>/bundles/.
func (s *session) sealAndBundle(code int, interrupted bool) (string, error) {
	// Stop the relay and drain the broker so every emitted record is in
	// the ledger before we compute chain heads.
	if s.relay != nil {
		s.relay.close()
	}
	s.brokerCancel()
	if err := s.broker.Close(); err != nil {
		return "", fmt.Errorf("broker close: %w", err)
	}
	if err := s.bridge.err(); err != nil {
		return "", fmt.Errorf("record sink: %w", err)
	}

	reason := "command-exit"
	if interrupted {
		reason = "signal"
	}
	// Broker chain: emitter.seal marks the head.
	if err := s.brokerEm.emit("emitter.seal", &evidence.EmitterSealBody{Final: true}); err != nil {
		return "", err
	}
	// A local session has an empty world.
	if err := s.worldEm.emit("world.closed", &evidence.WorldClosedBody{
		Outcome: "empty", Commits: []string{},
	}); err != nil {
		return "", err
	}
	if err := s.worldEm.emit("emitter.seal", &evidence.EmitterSealBody{Final: true}); err != nil {
		return "", err
	}

	counts, err := s.counts()
	if err != nil {
		return "", err
	}
	seal := &evidence.SessionSealBody{
		Reason:   reason,
		Emitters: []evidence.SealEmitter{s.brokerEm.sealRef(), s.worldEm.sealRef(), s.ctl.sealRef()},
		Counts:   counts,
	}
	if err := s.ctl.emit("session.seal", seal); err != nil {
		return "", err
	}

	bundle, err := s.led.ExportBundle(s.id, s.manifest, map[string][]byte{
		"policy.yaml": s.polBytes,
	})
	if err != nil {
		return "", fmt.Errorf("export bundle: %w", err)
	}
	bundlesDir := filepath.Join(s.dataDir, "bundles")
	if err := os.MkdirAll(bundlesDir, 0o700); err != nil {
		return "", err
	}
	bp := filepath.Join(bundlesDir, s.id+".tar")
	if err := os.WriteFile(bp, bundle, 0o600); err != nil {
		return "", err
	}
	return bp, nil
}

func (s *session) counts() (evidence.SealCounts, error) {
	c := evidence.SealCounts{}
	for _, line := range s.brokerEm.lines() {
		_, _, r, err := evidence.DecodeRecordLine(line)
		if err != nil {
			// These lines came from this emitter — an undecodable
			// one means the chain is already broken, which the
			// seal must not paper over.
			return c, fmt.Errorf("seal counts: %w", err)
		}
		switch r.Type {
		case "effect.http", "effect.tunnel", "effect.exec", "effect.connect":
			c.Effects++
			if b, ok := r.Body.(*evidence.EffectHTTPBody); ok && b.Decision.Action == "deny" {
				c.Denials++
			}
		case "effect.denied":
			c.Denials++
		}
	}
	return c, nil
}

func (s *session) cleanup(logf func(string, ...any)) {
	if s.relay != nil {
		s.relay.close()
	}
	if s.brokerCancel != nil {
		s.brokerCancel()
	}
	if s.led != nil {
		if err := s.led.Close(); err != nil {
			logf("ledger close: %v", err)
		}
	}
}

func (s *session) signer(role string) keys.Signer { return s.signers[role] }

// loadKeys loads or creates the persistent runner signers and rebuilds
// the key manifest for this run.
func (s *session) loadKeys() error {
	keyDir := filepath.Join(s.dataDir, "keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return err
	}
	s.signers = map[string]keys.Signer{}
	for _, role := range []string{"controller", "broker", "world", "log"} {
		p := filepath.Join(keyDir, role+".key")
		sg, err := keys.LoadSigner(p)
		if err != nil {
			seed := make([]byte, 32)
			if _, err := rand.Read(seed); err != nil {
				return err
			}
			sg = keys.NewSigner(seed)
			if err := keys.SaveSigner(sg, p); err != nil {
				return err
			}
		}
		s.signers[role] = sg
	}
	nb := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	var entries []keys.ManifestEntry
	for _, role := range []string{"controller", "broker", "world"} {
		entries = append(entries, keys.ManifestEntry{
			Role: "emitter:" + role, NotBefore: nb, Signer: s.signers[role],
		})
	}
	entries = append(entries, keys.ManifestEntry{
		Role: "log", NotBefore: nb, Signer: s.signers["log"],
	})
	m, err := keys.NewManifest(entries)
	if err != nil {
		return err
	}
	s.manifest = m
	data, err := keys.MarshalManifest(m)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dataDir, "keys.json"), data, 0o600)
}

func logOrigin(dataDir string) string {
	sum := sha256.Sum256([]byte(dataDir))
	return names.APIGroup + "/log/local-" + hex.EncodeToString(sum[:8])
}

func sessionMode(p *policy.SessionPolicy) string {
	if p.Spec.Mode == "" {
		return "enforce"
	}
	return p.Spec.Mode
}

func localPrincipal() evidence.Principal {
	u := os.Getenv("USER")
	if u == "" {
		u = fmt.Sprint(os.Getuid())
	}
	return evidence.Principal{Subject: u, Issuer: "local", Method: "local"}
}

func localSandbox() evidence.SandboxRef {
	// A hostname is a label here — an unresolvable host still runs.
	host, _ := os.Hostname()
	return evidence.SandboxRef{Namespace: "local", Node: host}
}

// placeholdersFor mints one csph_ token per (session, credentialed
// grant), matching spec/04 §4.1: csph_<8 hex of session>_<grant>_<22
// base62>.
func placeholdersFor(p *policy.SessionPolicy, session string) (map[string]string, error) {
	out := map[string]string{}
	tag := sessionTag(session)
	for _, g := range p.Spec.Grants {
		if g.Credential == nil || g.Credential.PlaceholderEnv == "" {
			continue
		}
		suffix, err := randBase62(22)
		if err != nil {
			return nil, err
		}
		out[g.Credential.PlaceholderEnv] = "csph_" + tag + "_" + g.ID + "_" + suffix
	}
	return out, nil
}

func sessionTag(session string) string {
	sum := sha256.Sum256([]byte(session))
	return hex.EncodeToString(sum[:4])
}

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func randBase62(n int) (string, error) {
	b := make([]byte, n)
	r := make([]byte, n*2)
	if _, err := rand.Read(r); err != nil {
		return "", fmt.Errorf("placeholder entropy: %w", err)
	}
	for i := range b {
		b[i] = base62[int(r[i])%62]
	}
	return string(b), nil
}

// chainEmitter wraps a keys.Emitter with its ledger and tracks the chain
// head (eseq + record hash) for the session.seal emitters list.
type chainEmitter struct {
	em   *keys.Emitter
	led  *ledger.Ledger
	eseq uint64
	head string
	n    int
}

func newChainEmitter(em *keys.Emitter, led *ledger.Ledger) *chainEmitter {
	return &chainEmitter{em: em, led: led, head: evidence.ZeroHash}
}

func (c *chainEmitter) emit(typeName string, body any) error {
	line, rec, err := c.em.Emit(typeName, body, nowTS())
	if err != nil {
		return err
	}
	if _, err := c.led.Append(line); err != nil {
		return err
	}
	env, _, _, err := evidence.DecodeRecordLine(line)
	if err != nil {
		return err
	}
	c.eseq = rec.Eseq
	c.head = evidence.RecordHash(env)
	c.n++
	return nil
}

func (c *chainEmitter) lines() [][]byte { return c.em.Lines() }

// sealRef is this chain's entry in session.seal: the head before the
// seal record. For the sealing emitter the session.seal record itself
// bumps the chain head, so its entry names the pre-seal head — exactly
// what head/eseq hold before session.seal is emitted. Clean reports
// the chain really emitted a contiguous eseq sequence from 0 — every
// emit above went through this emitter, so a mismatch means a record
// was dropped between emission and the ledger.
func (c *chainEmitter) sealRef() evidence.SealEmitter {
	clean := c.eseq == 0 && c.n == 0 ||
		c.n == int(c.eseq)+1
	return evidence.SealEmitter{
		Emitter: c.em.Name(), FinalEseq: c.eseq, HeadHash: c.head, Clean: clean,
	}
}
