// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/countersign/countersign/internal/names"
)

var (
	labelRe   = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	tokenRe   = regexp.MustCompile(`^[!#$%&'*+\-.^_` + "`" + `|~0-9A-Za-z]+$`)
	envRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	sizeRe    = regexp.MustCompile(`^[0-9]+(B|K|Ki|M|Mi|G|Gi)?$`)
	hostRe    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
	repoRe    = regexp.MustCompile(`^[^/]+/[^/]+$`)
	classEnum = map[string]bool{"exec": true, "http": true, "mcp": true, "local": true, "other": true}
	// revClasses are the 05 §1 reversibility classes usable on records, in
	// spec.autonomy keys, grant class and grant tools values.
	revClasses = map[string]bool{"control": true, "safe": true, "staged": true, "compensable": true, "irreversible": true}
)

func errf(path, format string, args ...any) error {
	return fmt.Errorf("policy: %s: %s", path, fmt.Sprintf(format, args...))
}

func oneOf(path, v string, set ...string) error {
	for _, s := range set {
		if v == s {
			return nil
		}
	}
	return errf(path, "invalid value %q (want %s)", v, strings.Join(set, "|"))
}

func oneOfDefault(path, v, def string, set ...string) error {
	if v == "" {
		v = def
	}
	return oneOf(path, v, set...)
}

func checkSize(path, s string) error {
	if s != "" && !sizeRe.MatchString(s) {
		return errf(path, "invalid size %q (want e.g. 1048576, 512Ki, 1Mi)", s)
	}
	return nil
}

func checkLabel(path, s string) error {
	if !labelRe.MatchString(s) {
		return errf(path, "invalid taint label %q (want [a-z][a-z0-9-]*)", s)
	}
	return nil
}

// hostEntry validates one match.hosts entry: a literal name or IP, a
// "*.domain" wildcard, or "*" alone (04 §1).
func hostEntry(path, h string) error {
	if h == "" {
		return errf(path, "empty host entry")
	}
	if h != strings.ToLower(h) {
		return errf(path, "host %q must be lowercase", h)
	}
	if h == "*" {
		return nil
	}
	name := h
	if strings.HasPrefix(h, "*.") {
		name = h[2:]
		if name == "" {
			return errf(path, "wildcard %q has no base domain", h)
		}
	} else if strings.Contains(h, "*") {
		return errf(path, "wildcard %q must be \"*\" or \"*.domain\"", h)
	}
	if _, err := netip.ParseAddr(strings.TrimPrefix(strings.TrimSuffix(name, "]"), "[")); err == nil {
		return nil // IP literal
	}
	if !hostRe.MatchString(name) {
		return errf(path, "invalid host name %q", h)
	}
	return nil
}

func validate(p *SessionPolicy) error {
	if p.APIVersion != names.APIGroup+"/v1alpha1" {
		return errf("apiVersion", "must be %q", names.APIGroup+"/v1alpha1")
	}
	if p.Kind != "SessionPolicy" {
		return errf("kind", "must be \"SessionPolicy\"")
	}
	if p.Metadata.Name == "" {
		return errf("metadata.name", "required")
	}
	s := &p.Spec
	if err := oneOfDefault("spec.mode", s.Mode, "enforce", "enforce", "audit", "learn"); err != nil {
		return err
	}
	mode := s.Mode
	if mode == "" {
		mode = "enforce"
	}
	if err := oneOfDefault("spec.scenario", s.Scenario, "agent", "agent", "mcp-server"); err != nil {
		return err
	}
	if err := oneOfDefault("spec.observer", s.Observer, "optional", "optional", "required"); err != nil {
		return err
	}
	if s.Taint != nil && s.Taint.InitialWorkspace != "" &&
		s.Taint.InitialWorkspace != "trusted" {
		if err := checkLabel("spec.taint.initialWorkspace", s.Taint.InitialWorkspace); err != nil {
			return err
		}
	}
	if err := checkSize("spec.bufferLimit", s.BufferLimit); err != nil {
		return err
	}
	if s.MaxIntentOpenSeconds != nil && *s.MaxIntentOpenSeconds <= 0 {
		return errf("spec.maxIntentOpenSeconds", "must be > 0")
	}
	for tool, class := range s.ToolClasses {
		if tool == "" {
			return errf("spec.toolClasses", "empty tool name")
		}
		if !classEnum[class] {
			return errf("spec.toolClasses", "invalid class %q for tool %q", class, tool)
		}
	}
	for cls, cond := range s.Autonomy {
		if !revClasses[cls] {
			return errf("spec.autonomy", "unknown class %q", cls)
		}
		if err := oneOf("spec.autonomy", cond, "allow", "review", "deny"); err != nil {
			return err
		}
	}
	seen := map[string]int{}
	for i, g := range s.Grants {
		if err := validateGrant(i, g, mode); err != nil {
			return err
		}
		if prev, dup := seen[g.ID]; dup {
			return errf(fmt.Sprintf("spec.grants[%d].id", i), "duplicate grant id %q (first at grants[%d])", g.ID, prev)
		}
		seen[g.ID] = i
	}
	return nil
}

func validateGrant(i int, g Grant, specMode string) error {
	base := fmt.Sprintf("spec.grants[%d]", i)
	if g.ID == "" {
		return errf(base+".id", "required")
	}
	if err := oneOfDefault(base+".action", g.Action, "allow", "allow", "deny"); err != nil {
		return err
	}
	if g.Match == nil {
		return errf(base+".match", "required")
	}
	m := g.Match
	if len(m.Hosts) == 0 {
		return errf(base+".match.hosts", "required (non-empty)")
	}
	star := false
	for _, h := range m.Hosts {
		if err := hostEntry(base+".match.hosts", h); err != nil {
			return err
		}
		if h == "*" {
			star = true
		}
	}
	if err := oneOfDefault(base+".match.scheme", m.Scheme, "https", "https", "http"); err != nil {
		return err
	}
	for _, port := range m.Ports {
		if port < 1 || port > 65535 {
			return errf(base+".match.ports", "port %d out of range 1-65535", port)
		}
	}
	for _, meth := range m.Methods {
		if !tokenRe.MatchString(meth) {
			return errf(base+".match.methods", "invalid method token %q", meth)
		}
	}
	for _, path := range m.Paths {
		if !strings.HasPrefix(path, "/") {
			return errf(base+".match.paths", "path glob %q must start with /", path)
		}
	}
	if m.Matcher != nil {
		git := m.Matcher.GitSmartHTTP
		if git == nil {
			return errf(base+".match.matcher", "unknown matcher (built-ins: git-smart-http)")
		}
		if len(git.Repos) == 0 {
			return errf(base+".match.matcher", "git-smart-http requires repos")
		}
		for _, r := range git.Repos {
			if !repoRe.MatchString(r) {
				return errf(base+".match.matcher", "repo %q must be owner/repo", r)
			}
		}
		if err := oneOf(base+".match.matcher", git.Access, "read", "write"); err != nil {
			return err
		}
		if len(m.Methods) > 0 || len(m.Paths) > 0 {
			return errf(base+".match.matcher", "replaces methods/paths; remove them")
		}
	}
	if err := oneOfDefault(base+".mode", g.Mode, "intercept", "intercept", "passthrough"); err != nil {
		return err
	}
	for _, u := range g.Upgrade {
		if err := oneOf(base+".upgrade", u, "websocket"); err != nil {
			return err
		}
	}
	if err := oneOfDefault(base+".network", g.Network, "public", "public", "cluster"); err != nil {
		return err
	}
	if err := oneOfDefault(base+".inspect", g.Inspect, "none", "none", "inference", "mcp"); err != nil {
		return err
	}
	if g.Trust != "" && g.Trust != "trusted" {
		if err := checkLabel(base+".trust", g.Trust); err != nil {
			return err
		}
	}
	if g.Class != "" {
		if !revClasses[g.Class] {
			return errf(base+".class", "unknown class %q", g.Class)
		}
		if g.Class == "staged" && g.Stager == nil {
			return errf(base+".class", "staged requires a stager")
		}
	}
	if g.Stager != nil {
		if err := validateStager(base+".stager", g.Stager); err != nil {
			return err
		}
	}
	if g.Compensate != nil {
		if err := validateCompensate(base+".compensate", g.Compensate); err != nil {
			return err
		}
	}
	for tool, cls := range g.Tools {
		if tool == "" {
			return errf(base+".tools", "empty tool name")
		}
		if g.Inspect != "mcp" {
			return errf(base+".tools", "requires inspect: mcp")
		}
		if !revClasses[cls] {
			return errf(base+".tools", "unknown class %q for tool %q", cls, tool)
		}
		if cls == "staged" && g.Stager == nil {
			return errf(base+".tools", "staged requires a stager")
		}
	}
	if g.Calls != "" {
		if g.Calls != "serialized" {
			return errf(base+".calls", "unknown calls mode %q", g.Calls)
		}
		if g.Inspect != "mcp" {
			return errf(base+".calls", "requires inspect: mcp")
		}
	}
	// 05 §2: the intent condition is rejected at validation until M9.
	if err := oneOfDefault(base+".requires", g.Requires, "allow", "allow", "review", "deny"); err != nil {
		return err
	}
	if err := oneOfDefault(base+".intentMatch", g.IntentMatch, "window", "window", "exact"); err != nil {
		return err
	}
	if err := oneOfDefault(base+".lineage", g.Lineage, "preferred", "off", "preferred", "required"); err != nil {
		return err
	}
	if g.WhenTainted != nil {
		if err := oneOfDefault(base+".whenTainted.default", g.WhenTainted.Default, "review", "allow", "review", "deny"); err != nil {
			return err
		}
		for label, cond := range g.WhenTainted.Labels {
			if err := checkLabel(base+".whenTainted.labels", label); err != nil {
				return err
			}
			if err := oneOf(base+".whenTainted.labels", cond, "allow", "review", "deny"); err != nil {
				return err
			}
		}
	}
	if err := checkSize(base+".bufferLimit", g.BufferLimit); err != nil {
		return err
	}
	if g.Limits != nil {
		if v := g.Limits.MaxRequestBodyBytes; v != nil && *v <= 0 {
			return errf(base+".limits.maxRequestBodyBytes", "must be > 0")
		}
		if v := g.Limits.MaxURLBytes; v != nil && *v <= 0 {
			return errf(base+".limits.maxUrlBytes", "must be > 0")
		}
		if v := g.Limits.RequestsPerMinute; v != nil && *v <= 0 {
			return errf(base+".limits.requestsPerMinute", "must be > 0")
		}
	}
	if g.Mode == "passthrough" {
		if g.Credential != nil {
			return errf(base+".credential", "not allowed with mode passthrough")
		}
		if g.Inspect != "" && g.Inspect != "none" {
			return errf(base+".inspect", "not allowed with mode passthrough")
		}
		if m.Matcher != nil {
			return errf(base+".match.matcher", "not allowed with mode passthrough")
		}
		if len(m.Paths) > 0 {
			return errf(base+".match.paths", "not allowed with mode passthrough")
		}
		if len(m.Methods) > 0 {
			return errf(base+".match.methods", "not allowed with mode passthrough")
		}
		if g.Stager != nil {
			return errf(base+".stager", "not allowed with mode passthrough")
		}
		if g.Compensate != nil {
			return errf(base+".compensate", "not allowed with mode passthrough")
		}
		if len(g.Tools) > 0 {
			return errf(base+".tools", "not allowed with mode passthrough")
		}
		if g.Calls != "" {
			return errf(base+".calls", "not allowed with mode passthrough")
		}
	}
	if g.Credential != nil {
		if err := validateCredential(base, g.Credential); err != nil {
			return err
		}
		if star && specMode != "learn" {
			return errf(base+".match.hosts", "host \"*\" is rejected on a credentialed grant unless spec.mode is learn")
		}
	}
	return nil
}

func validateStager(base string, s *Stager) error {
	if (s.Git == nil) == (s.Outbox == nil) {
		return errf(base, "exactly one of git or outbox required")
	}
	if g := s.Git; g != nil {
		if len(g.Refs) == 0 {
			return errf(base+".git.refs", "required")
		}
		for _, r := range g.Refs {
			if !strings.HasPrefix(r, "refs/") {
				return errf(base+".git.refs", "invalid ref pattern %q", r)
			}
		}
		if err := checkSize(base+".git.maxPackBytes", g.MaxPackBytes); err != nil {
			return err
		}
		return nil
	}
	o := s.Outbox
	if o.Respond == nil {
		return errf(base+".outbox.respond", "required")
	}
	if o.Respond.Status < 100 || o.Respond.Status > 599 {
		return errf(base+".outbox.respond.status", "invalid status %d", o.Respond.Status)
	}
	if o.Respond.ContentType == "" {
		return errf(base+".outbox.respond.contentType", "required")
	}
	if o.IDMap == nil {
		return errf(base+".outbox.idMap", "required")
	}
	for _, ptr := range []string{o.IDMap.Provisional, o.IDMap.Real} {
		if !strings.HasPrefix(ptr, "/") {
			return errf(base+".outbox.idMap", "invalid JSON pointer %q", ptr)
		}
	}
	if o.IdempotencyHeader != "" && !tokenRe.MatchString(o.IdempotencyHeader) {
		return errf(base+".outbox.idempotencyHeader", "invalid header name %q", o.IdempotencyHeader)
	}
	return nil
}

func validateCompensate(base string, c *Compensate) error {
	if c.Restore == nil && c.DeleteCreated == nil {
		return errf(base, "restore or deleteCreated required")
	}
	if r := c.Restore; r != nil {
		if err := checkMethods(base+".restore.methods", r.Methods); err != nil {
			return err
		}
	}
	if d := c.DeleteCreated; d != nil {
		if err := checkMethods(base+".deleteCreated.methods", d.Methods); err != nil {
			return err
		}
		if (d.From == nil) == (d.URLTemplate == "") {
			return errf(base+".deleteCreated", "exactly one of from or urlTemplate required")
		}
		if d.From != nil {
			switch f := d.From.(type) {
			case string:
				if f != "location" {
					return errf(base+".deleteCreated.from", "unknown form %q", f)
				}
			case map[string]any:
				ptr, ok := f["jsonPointer"].(string)
				if len(f) != 1 || !ok || !strings.HasPrefix(ptr, "/") {
					return errf(base+".deleteCreated.from", "must be \"location\" or {jsonPointer: ...}")
				}
			default:
				return errf(base+".deleteCreated.from", "must be \"location\" or {jsonPointer: ...}")
			}
		}
	}
	if sd := c.StateDigest; sd != nil {
		for _, ptr := range sd.Ignore {
			if !strings.HasPrefix(ptr, "/") {
				return errf(base+".stateDigest.ignore", "invalid JSON pointer %q", ptr)
			}
		}
	}
	return nil
}

func checkMethods(path string, methods []string) error {
	if len(methods) == 0 {
		return errf(path, "required")
	}
	for _, m := range methods {
		if !tokenRe.MatchString(m) {
			return errf(path, "invalid method %q", m)
		}
	}
	return nil
}

func validateCredential(base string, c *Credential) error {
	if c.Ref.Secret == "" {
		return errf(base+".credential.ref.secret", "required")
	}
	if c.Ref.Key == "" {
		return errf(base+".credential.ref.key", "required")
	}
	hasHeader := c.Inject.Header != ""
	hasBasic := c.Inject.Basic != nil
	if hasHeader == hasBasic {
		return errf(base+".credential.inject", "exactly one of header or basic required")
	}
	if hasHeader {
		if !tokenRe.MatchString(c.Inject.Header) {
			return errf(base+".credential.inject.header", "invalid header name %q", c.Inject.Header)
		}
		if c.Inject.Format != "" && !strings.Contains(c.Inject.Format, "{secret}") {
			return errf(base+".credential.inject.format", "must contain {secret}")
		}
	} else {
		if c.Inject.Format != "" {
			return errf(base+".credential.inject.format", "requires inject.header")
		}
		if c.Inject.Basic.Username == "" {
			return errf(base+".credential.inject.basic.username", "required")
		}
	}
	if !envRe.MatchString(c.PlaceholderEnv) {
		return errf(base+".credential.placeholderEnv", "invalid environment name %q", c.PlaceholderEnv)
	}
	return nil
}
