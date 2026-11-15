// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Package policy implements the SessionPolicy document of
// spec/04-policy-and-reconciliation.md §1 and the request matcher of §2
// steps 1–2 (M3.1).
//
// The structs are additive-only: later milestones add the session-level
// fields of 05 (autonomy, world, commit, budgets, tape, attest) and the
// grant fields class, stager, compensate, tools and egress as new optional
// fields. Unknown keys are rejected at load, so adding a field is always a
// non-breaking change to the schema.
package policy

// SessionPolicy is the top-level document (04 §1).
type SessionPolicy struct {
	APIVersion string   `yaml:"apiVersion" json:"apiVersion"`
	Kind       string   `yaml:"kind" json:"kind"`
	Metadata   Metadata `yaml:"metadata" json:"metadata"`
	Spec       Spec     `yaml:"spec" json:"spec"`

	digest string
}

// Metadata carries the object name.
type Metadata struct {
	Name string `yaml:"name" json:"name"`
}

// Spec is the session-level policy body. The 05 fields (autonomy, world,
// commit, budgets, tape, attest) are intentionally not represented yet; the
// strict loader rejects them as unknown until their milestones land.
type Spec struct {
	Mode                 string            `yaml:"mode,omitempty" json:"mode,omitempty"`
	Scenario             string            `yaml:"scenario,omitempty" json:"scenario,omitempty"`
	Observer             string            `yaml:"observer,omitempty" json:"observer,omitempty"`
	Taint                *Taint            `yaml:"taint,omitempty" json:"taint,omitempty"`
	Privacy              *Privacy          `yaml:"privacy,omitempty" json:"privacy,omitempty"`
	BufferLimit          string            `yaml:"bufferLimit,omitempty" json:"bufferLimit,omitempty"`
	MaxIntentOpenSeconds *int              `yaml:"maxIntentOpenSeconds,omitempty" json:"maxIntentOpenSeconds,omitempty"`
	CommandField         string            `yaml:"commandField,omitempty" json:"commandField,omitempty"`
	ToolClasses          map[string]string `yaml:"toolClasses,omitempty" json:"toolClasses,omitempty"`
	Grants               []Grant           `yaml:"grants,omitempty" json:"grants,omitempty"`
}

// Taint holds the session's initial taint label (04 §8, M10).
type Taint struct {
	InitialWorkspace string `yaml:"initialWorkspace,omitempty" json:"initialWorkspace,omitempty"`
}

// Privacy toggles content previews in records (M8.5).
type Privacy struct {
	Previews *bool `yaml:"previews,omitempty" json:"previews,omitempty"`
}

// Grant is one grant entry. Fields defined by 05 (class, stager, compensate,
// tools, egress) are rejected as unknown for now.
type Grant struct {
	ID          string       `yaml:"id" json:"id"`
	Action      string       `yaml:"action,omitempty" json:"action,omitempty"`
	Match       *Match       `yaml:"match" json:"match"`
	Mode        string       `yaml:"mode,omitempty" json:"mode,omitempty"`
	Upgrade     []string     `yaml:"upgrade,omitempty" json:"upgrade,omitempty"`
	Network     string       `yaml:"network,omitempty" json:"network,omitempty"`
	Inspect     string       `yaml:"inspect,omitempty" json:"inspect,omitempty"`
	Trust       string       `yaml:"trust,omitempty" json:"trust,omitempty"`
	Requires    string       `yaml:"requires,omitempty" json:"requires,omitempty"`
	IntentMatch string       `yaml:"intentMatch,omitempty" json:"intentMatch,omitempty"`
	Lineage     string       `yaml:"lineage,omitempty" json:"lineage,omitempty"`
	WhenTainted *WhenTainted `yaml:"whenTainted,omitempty" json:"whenTainted,omitempty"`
	BufferLimit string       `yaml:"bufferLimit,omitempty" json:"bufferLimit,omitempty"`
	Limits      *Limits      `yaml:"limits,omitempty" json:"limits,omitempty"`
	Credential  *Credential  `yaml:"credential,omitempty" json:"credential,omitempty"`
}

// Match selects the requests a grant applies to (04 §1 defaults table).
type Match struct {
	Hosts   []string `yaml:"hosts" json:"hosts"`
	Scheme  string   `yaml:"scheme,omitempty" json:"scheme,omitempty"`
	Ports   []int    `yaml:"ports,omitempty" json:"ports,omitempty"`
	Methods []string `yaml:"methods,omitempty" json:"methods,omitempty"`
	Paths   []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	Matcher *Matcher `yaml:"matcher,omitempty" json:"matcher,omitempty"`
}

// Matcher names a semantic matcher replacing methods/paths (04 §2). Only
// git-smart-http exists (M3.6); until it lands a grant carrying matcher can
// never match a generic request.
type Matcher struct {
	GitSmartHTTP *GitSmartHTTP `yaml:"git-smart-http,omitempty" json:"git-smart-http,omitempty"`
}

// GitSmartHTTP scopes a grant to repositories (04 §2, M3.6).
type GitSmartHTTP struct {
	Repos  []string `yaml:"repos" json:"repos"`
	Access string   `yaml:"access" json:"access"`
}

// WhenTainted maps taint labels to conditions (04 §8).
type WhenTainted struct {
	Default string            `yaml:"default,omitempty" json:"default,omitempty"`
	Labels  map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// Limits caps request size, URL size and rate (04 §1, M3.5).
type Limits struct {
	MaxRequestBodyBytes *int `yaml:"maxRequestBodyBytes,omitempty" json:"maxRequestBodyBytes,omitempty"`
	MaxURLBytes         *int `yaml:"maxUrlBytes,omitempty" json:"maxUrlBytes,omitempty"`
	RequestsPerMinute   *int `yaml:"requestsPerMinute,omitempty" json:"requestsPerMinute,omitempty"`
}

// Credential binds a stored secret to an injection point (04 §4).
type Credential struct {
	Ref            CredRef `yaml:"ref" json:"ref"`
	Inject         Inject  `yaml:"inject" json:"inject"`
	PlaceholderEnv string  `yaml:"placeholderEnv" json:"placeholderEnv"`
}

// CredRef names a secret entry in the credential store.
type CredRef struct {
	Secret string `yaml:"secret" json:"secret"`
	Key    string `yaml:"key" json:"key"`
}

// Inject is exactly one of a header template or HTTP Basic.
type Inject struct {
	Header string `yaml:"header,omitempty" json:"header,omitempty"`
	Format string `yaml:"format,omitempty" json:"format,omitempty"`
	Basic  *Basic `yaml:"basic,omitempty" json:"basic,omitempty"`
}

// Basic injects the secret as the HTTP Basic password.
type Basic struct {
	Username string `yaml:"username" json:"username"`
}
