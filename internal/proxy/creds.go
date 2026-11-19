// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"github.com/countersign/countersign/internal/creds"
	"github.com/countersign/countersign/internal/policy"
)

// Credential rules of 04 §4.3–4.4 (M3.3) plus the injection plan of §4.2
// (M3.2). evalCreds runs after the grant match and the limit checks,
// before the write-ahead record; on "allow" the plan is applied only
// after the record is durable.
//
// Deny reasons (04 §6.2):
//   - FOREIGN_CREDENTIAL  — non-empty credential material this session's
//     policy does not name: a value in a credential-bearing header, URL
//     userinfo, or a §4.4-shaped string in the URL or buffered body of a
//     credentialed-grant request.
//   - PLACEHOLDER_MISUSE  — any csph_ token outside the exact inject
//     slot (other headers, URL, body, Basic username), any session's.
//   - CREDENTIAL_UNAVAILABLE — the store could not resolve the grant's
//     ref (fail closed).

// credHeaders are the §4.3 credential-bearing header names checked on
// credentialed-grant requests (proxy-authorization never survives
// stripHopByHop; it is listed anyway because the rule names it).
var credHeaders = []string{
	"Authorization", "Proxy-Authorization", "X-Api-Key",
	"Api-Key", "X-Auth-Token", "Cookie",
}

// credPlan is the outcome of evalCreds for an allowed request.
type credPlan struct {
	spec        *creds.InjectSpec // non-nil when a credential is to be applied
	refID       string            // "<secret>:<key>" for decision.credentials
	injected    bool              // Apply ran (for tests and scrub activation)
	secret      string            // real value — memory only, never recorded
	placeholder string            // session placeholder — the scrub replacement
	username    string            // basic-inject username (for the Basic scrub form)
}

// evalCreds inspects the pre-injection request. It returns (plan, "") to
// proceed or (nil, reason) to deny. plan.spec is nil for non-credentialed
// grants; for credentialed ones it is the injection to apply post-record.
//
// body is the buffered prefix of the request body (or the whole body when
// not deferred); scans see only that part (04 §4.3).
func evalCreds(sess *Session, grant *policy.Grant, r *http.Request,
	h http.Header, tgt forwardTarget, body []byte) (*credPlan, string) {

	credentialed := grant != nil && grant.Credential != nil
	plan := &credPlan{}

	// URL userinfo: placeholder material → misuse; on a credentialed
	// grant any userinfo is credential material outside every slot.
	if r.URL != nil && r.URL.User != nil {
		ui := r.URL.User.String()
		if creds.HasPlaceholderToken(ui) {
			return nil, "PLACEHOLDER_MISUSE"
		}
		if credentialed {
			return nil, "FOREIGN_CREDENTIAL"
		}
	}

	// URL path+query, raw and percent-decoded (04 §4.3: any csph_ in the
	// URL; §4.4: credential-shaped strings on credentialed grants).
	rawURL := tgt.path
	if tgt.rawQuery != "" {
		rawURL += "?" + tgt.rawQuery
	}
	for _, cand := range urlForms(rawURL) {
		if creds.HasPlaceholderToken(cand) {
			return nil, "PLACEHOLDER_MISUSE"
		}
		if credentialed && len(creds.Detect([]byte(cand))) > 0 {
			return nil, "FOREIGN_CREDENTIAL"
		}
	}

	// Header checks: csph_ anywhere but the inject slot; on credentialed
	// grants, the §4.3 credential-bearing headers outside the slot.
	if credentialed {
		spec, refID, secret, reason := injectSpec(sess, grant)
		if reason != "" {
			return nil, reason
		}
		plan.spec, plan.refID, plan.secret = spec, refID, secret
		plan.placeholder = sess.placeholders[grant.ID]
		if grant.Credential.Inject.Basic != nil {
			plan.username = grant.Credential.Inject.Basic.Username
		}
		slot := spec.Header()
		for _, name := range credHeaders {
			if name == slot {
				continue
			}
			for _, v := range h.Values(name) {
				if v == "" {
					continue
				}
				if creds.HasPlaceholderToken(v) || hasPHBasic(v) {
					return nil, "PLACEHOLDER_MISUSE"
				}
				return nil, "FOREIGN_CREDENTIAL"
			}
		}
		// The remaining headers: a csph_ token anywhere but the slot is
		// misuse (the slot's own value is judged by spec.Eval next).
		for name, vals := range h {
			if http.CanonicalHeaderKey(name) == slot {
				continue
			}
			for _, v := range vals {
				if creds.HasPlaceholderToken(v) || hasPHBasic(v) {
					return nil, "PLACEHOLDER_MISUSE"
				}
			}
		}
		// Inject-location pinning: exact expected form or absent.
		if _, ok, sawPH := spec.Eval(h); !ok {
			if sawPH {
				return nil, "PLACEHOLDER_MISUSE"
			}
			return nil, "FOREIGN_CREDENTIAL"
		}
	} else {
		for _, vals := range h {
			for _, v := range vals {
				if creds.HasPlaceholderToken(v) || hasPHBasic(v) {
					return nil, "PLACEHOLDER_MISUSE"
				}
			}
		}
	}

	// Buffered body: csph_ for all grants; credential shapes on
	// credentialed ones (raw + percent-decoded, same as the URL).
	for _, cand := range bodyForms(body) {
		if creds.HasPlaceholderTokenB(cand) {
			return nil, "PLACEHOLDER_MISUSE"
		}
		if credentialed && len(creds.Detect(cand)) > 0 {
			return nil, "FOREIGN_CREDENTIAL"
		}
	}
	return plan, ""
}

// injectSpec resolves the grant's credential to the injection plan: the
// session's placeholder, the store's secret and the expected client form.
// ""/reason means the ref could not resolve (CREDENTIAL_UNAVAILABLE).
func injectSpec(sess *Session, grant *policy.Grant) (*creds.InjectSpec, string, string, string) {
	cr := grant.Credential
	ref := creds.Ref{Secret: cr.Ref.Secret, Key: cr.Ref.Key}
	secret, err := sess.credStore.Get(ref)
	if err != nil {
		return nil, "", "", "CREDENTIAL_UNAVAILABLE"
	}
	ph := sess.placeholders[grant.ID]
	var spec creds.InjectSpec
	switch {
	case cr.Inject.Basic != nil:
		spec = creds.BasicSpec(cr.Inject.Basic.Username, ph, secret)
	case cr.Inject.Header != "":
		format := cr.Inject.Format
		if format == "" {
			format = "{secret}"
		}
		spec = creds.HeaderSpec(cr.Inject.Header, format, ph, secret)
	default:
		return nil, "", "", "CREDENTIAL_UNAVAILABLE"
	}
	return &spec, ref.ID(), secret, ""
}

// urlForms returns the URL text in its raw and percent-decoded forms so a
// credential split across %-escapes is still seen.
func urlForms(raw string) []string {
	dec, err := url.PathUnescape(raw)
	if err != nil || dec == raw {
		return []string{raw}
	}
	return []string{raw, dec}
}

// bodyForms returns the buffered body raw and percent-decoded.
func bodyForms(b []byte) [][]byte {
	if len(b) == 0 {
		return nil
	}
	dec, err := url.QueryUnescape(string(b))
	if err != nil || dec == string(b) {
		return [][]byte{b}
	}
	return [][]byte{b, []byte(dec)}
}

// hasPHBasic reports whether v is a "Basic <b64>" value whose decoded
// payload carries a csph_ token (a placeholder in a Basic position —
// username or password — is misuse anywhere but the exact slot).
func hasPHBasic(v string) bool {
	if !strings.HasPrefix(v, "Basic ") {
		return false
	}
	dec, err := decodeBasic(v)
	return err == nil && creds.HasPlaceholderToken(dec)
}

func decodeBasic(v string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v, "Basic "))
	return string(b), err
}
