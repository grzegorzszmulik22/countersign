// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"strings"
	"testing"

	"github.com/countersign/countersign/internal/policy"
)

// gitPolicy builds a one-grant policy carrying a git-smart-http matcher.
func gitPolicy(t *testing.T, access string, repos ...string) *policy.SessionPolicy {
	t.Helper()
	src := `apiVersion: "countersign.dev/v1alpha1"
kind: "SessionPolicy"
metadata: {name: "git-test"}
spec:
  mode: "enforce"
  scenario: "agent"
  grants:
    - {id: "repo", match: {hosts: ["code.test"], matcher: {git-smart-http: {repos: ["` +
		strings.Join(repos, `", "`) + `"], access: "` + access + `"}}}}
`
	p, err := policy.Load([]byte(src))
	if err != nil {
		t.Fatalf("load git policy: %v", err)
	}
	return p
}

// TestC363GitMatcherEdges is C3.6.3: unknown service values, extra path
// segments and repository traversal attempts must not match; plus the whole
// read/write endpoint matrix of 04 §2 at the match level.
func TestC363GitMatcherEdges(t *testing.T) {
	read := gitPolicy(t, "read", "acme/widgets")
	write := gitPolicy(t, "write", "acme/widgets")
	multi := gitPolicy(t, "write", "acme/widgets", "acme/gadgets")
	dotted := gitPolicy(t, "read", "acme/widgets.git")

	// want: "" = no match (NO_GRANT), "repo" = matched.
	cases := []struct {
		name         string
		pol          *policy.SessionPolicy
		method, path string
		query        string
		want         string
	}{
		// The four permitted forms, each access level.
		{"r-refs-upload", read, "GET", "/acme/widgets.git/info/refs", "service=git-upload-pack", "repo"},
		{"r-refs-upload-nodot", read, "GET", "/acme/widgets/info/refs", "service=git-upload-pack", "repo"},
		{"r-upload-pack", read, "POST", "/acme/widgets.git/git-upload-pack", "", "repo"},
		{"r-upload-pack-nodot", read, "POST", "/acme/widgets/git-upload-pack", "", "repo"},
		{"r-refs-receive", read, "GET", "/acme/widgets.git/info/refs", "service=git-receive-pack", ""},
		{"r-receive-pack", read, "POST", "/acme/widgets.git/git-receive-pack", "", ""},
		{"w-refs-upload", write, "GET", "/acme/widgets.git/info/refs", "service=git-upload-pack", "repo"},
		{"w-refs-receive", write, "GET", "/acme/widgets.git/info/refs", "service=git-receive-pack", "repo"},
		{"w-upload-pack", write, "POST", "/acme/widgets.git/git-upload-pack", "", "repo"},
		{"w-receive-pack", write, "POST", "/acme/widgets.git/git-receive-pack", "", "repo"},
		{"w-receive-nodot", write, "POST", "/acme/widgets/git-receive-pack", "", "repo"},
		// service parameter must be exactly service=<svc>.
		{"svc-absent", read, "GET", "/acme/widgets.git/info/refs", "", ""},
		{"svc-empty", read, "GET", "/acme/widgets.git/info/refs", "service=", ""},
		{"svc-unknown", read, "GET", "/acme/widgets.git/info/refs", "service=git-dumb", ""},
		{"svc-dumb-http", read, "GET", "/acme/widgets.git/info/refs", "", ""},
		{"svc-name-case", read, "GET", "/acme/widgets.git/info/refs", "Service=git-upload-pack", ""},
		{"svc-value-case", read, "GET", "/acme/widgets.git/info/refs", "service=GIT-UPLOAD-PACK", ""},
		{"svc-encoded", read, "GET", "/acme/widgets.git/info/refs", "service=git%2dupload%2dpack", ""},
		{"svc-extra-param", read, "GET", "/acme/widgets.git/info/refs", "service=git-upload-pack&x=1", ""},
		{"svc-param-first", read, "GET", "/acme/widgets.git/info/refs", "x=1&service=git-upload-pack", ""},
		{"svc-duplicated", read, "GET", "/acme/widgets.git/info/refs", "service=git-upload-pack&service=git-receive-pack", ""},
		{"svc-nul-suffix", read, "GET", "/acme/widgets.git/info/refs", "service=git-upload-pack%00", ""},
		{"svc-on-post", read, "POST", "/acme/widgets.git/git-upload-pack", "service=git-upload-pack", ""},
		{"query-on-post", read, "POST", "/acme/widgets.git/git-upload-pack", "x=1", ""},
		{"svc-on-post-write", write, "POST", "/acme/widgets.git/git-receive-pack", "service=git-receive-pack", ""},
		// Method discipline per endpoint shape.
		{"post-info-refs", read, "POST", "/acme/widgets.git/info/refs", "service=git-upload-pack", ""},
		{"put-info-refs", read, "PUT", "/acme/widgets.git/info/refs", "service=git-upload-pack", ""},
		{"get-upload-pack", read, "GET", "/acme/widgets.git/git-upload-pack", "", ""},
		{"put-upload-pack", read, "PUT", "/acme/widgets.git/git-upload-pack", "", ""},
		{"head-info-refs", read, "HEAD", "/acme/widgets.git/info/refs", "service=git-upload-pack", ""},
		{"get-receive-pack", write, "GET", "/acme/widgets.git/git-receive-pack", "", ""},
		// Repository scoping: prefixes, suffixes, case, nesting, empties.
		{"prefix-repo", read, "GET", "/acme/widgets-evil.git/info/refs", "service=git-upload-pack", ""},
		{"suffix-repo", read, "GET", "/acme/widget.git/info/refs", "service=git-upload-pack", ""},
		{"repo-x-suffix", read, "GET", "/acme/widgetsx.git/info/refs", "service=git-upload-pack", ""},
		{"repo-gitx", read, "GET", "/acme/widgets.gitx/info/refs", "service=git-upload-pack", ""},
		{"repo-double-git", read, "GET", "/acme/widgets.git.git/info/refs", "service=git-upload-pack", ""},
		{"owner-case", read, "GET", "/ACME/widgets.git/info/refs", "service=git-upload-pack", ""},
		{"repo-case", read, "GET", "/acme/Widgets.git/info/refs", "service=git-upload-pack", ""},
		{"all-case", read, "GET", "/ACME/WIDGETS.git/info/refs", "service=git-upload-pack", ""},
		{"nested-owner", read, "GET", "/org/acme/widgets.git/info/refs", "service=git-upload-pack", ""},
		{"extra-seg-tail", read, "GET", "/acme/widgets.git/extra/info/refs", "service=git-upload-pack", ""},
		{"extra-seg-mid", read, "POST", "/acme/widgets.git/x/git-upload-pack", "", ""},
		{"trailing-slash", read, "GET", "/acme/widgets.git/", "", ""},
		{"bare-repo", read, "GET", "/acme/widgets.git", "", ""},
		{"refs-extra-seg", read, "GET", "/acme/widgets/info/refs/x", "service=git-upload-pack", ""},
		{"leading-dslash", read, "POST", "//widgets.git/git-upload-pack", "", ""},
		{"empty-repo-seg", read, "GET", "/acme//info/refs", "service=git-upload-pack", ""},
		{"dotgit-as-repo", read, "GET", "/acme/.git/info/refs", "service=git-upload-pack", ""},
		{"endpoint-case1", read, "GET", "/acme/widgets.git/INFO/refs", "service=git-upload-pack", ""},
		{"endpoint-case2", read, "GET", "/acme/widgets.git/info/REFS", "service=git-upload-pack", ""},
		{"endpoint-case3", read, "POST", "/acme/widgets.git/Git-Upload-Pack", "", ""},
		// Percent-encoded unreserved bytes decode first; reserved stay raw.
		{"unreserved-repo", read, "GET", "/acme/%77idgets.git/info/refs", "service=git-upload-pack", "repo"},
		{"unreserved-endpoint", read, "GET", "/acme/widgets.git/info/%72efs", "service=git-upload-pack", "repo"},
		// Second repo in the list; repos entry carrying ".git" names the same repo.
		{"multi-second", multi, "POST", "/acme/gadgets.git/git-receive-pack", "", "repo"},
		{"multi-first-read", multi, "GET", "/acme/widgets.git/info/refs", "service=git-upload-pack", "repo"},
		{"dotted-entry-nodot", dotted, "GET", "/acme/widgets/info/refs", "service=git-upload-pack", "repo"},
		{"dotted-entry-dot", dotted, "GET", "/acme/widgets.git/info/refs", "service=git-upload-pack", "repo"},
		{"dotted-entry-2dot", dotted, "GET", "/acme/widgets.git.git/info/refs", "service=git-upload-pack", ""},
		// Host is still consulted by grant selection before the matcher.
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.pol.Match(&policy.Request{
				Method: c.method, Host: "code.test", Path: c.path, Query: c.query,
			})
			if got.Grant != c.want {
				t.Fatalf("match %s %s?%s = {%q %q}, want grant %q",
					c.method, c.path, c.query, got.Grant, got.Reason, c.want)
			}
			if c.want == "" && got.Reason != policy.ReasonNoGrant {
				t.Fatalf("no-match reason = %q, want NO_GRANT", got.Reason)
			}
		})
	}

	// Traversal-shaped requests never reach the matcher: the §2.1 pre-checks
	// reject them as SMUGGLING_SUSPECT before any grant is consulted.
	for _, path := range []string{
		"/acme/widgets/../widgets.git/info/refs",
		"/acme/%2e%2e/widgets.git/info/refs",
		"/acme/widgets%2egit/info/refs",
		"/acme%2fwidgets.git/info/refs",
		"/acme/widgets.git/info/%2e%2e/refs",
	} {
		got := read.Match(&policy.Request{
			Method: "GET", Host: "code.test", Path: path, Query: "service=git-upload-pack",
		})
		if got.Reason != policy.ReasonSmugglingSuspect {
			t.Fatalf("traversal %q = {%q %q}, want SMUGGLING_SUSPECT", path, got.Grant, got.Reason)
		}
	}

	// Host / scheme / port still gate a matcher grant (matcher replaces
	// methods/paths only).
	if got := read.Match(&policy.Request{
		Method: "GET", Host: "other.test", Path: "/acme/widgets.git/info/refs",
		Query: "service=git-upload-pack",
	}); got.Grant != "" {
		t.Fatalf("wrong host matched: %+v", got)
	}
	if got := read.Match(&policy.Request{
		Method: "GET", Host: "code.test", Port: 8443, Path: "/acme/widgets.git/info/refs",
		Query: "service=git-upload-pack",
	}); got.Grant != "" {
		t.Fatalf("wrong port matched: %+v", got)
	}
}

// TestC364GitMatcherRows is C3.6.4: the decision table must carry at least
// 30 rows exercising the git-smart-http matcher.
func TestC364GitMatcherRows(t *testing.T) {
	vf := loadVectors(t)
	n := 0
	for _, row := range vf.Rows {
		if strings.HasPrefix(row.Name, "gitm-") {
			n++
		}
	}
	if n < 30 {
		t.Fatalf("decision table has %d gitm-* rows, need >= 30", n)
	}
}
