// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import "strings"

// gitSmartHTTPMatch implements the git-smart-http semantic matcher of 04 §2
// (M3.6). For repository OWNER/REPO the ".git" suffix on the repo segment is
// optional transport syntax, on the wire and in a repos entry; every other
// byte of owner/repo compares case-sensitively.
//
//	read:  GET /<owner>/<repo>[.git]/info/refs?service=git-upload-pack
//	       POST /<owner>/<repo>[.git]/git-upload-pack
//	write: the above, plus ?service=git-receive-pack and
//	       POST /<owner>/<repo>[.git]/git-receive-pack
//
// The info/refs query must be exactly "service=<svc>"; POST endpoints carry
// no query at all. Any other path, method or service value does not match.
// path is the already-unreserved-decoded request path; query is the raw
// query string without "?".
func gitSmartHTTPMatch(git *GitSmartHTTP, method, path, query string) bool {
	access, owner, repo, ok := GitRequestOp(method, path, query)
	return ok && git.Covers(access, owner, repo)
}

// GitRequestOp parses a request as a git smart-HTTP endpoint per 04 §2
// (M3.6) and reports the operation's access class and repository coordinate.
// ok is false for any other path, method or query shape.
func GitRequestOp(method, path, query string) (access, owner, repo string, ok bool) {
	segs := strings.Split(path, "/")
	if len(segs) > 0 && segs[0] == "" {
		segs = segs[1:]
	}
	switch {
	case len(segs) == 4 && segs[2] == "info" && segs[3] == "refs":
		if method != "GET" {
			return "", "", "", false
		}
		switch query {
		case "service=git-upload-pack":
			access = "read"
		case "service=git-receive-pack":
			access = "write"
		default:
			return "", "", "", false
		}
	case len(segs) == 3 && (segs[2] == "git-upload-pack" || segs[2] == "git-receive-pack"):
		if method != "POST" || query != "" {
			return "", "", "", false
		}
		access = "read"
		if segs[2] == "git-receive-pack" {
			access = "write"
		}
	default:
		return "", "", "", false
	}
	owner, repo = segs[0], gitRepoSeg(segs[1])
	if owner == "" || repo == "" {
		return "", "", "", false
	}
	return access, owner, repo, true
}

// Covers reports whether the matcher's repos list contains the repository
// and admits the operation's access class (write requires access: write).
func (git *GitSmartHTTP) Covers(access, owner, repo string) bool {
	if access == "write" && git.Access != "write" {
		return false
	}
	for _, e := range git.Repos {
		owner2, name2, ok := strings.Cut(e, "/")
		if !ok || strings.Contains(name2, "/") {
			continue
		}
		if owner2 == owner && gitRepoSeg(name2) == repo {
			return true
		}
	}
	return false
}

// gitRepoSeg drops one optional ".git" suffix from a repo segment.
func gitRepoSeg(seg string) string {
	return strings.TrimSuffix(seg, ".git")
}
