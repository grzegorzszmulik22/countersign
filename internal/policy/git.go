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
	segs := strings.Split(path, "/")
	if len(segs) > 0 && segs[0] == "" {
		segs = segs[1:]
	}
	var need string
	switch {
	case len(segs) == 4 && segs[2] == "info" && segs[3] == "refs":
		if method != "GET" {
			return false
		}
		switch query {
		case "service=git-upload-pack":
			need = "read"
		case "service=git-receive-pack":
			need = "write"
		default:
			return false
		}
	case len(segs) == 3 && (segs[2] == "git-upload-pack" || segs[2] == "git-receive-pack"):
		if method != "POST" || query != "" {
			return false
		}
		if segs[2] == "git-upload-pack" {
			need = "read"
		} else {
			need = "write"
		}
	default:
		return false
	}
	if need == "write" && git.Access != "write" {
		return false
	}
	owner, name := segs[0], gitRepoSeg(segs[1])
	if owner == "" || name == "" {
		return false
	}
	for _, e := range git.Repos {
		owner2, name2, ok := strings.Cut(e, "/")
		if !ok || strings.Contains(name2, "/") {
			continue
		}
		if owner2 == owner && gitRepoSeg(name2) == name {
			return true
		}
	}
	return false
}

// gitRepoSeg drops one optional ".git" suffix from a repo segment.
func gitRepoSeg(seg string) string {
	return strings.TrimSuffix(seg, ".git")
}
