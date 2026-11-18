// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Query abstraction (spec/04 §6.5): abstract traces carry the literal
// request query string; real evidence carries query_sha256/query_len. The
// engine must never compare digests by pretending they are literals — each
// rule applies to the appropriate query representation.
package reconcile

// query is the request query in one of two representations.
type query struct {
	lit string // literal query when known
	sha string // hex sha256 when digested
	ln  int64  // length in bytes when digested
}

// litQuery builds a literal query (abstract traces; "" is a valid literal).
func litQuery(s string) query { return query{lit: s, sha: sha256hex(s), ln: int64(len(s))} }

// digestQuery builds a digested query (real records). Empty sha means the
// query is unknown.
func digestQuery(sha string, ln int64) query { return query{sha: sha, ln: ln} }

// equal reports whether the query equals the literal s: direct compare for
// literal queries, digest+length compare for digested ones.
func (q query) equal(s string) bool {
	if q.sha == "" {
		return q.lit == s
	}
	return q.ln == int64(len(s)) && q.sha == sha256hex(s)
}

// nonEmpty reports whether the query is non-empty: a literal "" or a
// digested empty query (len 0) are empty; anything else is non-empty.
func (q query) nonEmpty() bool {
	if q.sha == "" {
		return q.lit != ""
	}
	return q.ln != 0
}
