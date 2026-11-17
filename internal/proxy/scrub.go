// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/countersign/countersign/internal/creds"
)

// Response scrubbing (04 §4.5, M3.4): only requests whose credential was
// injected get a scrubber — every other response relays bytes unchanged
// and never enters the decoder. The broker offers upstream exactly
// "gzip, identity", decodes gzip, scans decoded plaintext for the
// secret's three wire forms (raw, base64, URL-escaped) plus the Basic
// composite, replaces them with the placeholder, and forwards an
// identity body to the client. Headers and trailers are scrubbed as
// complete strings; the count lands in result.http.scrubbed.

// newScrubber builds the pattern set for an injected credential: the
// three §4.5 forms plus the Basic base64(username:secret) composite for
// basic grants. The replacement is the session placeholder — the same
// string the client's environment held.
func newScrubber(plan *credPlan) *creds.Scrubber {
	pats := creds.Patterns(plan.secret)
	if plan.username != "" {
		pats = append(pats, creds.BasicPattern(plan.username, plan.secret))
	}
	return creds.NewScrubber(pats, []byte(plan.placeholder))
}

// scrubHeaders runs the scrubber over every response header value.
// Encoding-sensitive headers are dropped unconditionally for credentialed
// responses: Content-Length (the body changes length under replacement),
// Content-Encoding (the client receives identity), and per-field
// integrity digests (ETag, Content-Digest, Digest, Content-Md5) whose
// hashes would no longer match a scrubbed/decoded body.
func scrubHeaders(scr *creds.Scrubber, h http.Header) {
	for _, k := range []string{"Content-Length", "Content-Encoding",
		"Etag", "Content-Digest", "Digest", "Content-Md5"} {
		h.Del(k)
	}
	for _, vals := range h {
		for i, v := range vals {
			vals[i] = scr.Scrub(v)
		}
	}
}

// errUnsupportedEncoding marks an upstream response in a content encoding
// the broker did not offer (anything but gzip/identity) and therefore
// cannot scan — fail closed rather than forward unverifiable bytes.
var errUnsupportedEncoding = errors.New("countersign: unsupported upstream encoding")

// scrubBody wraps an upstream body for relay: decode gzip when present,
// then stream through the scrubber. It returns the reader the relay loop
// consumes and whether the response is being decoded (so encoding headers
// can be dropped — scrubHeaders already does for credentialed responses).
func scrubBody(res *http.Response) (io.Reader, error) {
	enc := strings.ToLower(strings.TrimSpace(res.Header.Get("Content-Encoding")))
	switch enc {
	case "", "identity":
		return res.Body, nil
	case "gzip":
		return gzip.NewReader(res.Body)
	default:
		// The broker offers only gzip and identity upstream (04 §4.5); an
		// upstream answering in another encoding cannot be scanned, so the
		// response cannot cross — fail closed.
		return nil, errUnsupportedEncoding
	}
}
