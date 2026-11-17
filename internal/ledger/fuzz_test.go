// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package ledger_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/ledger"
)

// C1.4.7 Fuzz the bundle reader: never panics; arbitrary input that fails
// to parse yields E_BUNDLE, and inputs that parse but carry bad records
// yield structured E_* errors — never a panic or a crash.
func FuzzC147_BundleReader(f *testing.F) {
	b, _ := cleanBundle(&testing.T{})
	f.Add(b)
	f.Add([]byte{})
	f.Add([]byte("not a tar"))
	f.Add([]byte{0x1f, 0x8b})
	f.Add(b[:512])
	f.Fuzz(func(t *testing.T, data []byte) {
		members, err := ledger.ReadBundle(data)
		if err != nil {
			// Malformed archive: must be the E_BUNDLE class.
			var be *ledger.BundleError
			if !errors.As(err, &be) {
				t.Fatalf("ReadBundle error not E_BUNDLE-class: %v", err)
			}
			return
		}
		res := ledger.VerifyBundle2(members, keys.Manifest(nil))
		if res.Verdict == "INVALID" && len(res.Errors) > 0 {
			c := res.Errors[0].Code
			if !strings.HasPrefix(c, "E_") {
				t.Fatalf("unstructured error %q", c)
			}
		}
	})
}
