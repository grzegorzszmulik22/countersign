// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package inspect

import (
	"encoding/json"

	"github.com/countersign/countersign/internal/reconcile"
)

// Canonical digests come from the M9 reconcile package (internal/reconcile
// owns the RFC 8785 implementation spec/04 §6.3 requires).

func decodeCanon(raw []byte) (any, error) { return reconcile.DecodeJSON(raw) }

func canonSHA256(v any) (string, error) { return reconcile.CanonSHA256(v) }

func canonString(v any) (string, error) { return reconcile.CanonString(v) }

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
