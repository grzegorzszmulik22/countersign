# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""refverify — independent Python reference verifier for Countersign bundles.

Implements V1–V11 and V15 of spec/03-evidence-format.md §10, written from the
spec text and the upstream standards (DSSE v1, in-toto Statement v1, RFC 6962,
RFC 9162, C2SP signed-note/tlog-checkpoint) — not from the Go csverify.
Standard library plus ``cryptography`` only.
"""
