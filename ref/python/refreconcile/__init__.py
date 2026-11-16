# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# refreconcile — the executable specification of spec/04 §5–§7 (intents,
# reconciliation levels, expectation rules, MCP contracts) and spec/05 §1–§2
# (reversibility classes, autonomy), written for chunk M9.1 from those specs
# alone, using only the Python standard library.
#
# It operates on an abstract trace file: one JSON object per record body
# (docs/refreconcile.md), independent of the M1 bundle code.
