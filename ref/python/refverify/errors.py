# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""Error/warning codes and the verifier's exception type."""


class VerifyError(Exception):
    """A verification failure. ``code`` is the E_* code; ``record`` is the
    0-based position in records.jsonl when applicable."""

    def __init__(self, code, detail, record=None, entry=None):
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.record = record
        self.entry = entry

    def obj(self):
        o = {"code": self.code, "detail": self.detail}
        if self.record is not None:
            o["record"] = self.record
        if self.entry is not None:
            o["entry"] = self.entry
        return o


def err_obj(code, detail, record=None, entry=None):
    return VerifyError(code, detail, record, entry).obj()
