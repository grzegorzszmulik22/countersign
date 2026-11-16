#!/usr/bin/env python3
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# Abstract trace files (M9.1): one JSON object per record body, one record
# per line. The first line is a trace.meta object carrying the policy, the
# contracts, a derivation note and the expected result; every following line
# is a record body with a "type" field drawn from spec/03 §4.
import json


class TraceFormatError(Exception):
    pass


def parse_lines(lines):
    """Parse trace text lines -> (meta, records)."""
    meta, records = None, []
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            raise TraceFormatError("line %d: invalid JSON: %s" % (n, e))
        if not isinstance(obj, dict) or not isinstance(obj.get("type"), str):
            raise TraceFormatError("line %d: not a JSON object with a type" % n)
        if meta is None:
            if obj["type"] != "trace.meta":
                raise TraceFormatError("line %d: first record must be "
                                       "trace.meta, not %r" % (n, obj["type"]))
            meta = obj
        else:
            records.append(obj)
    if meta is None:
        raise TraceFormatError("empty trace")
    return meta, records


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return parse_lines(f)
