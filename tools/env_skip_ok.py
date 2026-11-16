# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""Decide whether a failing `make check-<chunk>` run is only allowed environment skips.

Reads the run's output on stdin. Exits 0 when the output has at least one CHECK
line and every CHECK line that is not PASS is a SKIP whose check ID is listed in
the allowlist for this host. Prints one note per accepted skip. Exits 1 otherwise.

Usage: python3 tools/env_skip_ok.py tools/env-skips.txt "$(hostname -s)" < output
"""
import re
import sys


def allowed(path, host):
    ids = {}
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        if host in parts[1].split(","):
            ids[parts[0]] = parts[2] if len(parts) > 2 else ""
    return ids


def main():
    ok_ids = allowed(sys.argv[1], sys.argv[2])
    checks = re.findall(r"^CHECK (\S+) (PASS|SKIP|BLOCKED|FAIL)\b.*$", sys.stdin.read(), re.M)
    if not checks:
        return 1
    accepted = []
    for check_id, status in checks:
        if status == "PASS":
            continue
        if status == "SKIP" and check_id in ok_ids:
            accepted.append(check_id)
            continue
        return 1
    for check_id in accepted:
        print(f"regress: note: {check_id} SKIP accepted on {sys.argv[2]} ({ok_ids[check_id]})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
