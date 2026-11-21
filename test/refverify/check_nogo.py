# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""C1.5.3 — nothing under ref/python/refverify is generated from, or reads,
Go sources. The scan root is the refverify package only: ref/python also
contains refreconcile, an M9.x deliverable owned by another lane whose own
check suite governs it (its pack data deliberately names the shared
internal/reconcile JSON path).
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REF = os.path.join(ROOT, "ref", "python", "refverify")

# Path/expression patterns that would indicate Go-source reading or codegen.
PATTERNS = [
    (re.compile(r"[\"'`][^\"'`]*\.go[\"'`]"), "a .go file literal"),
    (re.compile(r"\binternal/"), "reference to internal/"),
    (re.compile(r"\bcmd/[a-z]"), "reference to cmd/"),
    (re.compile(r"go\.mod|go\.sum|golang\.org|go:generate"), "Go tooling reference"),
    (re.compile(r"generated from .*\.go|DO NOT EDIT.*[Gg]o"), "generated-from-Go marker"),
    (re.compile(r"\bexec\s*\(.*\bgo\b|\bgo\s+(build|test|run|generate)"), "invoking the go tool"),
]


def main() -> int:
    bad = []
    for dirpath, _dirs, files in os.walk(REF):
        for f in sorted(files):
            path = os.path.join(dirpath, f)
            rel = os.path.relpath(path, ROOT)
            if f.endswith(".go"):
                bad.append(f"{rel}: Go source file under ref/python/")
                continue
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    for n, line in enumerate(fh, 1):
                        for pat, why in PATTERNS:
                            if pat.search(line):
                                bad.append(f"{rel}:{n}: {why}: {line.strip()[:100]}")
            except (UnicodeDecodeError, OSError):
                continue
    for b in bad:
        print(f"  {b}")
    if bad:
        print(f"C1.5.3: {len(bad)} Go-source reference(s)")
        return 1
    print("C1.5.3: no Go sources read or generated under ref/python/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
