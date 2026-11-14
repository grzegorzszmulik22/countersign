# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""C1.5.1 — every import under ref/python/ is stdlib, cryptography, or local."""
import ast
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REF = os.path.join(ROOT, "ref", "python")


def main() -> int:
    local = set()
    for dirpath, _dirs, files in os.walk(REF):
        for f in files:
            if f.endswith(".py"):
                local.add(os.path.splitext(f)[0])
    local.add("refverify")

    bad = []
    for dirpath, _dirs, files in os.walk(REF):
        for f in files:
            if not f.endswith(".py"):
                continue
            path = os.path.join(dirpath, f)
            rel = os.path.relpath(path, ROOT)
            try:
                tree = ast.parse(open(path, "rb").read(), filename=rel)
            except SyntaxError as e:
                bad.append(f"{rel}: syntax error {e}")
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [] if node.level else [node.module.split(".")[0]]
                else:
                    continue
                for name in names:
                    if name in sys.stdlib_module_names or name == "cryptography" or name in local:
                        continue
                    bad.append(f"{rel}: forbidden import '{name}'")
    for b in bad:
        print(f"  {b}")
    if bad:
        print(f"C1.5.1: {len(bad)} forbidden import(s)")
        return 1
    print("C1.5.1: imports are stdlib + cryptography only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
