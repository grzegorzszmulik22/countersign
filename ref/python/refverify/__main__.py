# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""CLI: ``python3 -m refverify <bundle> --keys keys.json`` → JSON verdict on
stdout. Exit 0 only for CLEAN and CLEAN_WITH_DENIALS; 1 otherwise; 2 on usage
or input errors."""
import argparse
import json
import os
import sys

from . import verify


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="refverify",
        description="Countersign reference verifier (spec 03 §10: V1–V11, V15)")
    ap.add_argument("bundle", help="bundle tar archive")
    ap.add_argument("--keys", required=True,
                    help="trusted key manifest (keys.json)")
    args = ap.parse_args(argv)

    for p in (args.bundle, args.keys):
        if not os.path.isfile(p):
            print(f"refverify: no such file: {p}", file=sys.stderr)
            return 2
    try:
        out = verify.run(args.bundle, args.keys)
    except OSError as e:
        print(f"refverify: {e}", file=sys.stderr)
        return 2
    json.dump(out, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if out["verdict"] in ("CLEAN", "CLEAN_WITH_DENIALS") else 1


if __name__ == "__main__":
    sys.exit(main())
