# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
"""CLI: ``python3 -m refverify <bundle> --keys keys.json`` → JSON verdict on
stdout. Exit 0 only for CLEAN and CLEAN_WITH_DENIALS; 1 otherwise; 2 on usage
or input errors."""
import sys

from . import verify

if __name__ == "__main__":
    sys.exit(verify.main())
