#!/usr/bin/env python3
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# `python -m refreconcile ...` dispatches to the corpus harness CLI.
import sys

from .corpus import main

sys.exit(main(sys.argv[1:]))
