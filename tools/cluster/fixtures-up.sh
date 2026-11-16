#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# fixtures-up.sh — `make fixtures-up`: bring the cluster to the state fixture
# services need (cluster up, namespaces applied). The fixture workloads
# themselves are built and deployed by chunk M0.3 (written on another host);
# this target makes the milestone command line (`make ... fixtures-up ...`)
# safe to run before M0.3 lands.
set -euo pipefail
cd "$(dirname "$0")/../.."

tools/cluster/cluster-up.sh
echo "fixtures-up: namespaces ready; fixture workloads are provided by M0.3"
