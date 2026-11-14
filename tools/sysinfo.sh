#!/usr/bin/env bash
# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0
#
# sysinfo.sh — print the machine description recorded with measurements
# (06-agent-loop.md §11, §12).
set -uo pipefail

echo "kernel: $(uname -r)"
echo "arch: $(uname -m)"

model=$(lscpu 2>/dev/null | sed -n 's/^Model name:[[:space:]]*//p' | head -1)
[ -z "$model" ] && model=$(sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -1)
[ -z "$model" ] && model="unknown"
echo "cpu_model: $model"

echo "cores: $(nproc)"

mem=$(awk '/^MemTotal:/{printf "%d MB", $2/1024}' /proc/meminfo)
echo "memory: ${mem:-unknown}"

dv=$(docker version --format '{{.Server.Version}}' 2>/dev/null)
[ -z "$dv" ] && dv=$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')
echo "docker: ${dv:-unavailable}"
