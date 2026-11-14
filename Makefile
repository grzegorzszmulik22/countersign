# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0

TOOLS_DIR := $(abspath .tools)
export PATH := $(TOOLS_DIR)/bin:$(PATH)
GO := $(TOOLS_DIR)/bin/go

.PHONY: tools lint test clean sysinfo regress check-% sabotage-% images \
	cluster-up cluster-down offline-on offline-off fixtures-up

tools:
	@tools/install-tools.sh

lint:
	@command -v golangci-lint >/dev/null || { echo "missing golangci-lint: run make tools" >&2; exit 1; }
	golangci-lint run ./...
	tools/check-license.sh
	tools/lint-progress.sh

test:
	@test -x $(GO) || { echo "missing go toolchain: run make tools" >&2; exit 1; }
	$(GO) build ./...
	$(GO) test ./...

clean:
	rm -rf bin .check-work
	-$(GO) clean -testcache 2>/dev/null || true

sysinfo:
	@tools/sysinfo.sh

regress:
	@tools/regress.sh

check-%:
	@tools/check.sh "$*"

sabotage-%:
	@tools/sabotage.sh "$*"

# M0.2: hermetic kind cluster `countersign` (see docs/cluster.md).
images:
	@tools/cluster/images.sh

cluster-up:
	@tools/cluster/cluster-up.sh

cluster-down:
	@tools/cluster/cluster-down.sh

offline-on:
	@tools/cluster/offline.sh on

offline-off:
	@tools/cluster/offline.sh off

fixtures-up:
	@tools/cluster/fixtures-up.sh
