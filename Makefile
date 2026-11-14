# Copyright 2026 The Countersign Authors
# SPDX-License-Identifier: Apache-2.0

TOOLS_DIR := $(abspath .tools)
export PATH := $(TOOLS_DIR)/bin:$(PATH)
GO := $(TOOLS_DIR)/bin/go

.PHONY: tools lint test clean sysinfo regress check-% sabotage-% images

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

# M0.2 provides cluster-up/cluster-down/images/offline-on/offline-off and
# fixtures-up; they are intentionally absent until that chunk lands.
