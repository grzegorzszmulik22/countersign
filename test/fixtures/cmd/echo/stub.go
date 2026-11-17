// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Fixture commands are built only with the `fixtures` tag. This stub keeps
// release `go build ./...` working: the binary exists but refuses to run.
//go:build !fixtures

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "echo: fixture binary requires -tags fixtures")
	os.Exit(2)
}
