// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !fixtures

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "fakereg: fixture binary requires -tags fixtures")
	os.Exit(2)
}
