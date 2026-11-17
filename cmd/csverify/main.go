// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// csverify <bundle> --keys keys.json — the offline evidence verifier of
// 03 §10. Reads only the bundle and the trusted manifest; no network, no
// ledger access. Exit 0 only for CLEAN and CLEAN_WITH_DENIALS.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/countersign/countersign/internal/keys"
	"github.com/countersign/countersign/internal/ledger"
)

func main() {
	// `csverify <bundle> --keys keys.json` — the spec's order has the
	// positional first, so parse --keys by hand.
	var keysPath, bundlePath string
	rest := []string{}
	for i := 1; i < len(os.Args); i++ {
		a := os.Args[i]
		if a == "--keys" && i+1 < len(os.Args) {
			keysPath = os.Args[i+1]
			i++
		} else if len(a) > 7 && a[:7] == "--keys=" {
			keysPath = a[7:]
		} else {
			rest = append(rest, a)
		}
	}
	if len(rest) != 1 || keysPath == "" {
		fmt.Fprintln(os.Stderr, "usage: csverify <bundle> --keys keys.json")
		os.Exit(2)
	}
	bundlePath = rest[0]
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	m, err := keys.LoadManifest(keysPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	res := ledger.VerifyBundle(bundle, m)
	out, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println(string(out))
	if res.Verdict == "CLEAN" || res.Verdict == "CLEAN_WITH_DENIALS" {
		os.Exit(0)
	}
	os.Exit(1)
}
