// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

package names

import "testing"

func TestConstants(t *testing.T) {
	for name, v := range map[string]string{
		"Project":         Project,
		"APIGroup":        APIGroup,
		"ModulePath":      ModulePath,
		"BoundaryHost":    BoundaryHost,
		"ClusterName":     ClusterName,
		"SystemNamespace": SystemNamespace,
	} {
		if v == "" {
			t.Errorf("%s is empty", name)
		}
	}
	if APIGroup != "countersign.dev" {
		t.Errorf("APIGroup = %q, want countersign.dev", APIGroup)
	}
	if ModulePath != "github.com/countersign/countersign" {
		t.Errorf("ModulePath = %q, want github.com/countersign/countersign", ModulePath)
	}
}
