// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// Package names holds the project-wide name constants (02-architecture.md §9).
// These strings appear in Go sources only here and in import paths; the M0.1
// check suite enforces that.
package names

const (
	// Project is the working name of the system.
	Project = "countersign"
	// APIGroup is the Kubernetes API group for Countersign resources.
	APIGroup = "countersign.dev"
	// ModulePath is the Go module path (a placeholder per 02 §9).
	ModulePath = "github.com/countersign/countersign"
	// BoundaryHost is the in-sandbox host name of the readable boundary
	// endpoint answered by the broker (05 §15).
	BoundaryHost = "countersign.internal"
	// ClusterName is the name of the kind test cluster (06 §11).
	ClusterName = "countersign"
	// SystemNamespace hosts the trusted computing base (02 §8).
	SystemNamespace = "countersign-system"
)
