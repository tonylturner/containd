// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package netcfg

import (
	"context"

	"github.com/tonylturner/containd/pkg/cp/config"
)

type ApplyOptions struct {
	// Replace, when true, removes any non-desired interface addresses for interfaces
	// that declare Addresses in config (explicit, admin-triggered).
	Replace bool
}

type ApplyRoutingOptions struct {
	// Replace, when true, replaces managed routes/rules (best-effort).
	Replace bool
}

// ApplyInterfaces applies interface addressing intent to the OS.
// Platform-specific implementations may be a no-op on unsupported systems.
func ApplyInterfaces(ctx context.Context, ifaces []config.Interface) error {
	return applyInterfaces(ctx, ifaces, ApplyOptions{})
}

// ApplyInterfacesReplace performs a reconcile pass (replace semantics) for interfaces with configured addresses.
func ApplyInterfacesReplace(ctx context.Context, ifaces []config.Interface) error {
	return applyInterfaces(ctx, ifaces, ApplyOptions{Replace: true})
}

// ApplyRouting applies routing configuration (static routes and policy rules).
func ApplyRouting(ctx context.Context, routing config.RoutingConfig) error {
	return applyRouting(ctx, routing, ApplyRoutingOptions{})
}

// ApplyRoutingReplace performs a reconcile pass for routing rules (best-effort).
func ApplyRoutingReplace(ctx context.Context, routing config.RoutingConfig) error {
	return applyRouting(ctx, routing, ApplyRoutingOptions{Replace: true})
}
