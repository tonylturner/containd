// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package netcfg

import (
	"context"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
)

type ApplyOptions struct {
	// Replace, when true, removes any non-desired interface addresses for interfaces
	// that declare Addresses in config (explicit, admin-triggered).
	Replace bool
	// Reservation is immutable startup authority, never configuration input.
	Reservation *mgmtpath.Reservation
}

// ApplyInterfaces adds desired addresses and removes only stale owned addresses.
// Platform-specific implementations may be a no-op on unsupported systems.
func ApplyInterfaces(ctx context.Context, ifaces []config.Interface) error {
	return ApplyInterfacesWithOptions(ctx, ifaces, ApplyOptions{})
}

// ApplyInterfacesWithOptions converges owned addresses while protecting the
// reserved management device, including during explicit replacement.
func ApplyInterfacesWithOptions(ctx context.Context, ifaces []config.Interface, opts ApplyOptions) error {
	return applyInterfaces(ctx, ifaces, opts)
}

// ApplyInterfacesReplace explicitly removes foreign as well as owned stale
// addresses on interfaces declaring addresses. Link-local addresses are spared.
// Engines with a reserved management path use ApplyInterfacesWithOptions.
func ApplyInterfacesReplace(ctx context.Context, ifaces []config.Interface) error {
	return applyInterfaces(ctx, ifaces, ApplyOptions{Replace: true})
}

// ApplyRouting converges static routes and policy rules marked with protocol 98.
// Identical foreign entries satisfy intent without being adopted. A displaced
// foreign route is journaled before replacement and restored on intent removal.
func ApplyRouting(ctx context.Context, routing config.RoutingConfig) error {
	return applyRouting(ctx, routing)
}

// ApplyRoutingReplace is the explicit reconcile entry point; ordinary applies
// have the same ownership-scoped convergence semantics.
func ApplyRoutingReplace(ctx context.Context, routing config.RoutingConfig) error {
	return applyRouting(ctx, routing)
}
