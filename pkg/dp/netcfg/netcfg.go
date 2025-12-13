package netcfg

import (
	"context"

	"github.com/containd/containd/pkg/cp/config"
)

type ApplyOptions struct {
	// Replace, when true, removes any non-desired interface addresses for interfaces
	// that declare Addresses in config (explicit, admin-triggered).
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
