package netcfg

import (
	"context"

	"github.com/containd/containd/pkg/cp/config"
)

// ApplyInterfaces applies interface addressing intent to the OS.
// Platform-specific implementations may be a no-op on unsupported systems.
func ApplyInterfaces(ctx context.Context, ifaces []config.Interface) error {
	return applyInterfaces(ctx, ifaces)
}

