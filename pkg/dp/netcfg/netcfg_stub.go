//go:build !linux

package netcfg

import (
	"context"

	"github.com/containd/containd/pkg/cp/config"
)

func applyInterfaces(ctx context.Context, ifaces []config.Interface, opts ApplyOptions) error {
	_ = ctx
	_ = ifaces
	_ = opts
	// No-op on non-Linux platforms.
	return nil
}
