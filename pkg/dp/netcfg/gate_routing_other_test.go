// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package netcfg

import (
	"context"
	"errors"
	"testing"
)

func TestGateRoutingUnsupportedPlatform(t *testing.T) {
	t.Parallel()
	for name, call := range map[string]func(context.Context) error{"ensure": EnsureGateRouting, "remove": RemoveGateRouting} {
		if err := call(context.Background()); !errors.Is(err, errors.ErrUnsupported) {
			t.Fatalf("%s: err = %v, want errors.ErrUnsupported", name, err)
		}
	}
}
