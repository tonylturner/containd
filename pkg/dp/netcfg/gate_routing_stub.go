// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package netcfg

import (
	"context"
	"errors"
	"fmt"
)

var errGateRoutingUnsupported = fmt.Errorf("gate policy routing requires Linux netlink: %w", errors.ErrUnsupported)

// EnsureGateRouting reports errors.ErrUnsupported: policy routing needs Linux.
func EnsureGateRouting(_ context.Context) error { return errGateRoutingUnsupported }

// RemoveGateRouting reports errors.ErrUnsupported: policy routing needs Linux.
func RemoveGateRouting(_ context.Context) error { return errGateRoutingUnsupported }
