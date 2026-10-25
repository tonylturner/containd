// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package netcfg

import (
	"context"
	"fmt"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
)

func StartManagementGuard(_ context.Context, r *mgmtpath.Reservation, _ func(ManagementFault)) (*ManagementGuard, error) {
	if r != nil {
		return nil, fmt.Errorf("reserved management path requires Linux netlink")
	}
	return nil, nil
}
func (g *ManagementGuard) Reconcile(_ context.Context) error { return nil }
