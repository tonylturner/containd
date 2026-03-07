// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package netcfg

import (
	"context"
	"fmt"
)

type dhcpLease struct {
	AddrCIDR string
	RouterIP string
}

func dhcpAcquireV4(ctx context.Context, dev string, timeoutSeconds int) (*dhcpLease, error) {
	_ = ctx
	_ = dev
	_ = timeoutSeconds
	return nil, fmt.Errorf("dhcp not supported on this platform")
}

