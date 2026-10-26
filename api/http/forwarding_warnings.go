// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
)

const ipv4ForwardingWarning = "ipv4 forwarding is disabled (net.ipv4.ip_forward=0); routed traffic will not pass"

func ipv4ForwardingCommitWarning(ctx context.Context, cfg *config.Config, engine EngineClient) string {
	if cfg == nil || engine == nil || !netcfg.RequiresIPv4Forwarding(cfg.Interfaces) {
		return ""
	}
	healthClient, ok := engine.(RuntimeHealthClient)
	if !ok {
		return ""
	}
	health, err := healthClient.RuntimeHealth(ctx)
	if err != nil || health.IPv4Forwarding != netcfg.IPv4ForwardingDisabled {
		return ""
	}
	return ipv4ForwardingWarning
}
