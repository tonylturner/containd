// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	engineclient "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
)

// RuntimeHealthClient reads health values observed in the engine's network
// namespace.
type RuntimeHealthClient interface {
	RuntimeHealth(ctx context.Context) (engineclient.RuntimeHealth, error)
}

// engineHealthTimeout keeps liveness fast when the engine is slow.
const engineHealthTimeout = time.Second

// engineUnreachable is reported when the engine cannot be asked: health
// never invents a healthy engine (contracts K6).
var engineUnreachable = dpengine.IEC104Enforcement{Active: false, Healthy: false, Reason: "engine unreachable"}

// healthHandler is unauthenticated liveness. It is always 200; the
// iec104Enforcement object carries the engine's enforcement health.
func healthHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		iec := engineUnreachable
		forwarding := netcfg.IPv4ForwardingUnknown
		if hc, ok := engine.(RuntimeHealthClient); ok && hc != nil {
			ctx, cancel := context.WithTimeout(c.Request.Context(), engineHealthTimeout)
			if health, err := hc.RuntimeHealth(ctx); err == nil {
				iec = health.IEC104Enforcement
				forwarding = health.IPv4Forwarding
			}
			cancel()
		}
		binding := gin.H{"state": "unknown"}
		if store != nil && engine != nil {
			ctx, cancel := context.WithTimeout(c.Request.Context(), engineHealthTimeout)
			cfg, cfgErr := store.Load(ctx)
			state, stateErr := engine.ListInterfaceState(ctx)
			if cfgErr == nil && stateErr == nil && cfg != nil {
				live := make([]string, 0, len(state))
				for _, iface := range state {
					if iface.Name != "lo" {
						live = append(live, iface.Name)
					}
				}
				ports := compile.UnboundManagementPorts(cfg, live)
				binding["state"] = "configured"
				if len(ports) > 0 {
					binding["state"] = "unbound-appliance"
					binding["recoveryPorts"] = ports
				}
			}
			cancel()
		}
		if forwarding != netcfg.IPv4ForwardingEnabled && forwarding != netcfg.IPv4ForwardingDisabled {
			forwarding = netcfg.IPv4ForwardingUnknown
		}
		c.JSON(http.StatusOK, gin.H{
			"status":            "ok",
			"component":         "mgmt",
			"build":             config.BuildVersion,
			"time":              time.Now().UTC().Format(time.RFC3339Nano),
			"iec104Enforcement": iec,
			"ipv4Forwarding":    forwarding,
			"managementBinding": binding,
		})
	}
}
