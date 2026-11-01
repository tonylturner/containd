// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"errors"
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
// never invents a healthy engine.
var engineUnreachable = dpengine.IEC104Enforcement{Active: false, Healthy: false, Reason: "engine unreachable"}

// healthHandler is unauthenticated liveness and always returns 200.
// IEC104 queue/reset health remains separate from general ruleset state, and
// semantic ICS rule coverage (icsEnforcement) from the nft-level state.
func healthHandler(store config.Store, engine EngineClient, evidenceProviders ...any) gin.HandlerFunc {
	return func(c *gin.Context) {
		// One budget for all observations, not a fresh timeout per dependency.
		ctx, cancel := context.WithTimeout(c.Request.Context(), engineHealthTimeout)
		defer cancel()
		var snapshot config.HealthSnapshot
		snapshotErr := errors.New("configuration health unavailable")
		if reader, ok := store.(config.HealthReader); ok {
			snapshot, snapshotErr = reader.ReadHealthSnapshot(ctx)
		}
		iec := engineUnreachable
		protection := engineclient.UnknownProtection("")
		forwarding := netcfg.IPv4ForwardingUnknown
		if hc, ok := engine.(RuntimeHealthClient); ok && hc != nil {
			if health, err := hc.RuntimeHealth(ctx); err == nil && ctx.Err() == nil {
				iec = health.IEC104Enforcement
				if iec.Reason != "" {
					iec.Reason = "IEC104 enforcement unavailable"
				}
				protection = engineclient.NormalizeProtection(health.Protection, "")
				if protection.BootID != health.BootID {
					protection = engineclient.UnknownProtection("")
				}
				forwarding = health.IPv4Forwarding
			}
		}
		ruleset := observeRuleset(ctx, engine)
		enforcement := enforcementHealth(snapshot, snapshotErr, ruleset, protection)
		recovery := managementRecoveryHealth(ctx, store, ruleset)
		if recovery["state"] != recoveryInactive && recovery["state"] != recoveryUnknown {
			// Recovery enforces its own ruleset, never the stored policy.
			enforcement = gin.H{"state": "unavailable", "reason": "management recovery: stored running configuration not applied"}
		}
		binding := gin.H{"state": "unknown"}
		if snapshotErr == nil && snapshot.Config != nil && engine != nil {
			cfg := snapshot.Config
			state, stateErr := engine.ListInterfaceState(ctx)
			if stateErr == nil && ctx.Err() == nil {
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
		}
		if forwarding != netcfg.IPv4ForwardingEnabled && forwarding != netcfg.IPv4ForwardingDisabled {
			forwarding = netcfg.IPv4ForwardingUnknown
		}
		c.JSON(http.StatusOK, gin.H{
			"status":             "ok",
			"evidence":           gin.H{"state": evidenceHealth(readEvidence(evidenceProviders...))},
			"component":          "mgmt",
			"build":              config.BuildVersion,
			"time":               time.Now().UTC().Format(time.RFC3339Nano),
			"iec104Enforcement":  iec,
			"enforcement":        enforcement,
			"protection":         gin.H{"state": protection.State, "applyId": protection.ApplyID},
			"icsEnforcement":     icsEnforcementHealth(ruleset),
			"ipv4Forwarding":     forwarding,
			"managementBinding":  binding,
			"managementRecovery": recovery,
		})
	}
}

// managementRecoveryHealth reports boot recovery without the persisted fault
// text: health is unauthenticated and that text names stored rules. The
// authenticated management-reservation view carries the cause.
func managementRecoveryHealth(ctx context.Context, store config.Store, ruleset rulesetObservation) gin.H {
	fault, err := config.ManagementBootFaultForStore(ctx, store)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return gin.H{"state": recoveryUnknown, "reason": "boot fault state unavailable"}
	}
	if fault == "" {
		return gin.H{"state": recoveryInactive, "reason": ""}
	}
	const cause = "stored running configuration refused at boot"
	state, _ := observeManagementRecovery(ruleset)
	reason := map[string]string{
		recoveryApplied: cause + "; new transit is dropped",
		recoveryPending: cause + "; recovery ruleset not applied yet",
		recoveryFailed:  cause + "; recovery ruleset failed to apply",
	}[state]
	return gin.H{"state": state, "reason": reason}
}
