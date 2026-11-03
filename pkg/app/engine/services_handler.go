// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	engineapi "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/dhcpd"
	"github.com/tonylturner/containd/pkg/dp/engine"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
	"go.uber.org/zap"
)

// avApplyTimeout bounds how long a services apply waits for the scanner
// backend to become ready; it stays within management's request timeout. A
// backend still starting when it ends is pending, not failed: the AV
// manager keeps bringing it up and the gate withholds or passes selected
// objects by the fail policy until it is ready.
const avApplyTimeout = 3 * time.Second

type avDeliveryOwner interface {
	ApplyDelivery(context.Context, protection.Metadata, config.AVConfig) (protection.OwnerOutcome, error)
	RetryDelivery(context.Context, protection.Metadata) (protection.OwnerOutcome, error)
	DeliveryOutcome() protection.OwnerOutcome
}

type dhcpDeliveryOwner interface {
	ApplyDelivery(context.Context, protection.Metadata, config.DHCPConfig, []config.Interface) (protection.OwnerOutcome, error)
	RetryDelivery(context.Context, protection.Metadata) (protection.OwnerOutcome, error)
	DeliveryOutcome() protection.OwnerOutcome
}

func servicesHandler(logger *zap.SugaredLogger, dpEngine *engine.Engine, ownership *ownershipManager, dhcpMgr *dhcpd.Manager, av avDeliveryOwner, gate *gateManager, coordinator *protectionCoordinator) http.HandlerFunc {
	var dhcp dhcpDeliveryOwner
	if dhcpMgr != nil {
		dhcp = dhcpMgr
	}
	applyWireGuard := func(ctx context.Context, cfg config.WireGuardConfig) error {
		err := netcfg.ApplyWireGuard(ctx, cfg)
		if dpEngine != nil && dpEngine.Events() != nil {
			kind := "service.wireguard.disabled"
			var attrs map[string]any
			if err != nil {
				kind, attrs = "service.wireguard.apply_failed", map[string]any{"error": "runtime apply failed"}
			} else {
				if cfg.Enabled {
					kind = "service.wireguard.applied"
				}
				iface := strings.TrimSpace(cfg.Interface)
				if iface == "" {
					iface = "wg0"
				}
				port := cfg.ListenPort
				if port <= 0 {
					port = 51820
				}
				attrs = map[string]any{"interface": iface, "listen_port": port, "peers": len(cfg.Peers)}
			}
			dpEngine.Events().Append(dpevents.Event{Proto: "vpn", Kind: kind, Timestamp: time.Now().UTC(), Attributes: attrs})
		}
		return err
	}
	return coordinator.admit("services", serviceApplyHandler(logger, dpEngine, ownership, dhcp, av, gate, newWireGuardDelivery(applyWireGuard, observeWireGuard)))
}

func serviceApplyHandler(logger *zap.SugaredLogger, dpEngine *engine.Engine, ownership *ownershipManager, dhcpMgr dhcpDeliveryOwner, av avDeliveryOwner, gate *gateManager, wg *wireGuardDelivery) http.HandlerFunc {
	var current config.ServicesConfig
	var currentMu sync.Mutex
	// Admission serializes effects with retries. The handler mutex also protects GET.
	if dpEngine != nil {
		dpEngine.ObserveServiceDelivery(func() []protection.OwnerOutcome {
			out := []protection.OwnerOutcome{wg.observation()}
			if av != nil {
				out = append(out, av.DeliveryOutcome())
			}
			if dhcpMgr != nil {
				out = append(out, dhcpMgr.DeliveryOutcome())
			}
			return out
		})
	}
	var currentMeta protection.Metadata
	retry := func(ctx context.Context, meta protection.Metadata) ([]protection.OwnerOutcome, error) {
		currentMu.Lock()
		defer currentMu.Unlock()
		if currentMeta != meta {
			return nil, nil
		}
		var out []protection.OwnerOutcome
		if av != nil {
			o, err := av.RetryDelivery(ctx, meta)
			if err != nil {
				return out, err
			}
			out = append(out, o)
		}
		o, err := wg.retry(ctx, meta)
		if err != nil {
			return out, err
		}
		out = append(out, o)
		if dhcpMgr != nil {
			o, err := dhcpMgr.RetryDelivery(ctx, meta)
			if err != nil {
				return out, err
			}
			out = append(out, o)
		}
		return out, nil
	}

	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			currentMu.Lock()
			defer currentMu.Unlock()
			writeJSON(w, current)
			return
		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
			var svc config.ServicesConfig
			if err := json.Unmarshal(body, &svc); err != nil {
				http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
				return
			}
			if ownership != nil {
				ownership.applyMu.Lock()
				defer ownership.applyMu.Unlock()
				if !resolvedPhaseInput(w, r, "services", struct {
					Services   config.ServicesConfig
					Interfaces []config.Interface
				}{svc, ownership.currentInterfaces()}) {
					return
				}
			}
			if dpEngine != nil {
				if err := config.ValidateManagementServices(svc, dpEngine.ManagementReservation()); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			}
			currentMu.Lock()
			defer currentMu.Unlock()
			result := engineapi.ServicesApplyResult{Faults: []config.ServiceFault{}}
			failed := func(service string) {
				logger.Errorf("apply %s failed: runtime apply failed", service)
				// Never send raw backend errors: they may contain credentials.
				result.Faults = append(result.Faults, config.ServiceFault{Service: service, Kind: "runtime", Message: "runtime apply failed"})
			}

			completion, labelled := r.Context().Value(completionKey{}).(phaseCompletion)
			if !labelled {
				http.Error(w, "service delivery identity required", http.StatusBadRequest)
				return
			}
			currentMeta = completion.m
			completion.c.retryServices = retry
			publish := func(out protection.OwnerOutcome) {
				completion.c.dp.SetProtectionOutcome(completion.m, out)
				if out.Fault != nil {
					failed(string(out.Name))
				}
			}
			invalidate := func(name protection.SubsystemName, enabled bool) {
				completion.c.outcome(completion.m, name, enabled, false, false, "")
			}
			var avPending bool
			if av != nil {
				backend := svc.AV
				if backend.BackendDisabled {
					backend.Enabled = false
				}
				before := av.DeliveryOutcome()
				// The owner invalidates its own ledger before mutation. Revoke the
				// projected proof while it decides whether this input can be adopted.
				// Old-attempt proofs are already fenced by metadata.
				avCtx, cancel := context.WithTimeout(r.Context(), avApplyTimeout)
				if before.Acknowledged == nil {
					invalidate(protection.SubsystemAV, backend.Enabled)
				}
				out, err := av.ApplyDelivery(avCtx, completion.m, backend)
				cancel()
				if err != nil {
					http.Error(w, "AV delivery identity rejected", http.StatusConflict)
					return
				}
				avPending = out.State == protection.DeliveryPending
				publish(out)
			}
			gate.applyAV(svc.AV)
			wgCtx, cancelWG := context.WithTimeout(r.Context(), 5*time.Second)
			out, err := wg.deliver(wgCtx, completion.m, svc.VPN.WireGuard, func() { invalidate(protection.SubsystemWireGuard, svc.VPN.WireGuard.Enabled) })
			cancelWG()
			if err != nil {
				http.Error(w, "WireGuard delivery identity rejected", http.StatusConflict)
				return
			}
			publish(out)
			if dhcpMgr != nil {
				var ifaces []config.Interface
				if ownership != nil {
					ifaces = ownership.currentInterfaces()
				}
				dhcpCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
				out, err := dhcpMgr.ApplyDelivery(dhcpCtx, completion.m, svc.DHCP, ifaces)
				cancel()
				if err != nil {
					http.Error(w, "DHCP delivery identity rejected", http.StatusConflict)
					return
				}
				publish(out)
			}
			current = svc
			if avPending {
				warning := "AV backend is still starting; scanning is pending until it is ready"
				logger.Warnf("services apply: %s", warning)
				if dpEngine != nil && dpEngine.Events() != nil {
					dpEngine.Events().Append(dpevents.Event{Proto: "av", Kind: gateEventPending, Timestamp: time.Now().UTC(), Attributes: map[string]any{"error": warning}})
				}
				result.Warnings = []string{warning}
			}
			writeJSON(w, result)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}
}
