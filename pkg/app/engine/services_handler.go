// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	engineapi "github.com/tonylturner/containd/api/engine"
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

type avConfigApplier interface {
	Apply(ctx context.Context, cfg config.AVConfig) error
}

// avApplyPending reports an apply that ran out of time while its backend
// was starting, as opposed to one the backend refused.
func avApplyPending(ctx context.Context, err error) bool {
	return err != nil && (ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded))
}

type dhcpConfigApplier interface {
	Apply(context.Context, config.DHCPConfig, []config.Interface) error
}

func servicesHandler(logger *zap.SugaredLogger, dpEngine *engine.Engine, ownership *ownershipManager, dhcpMgr *dhcpd.Manager, av avConfigApplier, gate *gateManager) http.HandlerFunc {
	var dhcp dhcpConfigApplier
	if dhcpMgr != nil {
		dhcp = dhcpMgr
	}
	return serviceApplyHandler(logger, dpEngine, ownership, dhcp, av, gate, netcfg.ApplyWireGuard)
}

func serviceApplyHandler(logger *zap.SugaredLogger, dpEngine *engine.Engine, ownership *ownershipManager, dhcpMgr dhcpConfigApplier, av avConfigApplier, gate *gateManager, applyWireGuard func(context.Context, config.WireGuardConfig) error) http.HandlerFunc {
	var current config.ServicesConfig
	var currentMu sync.Mutex
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
			failed := func(service string, err error) {
				logger.Errorf("apply %s failed: %v", service, err)
				// Never send raw backend errors: they may contain credentials.
				result.Faults = append(result.Faults, config.ServiceFault{Service: service, Kind: "runtime", Message: "runtime apply failed"})
			}
			var avErr error
			var avPending bool
			if av != nil {
				avCtx, cancelAV := context.WithTimeout(r.Context(), avApplyTimeout)
				backend := svc.AV
				if backend.BackendDisabled {
					backend.Enabled = false
				}
				avErr = av.Apply(avCtx, backend)
				avPending = avApplyPending(avCtx, avErr)
				cancelAV()
			}
			gate.applyAV(svc.AV)
			wgCtx, cancelWG := context.WithTimeout(r.Context(), 5*time.Second)
			if err := applyWireGuard(wgCtx, svc.VPN.WireGuard); err != nil {
				failed(config.ServiceWireGuard, err)
				if dpEngine != nil && dpEngine.Events() != nil {
					dpEngine.Events().Append(dpevents.Event{
						Proto:     "vpn",
						Kind:      "service.wireguard.apply_failed",
						Timestamp: time.Now().UTC(),
						Attributes: map[string]any{
							"error": err.Error(),
						},
					})
				}
			} else if dpEngine != nil && dpEngine.Events() != nil {
				kind := "service.wireguard.disabled"
				if svc.VPN.WireGuard.Enabled {
					kind = "service.wireguard.applied"
				}
				dpEngine.Events().Append(dpevents.Event{
					Proto:     "vpn",
					Kind:      kind,
					Timestamp: time.Now().UTC(),
					Attributes: map[string]any{
						"interface": func() string {
							if v := strings.TrimSpace(svc.VPN.WireGuard.Interface); v != "" {
								return v
							}
							return "wg0"
						}(),
						"listen_port": func() int {
							if svc.VPN.WireGuard.ListenPort > 0 {
								return svc.VPN.WireGuard.ListenPort
							}
							return 51820
						}(),
						"peers": len(svc.VPN.WireGuard.Peers),
					},
				})
			}
			cancelWG()
			if dhcpMgr != nil {
				var ifaces []config.Interface
				if ownership != nil {
					ifaces = ownership.currentInterfaces()
				}
				dhcpCtx, cancelDHCP := context.WithTimeout(r.Context(), 5*time.Second)
				if err := dhcpMgr.Apply(dhcpCtx, svc.DHCP, ifaces); err != nil {
					failed(config.ServiceDHCP, err)
				}
				cancelDHCP()
			}
			current = svc
			if avErr != nil && !avPending {
				failed(config.ServiceAV, avErr)
			}
			if avPending {
				warning := "AV backend is still starting; scanning is pending until it is ready"
				logger.Warnf("services apply: %s", warning)
				if dpEngine != nil && dpEngine.Events() != nil {
					dpEngine.Events().Append(dpevents.Event{Proto: "av", Kind: gateEventPending, Timestamp: time.Now().UTC(), Attributes: map[string]any{"error": avErr.Error()}})
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
