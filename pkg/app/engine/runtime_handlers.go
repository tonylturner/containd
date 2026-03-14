// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dhcpd"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/engine"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/ids"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/synth"
)

func wireguardStatusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		iface := strings.TrimSpace(r.URL.Query().Get("iface"))
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		st, err := netcfg.GetWireGuardStatus(ctx, iface)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "not supported") {
				http.Error(w, err.Error(), http.StatusNotImplemented)
				return
			}
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, st)
	}
}

type blockHostRequest struct {
	IP         string `json:"ip"`
	TTLSeconds int    `json:"ttlSeconds,omitempty"`
}

type blockFlowRequest struct {
	SrcIP      string `json:"srcIp"`
	DstIP      string `json:"dstIp"`
	Proto      string `json:"proto"`
	DstPort    string `json:"dstPort"`
	TTLSeconds int    `json:"ttlSeconds,omitempty"`
}

func blockHostHandler(dp *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if dp == nil || dp.Updater() == nil {
			http.Error(w, "updater unavailable", http.StatusServiceUnavailable)
			return
		}
		var req blockHostRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		ip := net.ParseIP(strings.TrimSpace(req.IP))
		if ip == nil || ip.To4() == nil {
			http.Error(w, "invalid ip", http.StatusBadRequest)
			return
		}
		if req.TTLSeconds < 0 {
			http.Error(w, "ttlSeconds must be >= 0", http.StatusBadRequest)
			return
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		if err := dp.Updater().BlockHostTemp(r.Context(), ip, ttl); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	}
}

func blockFlowHandler(dp *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if dp == nil || dp.Updater() == nil {
			http.Error(w, "updater unavailable", http.StatusServiceUnavailable)
			return
		}
		var req blockFlowRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		srcIP := net.ParseIP(strings.TrimSpace(req.SrcIP))
		dstIP := net.ParseIP(strings.TrimSpace(req.DstIP))
		if srcIP == nil || srcIP.To4() == nil || dstIP == nil || dstIP.To4() == nil {
			http.Error(w, "invalid flow ip", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.Proto) == "" || strings.TrimSpace(req.DstPort) == "" {
			http.Error(w, "proto and dstPort required", http.StatusBadRequest)
			return
		}
		if req.TTLSeconds < 0 {
			http.Error(w, "ttlSeconds must be >= 0", http.StatusBadRequest)
			return
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		if err := dp.Updater().BlockFlowTemp(r.Context(), srcIP, dstIP, strings.ToLower(strings.TrimSpace(req.Proto)), strings.TrimSpace(req.DstPort), ttl); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	}
}

func servicesHandler(logger *zap.SugaredLogger, dpEngine *engine.Engine, ownership *ownershipManager, dhcpMgr *dhcpd.Manager) http.HandlerFunc {
	var current config.ServicesConfig
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
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
			if dpEngine != nil && dpEngine.AVSink() != nil {
				if adapter, ok := dpEngine.AVSink().(*avSinkAdapter); ok && adapter != nil {
					avCtx, cancelAV := context.WithTimeout(r.Context(), 3*time.Second)
					_ = adapter.ApplyAVConfig(avCtx, svc.AV)
					cancelAV()
				}
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			if err := netcfg.ApplyWireGuard(ctx, svc.VPN.WireGuard); err != nil {
				logger.Errorf("apply wireguard failed: %v", err)
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
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if dpEngine != nil && dpEngine.Events() != nil {
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
			if dhcpMgr != nil {
				var ifaces []config.Interface
				if ownership != nil {
					ifaces = ownership.currentInterfaces()
				}
				if err := dhcpMgr.Apply(ctx, svc.DHCP, ifaces); err != nil {
					logger.Errorf("apply dhcp failed: %v", err)
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			}
			current = svc
			writeJSON(w, map[string]any{"status": "applied"})
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}
}

func dhcpLeasesHandler(mgr *dhcpd.Manager) http.HandlerFunc {
	type resp struct {
		Leases []dhcpd.Lease `json:"leases"`
		Status any           `json:"status,omitempty"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if mgr == nil {
			writeJSON(w, resp{Leases: nil, Status: map[string]any{"enabled": false}})
			return
		}
		writeJSON(w, resp{Leases: mgr.Leases(), Status: mgr.Status()})
	}
}

func conntrackHandler() http.HandlerFunc {
	type resp struct {
		Entries []conntrack.Entry `json:"entries"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			limit := 200
			if q := strings.TrimSpace(r.URL.Query().Get("limit")); q != "" {
				if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 5000 {
					limit = v
				}
			}
			entries, err := conntrack.List(limit)
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			writeJSON(w, resp{Entries: entries})
			return
		case http.MethodPost:
			var req conntrack.DeleteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if err := conntrack.Delete(ctx, req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]any{"status": "deleted"})
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	resp := healthResponse{
		Status:    "ok",
		Component: "engine",
		Build:     config.BuildVersion,
	}
	writeJSON(w, resp)
}

func applyRulesHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		var snap rules.Snapshot
		if err := json.Unmarshal(body, &snap); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := dpEngine.ApplyRules(ctx, snap); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"status": "applied"})
	}
}

func getRulesHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		snap := dpEngine.CurrentRules()
		if snap == nil {
			http.Error(w, "no rules loaded", http.StatusNotFound)
			return
		}
		writeJSON(w, snap)
	}
}

func rulesetStatusHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		status := dpEngine.RulesetStatus()
		writeJSON(w, status)
	}
}

func configHandler(logger *zap.SugaredLogger, dpEngine *engine.Engine, simMgr *simulationManager) http.HandlerFunc {
	var current config.DataPlaneConfig
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, current)
			return
		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
			var dp config.DataPlaneConfig
			if err := json.Unmarshal(body, &dp); err != nil {
				http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
				return
			}
			current = dp
			var excl []engine.DPIExclusion
			for _, e := range dp.DPIExclusions {
				excl = append(excl, engine.DPIExclusion{Value: e.Value, Type: e.Type})
			}
			newEngine, err := engine.New(engine.Config{
				Capture:         capture.Config{Interfaces: dp.CaptureInterfaces},
				Enforce:         engine.EnforceConfig{Enabled: dp.Enforcement, TableName: firstNonEmpty(dp.EnforceTable, "containd"), Applier: enforce.NewNftApplier(), Updater: enforce.NewNftUpdater(firstNonEmpty(dp.EnforceTable, "containd"))},
				InspectAll:      dp.DPIMock,
				DPIEnabled:      dp.DPIEnabled,
				DPIMode:         dp.DPIMode,
				DPIProtocols:    dp.DPIProtocols,
				DPIICSProtocols: dp.DPIICSProtocols,
				DPIExclusions:   excl,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			dpEngine.Reconfigure(newEngine)
			go func() {
				if err := dpEngine.Start(context.Background()); err != nil {
					logger.Errorf("capture start failed: %v", err)
				}
			}()
			if dp.DPIMock {
				simMgr.stop()
				simMgr.start(nil)
			} else {
				simMgr.stop()
			}
			writeJSON(w, map[string]any{"status": "configured"})
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}
}

type simulationManager struct {
	dpEngine *engine.Engine
	logger   *zap.SugaredLogger
	cancel   context.CancelFunc
	running  bool
}

func (sm *simulationManager) start(subnets []synth.Subnet) {
	if sm.running {
		return
	}
	cfg := synth.Config{
		EventsPerSecond: 4,
		Subnets:         subnets,
		OnEvent:         synthIDSCallback(sm.dpEngine),
	}
	ctx, cancel := context.WithCancel(context.Background())
	sm.cancel = cancel
	sm.running = true
	sm.logger.Infof("simulation started (%d subnets)", len(cfg.Subnets))
	go synth.Run(ctx, sm.dpEngine.Events(), cfg)
}

func (sm *simulationManager) stop() {
	if !sm.running || sm.cancel == nil {
		return
	}
	sm.cancel()
	sm.cancel = nil
	sm.running = false
	sm.logger.Infof("simulation stopped")
}

func simulationHandler(sm *simulationManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]any{"running": sm.running})
		case http.MethodPost:
			var req struct {
				Action  string         `json:"action"`
				Subnets []synth.Subnet `json:"subnets,omitempty"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
			switch req.Action {
			case "start":
				sm.start(req.Subnets)
				writeJSON(w, map[string]any{"running": true})
			case "stop":
				sm.stop()
				writeJSON(w, map[string]any{"running": false})
			default:
				http.Error(w, `action must be "start" or "stop"`, http.StatusBadRequest)
			}
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func synthIDSCallback(dpEngine *engine.Engine) func(dpevents.Event) {
	return func(ev dpevents.Event) {
		snap := dpEngine.CurrentRules()
		if snap == nil || !snap.IDS.Enabled || len(snap.IDS.Rules) == 0 {
			return
		}
		eval := ids.New(snap.IDS)
		dpiEv := dpi.Event{
			FlowID:     ev.FlowID,
			Proto:      ev.Proto,
			Kind:       ev.Kind,
			Attributes: ev.Attributes,
			Timestamp:  ev.Timestamp,
		}
		alerts := eval.Evaluate(dpiEv)
		for _, a := range alerts {
			dpEngine.Events().Append(dpevents.Event{
				FlowID:     ev.FlowID,
				Proto:      a.Proto,
				Kind:       a.Kind,
				Attributes: a.Attributes,
				Timestamp:  a.Timestamp,
				SrcIP:      ev.SrcIP,
				DstIP:      ev.DstIP,
				SrcPort:    ev.SrcPort,
				DstPort:    ev.DstPort,
				Transport:  ev.Transport,
			})
		}
	}
}
