// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dhcpd"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/engine"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
	"github.com/tonylturner/containd/pkg/dp/pcap"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type Options struct {
	Addr              string
	CaptureInterfaces []string
	EnforceEnabled    *bool
	EnforceTable      string
}

type healthResponse struct {
	Status     string `json:"status"`
	Component  string `json:"component"`
	Build      string `json:"build"`
	CommitHash string `json:"commitHash,omitempty"`
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("json encode error", "error", err)
	}
}

func Run(ctx context.Context, opts Options) error {
	addr := opts.Addr
	if addr == "" {
		addr = common.Env("CONTAIND_ENGINE_ADDR", ":8081")
	}
	logger := logging.NewService("engine")
	ownership := newOwnershipManager(logger)

	ifaces := opts.CaptureInterfaces
	enforceEnabled := false
	if opts.EnforceEnabled != nil {
		enforceEnabled = *opts.EnforceEnabled
	}
	enforceTable := opts.EnforceTable
	if enforceTable == "" {
		enforceTable = "containd"
	}

	dpEngine, err := engine.New(engine.Config{
		Capture:    capture.Config{Interfaces: ifaces},
		Enforce:    engine.EnforceConfig{Enabled: enforceEnabled, TableName: enforceTable, Applier: enforce.NewNftApplier(), Updater: enforce.NewNftUpdater(enforceTable)},
		InspectAll: common.Env("CONTAIND_DPI_MOCK", "") == "1",
	})
	if err != nil {
		return fmt.Errorf("failed to init dp engine: %w", err)
	}
	avMgr := services.NewAVManager()
	if avMgr != nil {
		wireAVEvents(avMgr, dpEngine)
		avMgr.StartWorker(ctx)
		dpEngine.SetAVSink(&avSinkAdapter{av: avMgr, dp: dpEngine})
	}
	// Start capture (no-op if no interfaces).
	go func() {
		if err := dpEngine.Start(ctx); err != nil {
			logger.Errorf("capture start failed: %v", err)
		}
	}()

	ownership.start(ctx)
	dhcpMgr := dhcpd.NewManager()
	// Emit DHCP runtime events into the unified telemetry store.
	if dhcpMgr != nil {
		dhcpMgr.SetOnEvent(func(kind string, attrs map[string]any) {
			if dpEngine == nil || dpEngine.Events() == nil {
				return
			}
			dpEngine.Events().Append(dpevents.Event{
				Proto:      "dhcp",
				Kind:       kind,
				Attributes: attrs,
				Timestamp:  time.Now().UTC(),
			})
		})
	}

	mux := http.NewServeMux()
	pcapMgr := pcap.NewManager(common.Env("CONTAIND_PCAP_DIR", "/data/pcaps"))
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/internal/apply_rules", applyRulesHandler(dpEngine))
	mux.HandleFunc("/internal/rules", getRulesHandler(dpEngine))
	mux.HandleFunc("/internal/ruleset_status", rulesetStatusHandler(dpEngine))
	mux.HandleFunc("/internal/config", configHandler(logger, dpEngine))
	mux.HandleFunc("/internal/pcap/config", pcapConfigHandler(pcapMgr))
	mux.HandleFunc("/internal/pcap/start", pcapStartHandler(pcapMgr))
	mux.HandleFunc("/internal/pcap/stop", pcapStopHandler(pcapMgr))
	mux.HandleFunc("/internal/pcap/status", pcapStatusHandler(pcapMgr))
	mux.HandleFunc("/internal/pcap/list", pcapListHandler(pcapMgr))
	mux.HandleFunc("/internal/pcap/upload", pcapUploadHandler(pcapMgr))
	mux.HandleFunc("/internal/pcap/download", pcapDownloadHandler(pcapMgr))
	mux.HandleFunc("/internal/pcap/tag", pcapTagHandler(pcapMgr))
	mux.HandleFunc("/internal/pcap/delete", pcapDeleteHandler(pcapMgr))
	mux.HandleFunc("/internal/pcap/replay", pcapReplayHandler(pcapMgr))
	mux.HandleFunc("/internal/interfaces", interfacesHandler(logger, ownership))
	mux.HandleFunc("/internal/routing", routingHandler(logger, ownership))
	mux.HandleFunc("/internal/interfaces/state", interfacesStateHandler())
	mux.HandleFunc("/internal/ownership", ownershipHandler(ownership))
	mux.HandleFunc("/internal/events", eventsHandler(dpEngine))
	mux.HandleFunc("/internal/flows", flowsHandler(dpEngine))
	mux.HandleFunc("/internal/conntrack", conntrackHandler())
	mux.HandleFunc("/internal/blocks/host", blockHostHandler(dpEngine))
	mux.HandleFunc("/internal/blocks/flow", blockFlowHandler(dpEngine))
	mux.HandleFunc("/internal/services", servicesHandler(logger, dpEngine, ownership, dhcpMgr))
	mux.HandleFunc("/internal/wireguard/status", wireguardStatusHandler())
	mux.HandleFunc("/internal/dhcp/leases", dhcpLeasesHandler(dhcpMgr))

	logger.Infof("containd engine starting on %s", addr)
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		_ = server.Shutdown(context.Background())
		return ctx.Err()
	case err := <-errCh:
		return fmt.Errorf("engine server exited: %w", err)
	}
}

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

type avSinkAdapter struct {
	av *services.AVManager
	dp *engine.Engine
}

func (a *avSinkAdapter) EnqueueAVScan(ctx context.Context, task engine.AVScanTask) {
	if a == nil || a.av == nil {
		return
	}
	a.av.EnqueueScan(services.ScanTask{
		Hash:    task.Hash,
		Proto:   task.Proto,
		Source:  task.Source,
		Dest:    task.Dest,
		Preview: task.Preview,
		ICS:     task.ICS,
		Metadata: map[string]any{
			"direction": task.Direction,
			"flow_id":   task.FlowID,
		},
	})
}

func (a *avSinkAdapter) ApplyAVConfig(ctx context.Context, cfg config.AVConfig) error {
	if a == nil || a.av == nil {
		return fmt.Errorf("av sink unavailable")
	}
	return a.av.Apply(ctx, cfg)
}

// wireAVEvents attaches AV event and verdict handling into the engine telemetry/enforcement path.
func wireAVEvents(avMgr *services.AVManager, dpEngine *engine.Engine) {
	if avMgr == nil {
		return
	}
	if dpEngine != nil && dpEngine.Events() != nil {
		avMgr.OnEvent = func(kind string, attrs map[string]any) {
			dpEngine.Events().Append(dpevents.Event{
				Proto:      "service",
				Kind:       kind,
				Attributes: attrs,
				Timestamp:  time.Now().UTC(),
			})
		}
	}
	if dpEngine != nil {
		avMgr.OnVerdict = func(task services.ScanTask, res services.ScanResult) {
			handleAVVerdict(dpEngine, task, res)
		}
	}
}

// handleAVVerdict enforces AV results and emits telemetry.
func handleAVVerdict(dpEngine *engine.Engine, task services.ScanTask, res services.ScanResult) {
	if dpEngine == nil || res.Verdict == "" {
		return
	}
	events := dpEngine.Events()
	flowID := ""
	if task.Metadata != nil {
		if v, ok := task.Metadata["flow_id"].(string); ok {
			flowID = v
		}
	}
	emit := func(kind string, attrs map[string]any) {
		if events == nil {
			return
		}
		events.Append(dpevents.Event{
			Proto:      "service",
			Kind:       kind,
			Attributes: attrs,
			FlowID:     flowID,
			Timestamp:  time.Now().UTC(),
		})
	}
	// Bypass if ICS and fail-open-for-ICS is set.
	cfg := config.AVConfig{}
	if a, ok := dpEngine.AVSink().(*avSinkAdapter); ok && a != nil && a.av != nil {
		cfg = a.av.Current()
	}
	if task.ICS && cfg.FailOpenICS {
		emit("service.av.bypass_ics", map[string]any{
			"hash":   task.Hash,
			"proto":  task.Proto,
			"source": task.Source,
			"dest":   task.Dest,
		})
		return
	}
	if res.Verdict != "malware" {
		return
	}
	emit("service.av.detected", map[string]any{
		"hash":    task.Hash,
		"proto":   task.Proto,
		"source":  task.Source,
		"dest":    task.Dest,
		"flow_id": flowID,
	})
	upd := dpEngine.Updater()
	if upd == nil {
		return
	}
	srcIP, dstIP, dport, proto := parseHostPort(task.Source, task.Dest)
	if srcIP == nil || dstIP == nil || proto == "" || dport == "" {
		return
	}
	ttl := time.Duration(cfg.BlockTTL) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = upd.BlockFlowTemp(ctx, srcIP, dstIP, proto, dport, ttl)
	emit("service.av.block_flow", map[string]any{
		"hash":   task.Hash,
		"src":    task.Source,
		"dst":    task.Dest,
		"proto":  proto,
		"dport":  dport,
		"ttl":    int(ttl.Seconds()),
		"reason": "av_malware",
	})
}

func parseHostPort(src, dst string) (net.IP, net.IP, string, string) {
	srcHost, _, _ := strings.Cut(src, ":")
	dstHost, dstPort, _ := strings.Cut(dst, ":")
	return net.ParseIP(strings.TrimSpace(srcHost)), net.ParseIP(strings.TrimSpace(dstHost)), strings.TrimSpace(dstPort), "tcp"
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
				// Apply AV config in engine for inline scanning.
				if adapter, ok := dpEngine.AVSink().(*avSinkAdapter); ok && adapter != nil {
					avCtx, cancelAV := context.WithTimeout(r.Context(), 3*time.Second)
					_ = adapter.ApplyAVConfig(avCtx, svc.AV)
					cancelAV()
				}
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			// WireGuard runs in the engine (privileged) because it requires NET_ADMIN.
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

func addrFromEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
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

func configHandler(logger *zap.SugaredLogger, dpEngine *engine.Engine) http.HandlerFunc {
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
			// Reconfigure by rebuilding the engine instance.
			current = dp
			newEngine, err := engine.New(engine.Config{
				Capture:    capture.Config{Interfaces: dp.CaptureInterfaces},
				Enforce:    engine.EnforceConfig{Enabled: dp.Enforcement, TableName: firstNonEmpty(dp.EnforceTable, "containd"), Applier: enforce.NewNftApplier(), Updater: enforce.NewNftUpdater(firstNonEmpty(dp.EnforceTable, "containd"))},
				InspectAll: dp.DPIMock,
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
			writeJSON(w, map[string]any{"status": "configured"})
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}
}

func pcapConfigHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, mgr.Config())
			return
		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
			var cfg config.PCAPConfig
			if err := json.Unmarshal(body, &cfg); err != nil {
				http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
				return
			}
			wasRunning := mgr.Status().Running
			if err := mgr.Configure(cfg); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if wasRunning {
				_ = mgr.Stop()
				if cfg.Enabled {
					if err := mgr.Start(r.Context(), cfg); err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
				}
			}
			writeJSON(w, mgr.Config())
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}
}

func pcapStartHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cfg := mgr.Config()
		if r.ContentLength > 0 {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
			if err := json.Unmarshal(body, &cfg); err != nil {
				http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		if err := mgr.Start(r.Context(), cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, mgr.Status())
	}
}

func pcapStopHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = mgr.Stop()
		writeJSON(w, mgr.Status())
	}
}

func pcapStatusHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, mgr.Status())
	}
}

func pcapListHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		items, err := mgr.List()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, items)
	}
}

func pcapUploadHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseMultipartForm(64 << 20); err != nil {
			http.Error(w, "invalid multipart form: "+err.Error(), http.StatusBadRequest)
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file required", http.StatusBadRequest)
			return
		}
		defer file.Close()
		// Validate PCAP/PCAPng magic bytes.
		var magic [4]byte
		if _, err := io.ReadFull(file, magic[:]); err != nil {
			http.Error(w, "file too small or unreadable", http.StatusBadRequest)
			return
		}
		switch {
		case magic == [4]byte{0xd4, 0xc3, 0xb2, 0xa1}: // pcap LE
		case magic == [4]byte{0xa1, 0xb2, 0xc3, 0xd4}: // pcap BE
		case magic == [4]byte{0x0a, 0x0d, 0x0d, 0x0a}: // pcapng
		default:
			http.Error(w, "not a valid pcap/pcapng file", http.StatusBadRequest)
			return
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			http.Error(w, "failed to rewind file", http.StatusInternalServerError)
			return
		}
		item, err := mgr.Upload(header.Filename, file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, item)
	}
}

func pcapDownloadHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		f, size, err := mgr.Open(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
		_, _ = io.Copy(w, f)
	}
}

func pcapTagHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req pcap.TagRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		if err := mgr.Tag(req.Name, req.Tags); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func pcapDeleteHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		if err := mgr.Delete(name); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func pcapReplayHandler(mgr *pcap.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req pcap.ReplayRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Name == "" || req.Interface == "" {
			http.Error(w, "name and interface required", http.StatusBadRequest)
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			if err := mgr.Replay(ctx, req); err != nil {
				slog.Error("pcap replay failed", "name", req.Name, "error", err)
			}
		}()
		w.WriteHeader(http.StatusAccepted)
	}
}

func interfacesHandler(logger *zap.SugaredLogger, ownership *ownershipManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))
		replace := mode == "replace"
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		var ifaces []config.Interface
		if err := json.Unmarshal(body, &ifaces); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if replace {
			if err := netcfg.ApplyInterfacesReplace(ctx, ifaces); err != nil {
				logger.Errorf("apply interfaces(replace) failed: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			if err := netcfg.ApplyInterfaces(ctx, ifaces); err != nil {
				logger.Errorf("apply interfaces failed: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		// Store desired state for background ownership reconcile (non-destructive).
		if ownership != nil {
			ownership.setInterfaces(ifaces)
		}
		writeJSON(w, map[string]any{"status": "applied"})
	}
}

func interfacesStateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sysIfaces, err := net.Interfaces()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]config.InterfaceState, 0, len(sysIfaces))
		for _, si := range sysIfaces {
			addrs, _ := si.Addrs()
			ss := make([]string, 0, len(addrs))
			for _, a := range addrs {
				if s := strings.TrimSpace(a.String()); s != "" {
					ss = append(ss, s)
				}
			}
			sort.Strings(ss)
			out = append(out, config.InterfaceState{
				Name:  si.Name,
				Index: si.Index,
				Up:    (si.Flags & net.FlagUp) != 0,
				MTU:   si.MTU,
				MAC:   strings.TrimSpace(si.HardwareAddr.String()),
				Addrs: ss,
			})
		}
		writeJSON(w, out)
	}
}

func routingHandler(logger *zap.SugaredLogger, ownership *ownershipManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mode := strings.TrimSpace(r.URL.Query().Get("mode"))
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		var routing config.RoutingConfig
		if err := json.Unmarshal(body, &routing); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		resolved := routing
		if ownership != nil {
			// Best-effort resolve logical iface names (wan/dmz/lanX) to kernel device names
			// using the last known interface bindings.
			// If no bindings exist, the route will still apply when Iface already names a kernel device.
			resolved = resolveRoutingIfaces(routing, ownership.currentInterfaces())
		}
		applyErr := error(nil)
		if strings.EqualFold(mode, "replace") {
			applyErr = netcfg.ApplyRoutingReplace(ctx, resolved)
		} else {
			applyErr = netcfg.ApplyRouting(ctx, resolved)
		}
		if applyErr != nil {
			err := applyErr
			logger.Errorf("apply routing failed: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if ownership != nil {
			ownership.setRouting(routing)
		}
		writeJSON(w, map[string]any{"status": "applied"})
	}
}

func ownershipHandler(ownership *ownershipManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ownershipStatusJSON(ownership))
	}
}

func firstNonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func parseListEnv(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}


func eventsHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := parseLimit(r, 500)
		list := dpEngine.Events().List(limit)
		writeJSON(w, list)
	}
}

func flowsHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := parseLimit(r, 200)
		list := dpEngine.Events().Flows(limit)
		writeJSON(w, list)
	}
}

func parseLimit(r *http.Request, def int) int {
	q := r.URL.Query().Get("limit")
	if q == "" {
		return def
	}
	if v, err := strconv.Atoi(q); err == nil && v > 0 {
		return v
	}
	return def
}
