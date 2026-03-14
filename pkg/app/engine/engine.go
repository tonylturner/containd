// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dhcpd"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/engine"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/pcap"
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

func initialEngineConfig(ifaces []string, enforceEnabled bool, enforceTable string) engine.Config {
	return engine.Config{
		Capture: capture.Config{Interfaces: ifaces},
		Enforce: engine.EnforceConfig{
			Enabled:   enforceEnabled,
			TableName: enforceTable,
			Applier:   enforce.NewNftApplier(),
			Updater:   enforce.NewNftUpdater(enforceTable),
		},
		InspectAll: common.Env("CONTAIND_DPI_MOCK", "") == "1",
		DPIEnabled: true,
	}
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
	logging.InstallSlogBridge(logger.Desugar())
	ownership := newOwnershipManager(logger)

	ifaces := opts.CaptureInterfaces
	if len(ifaces) == 0 {
		ifaces = common.EnvCSV("CONTAIND_CAPTURE_IFACES")
	}
	enforceEnabled := common.EnvBool("CONTAIND_ENFORCE_ENABLED", false)
	if opts.EnforceEnabled != nil {
		enforceEnabled = *opts.EnforceEnabled
	}
	enforceTable := opts.EnforceTable
	if enforceTable == "" {
		enforceTable = "containd"
	}

	dpEngine, err := engine.New(initialEngineConfig(ifaces, enforceEnabled, enforceTable))
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

	// Simulation manager for synthetic traffic (lab/demo mode).
	simMgr := &simulationManager{dpEngine: dpEngine, logger: logger}

	// Auto-start synthetic traffic generator if CONTAIND_DPI_MOCK=1.
	if common.Env("CONTAIND_DPI_MOCK", "") == "1" {
		simMgr.start(nil) // nil subnets → uses DefaultSubnets
	}

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
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if dpEngine == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("/internal/apply_rules", applyRulesHandler(dpEngine))
	mux.HandleFunc("/internal/rules", getRulesHandler(dpEngine))
	mux.HandleFunc("/internal/ruleset_status", rulesetStatusHandler(dpEngine))
	mux.HandleFunc("/internal/config", configHandler(logger, dpEngine, simMgr))
	mux.HandleFunc("/internal/pcap/config", pcapConfigHandler(pcapMgr, ownership))
	mux.HandleFunc("/internal/pcap/start", pcapStartHandler(pcapMgr, ownership))
	mux.HandleFunc("/internal/pcap/stop", pcapStopHandler(pcapMgr))
	mux.HandleFunc("/internal/pcap/status", pcapStatusHandler(pcapMgr))
	mux.HandleFunc("/internal/pcap/list", pcapListHandler(pcapMgr))
	mux.HandleFunc("/internal/pcap/upload", pcapUploadHandler(pcapMgr))
	mux.HandleFunc("/internal/pcap/download", pcapDownloadHandler(pcapMgr))
	mux.HandleFunc("/internal/pcap/tag", pcapTagHandler(pcapMgr))
	mux.HandleFunc("/internal/pcap/delete", pcapDeleteHandler(pcapMgr))
	mux.HandleFunc("/internal/pcap/replay", pcapReplayHandler(pcapMgr))
	mux.HandleFunc("/internal/pcap/analyze", pcapAnalyzeUploadHandler(pcapMgr, dpEngine))
	mux.HandleFunc("/internal/pcap/analyze/", pcapAnalyzeNameHandler(pcapMgr, dpEngine))
	mux.HandleFunc("/internal/interfaces", interfacesHandler(logger, ownership))
	mux.HandleFunc("/internal/routing", routingHandler(logger, ownership))
	mux.HandleFunc("/internal/interfaces/state", interfacesStateHandler())
	mux.HandleFunc("/internal/ownership", ownershipHandler(ownership))
	mux.HandleFunc("/internal/events", eventsHandler(dpEngine))
	mux.HandleFunc("/internal/flows", flowsHandler(dpEngine))
	mux.HandleFunc("/internal/stats/protocols", protoStatsHandler(dpEngine))
	mux.HandleFunc("/internal/stats/top-talkers", topTalkersHandler(dpEngine))
	mux.HandleFunc("/internal/inventory", inventoryHandler(dpEngine))
	mux.HandleFunc("/internal/inventory/", inventoryItemHandler(dpEngine))
	mux.HandleFunc("/internal/conntrack", conntrackHandler())
	mux.HandleFunc("/internal/blocks/host", blockHostHandler(dpEngine))
	mux.HandleFunc("/internal/blocks/flow", blockFlowHandler(dpEngine))
	mux.HandleFunc("/internal/services", servicesHandler(logger, dpEngine, ownership, dhcpMgr))
	mux.HandleFunc("/internal/wireguard/status", wireguardStatusHandler())
	mux.HandleFunc("/internal/dhcp/leases", dhcpLeasesHandler(dhcpMgr))
	mux.HandleFunc("/internal/simulation", simulationHandler(simMgr))

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
