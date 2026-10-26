// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dhcpd"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/engine"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
	"github.com/tonylturner/containd/pkg/dp/pcap"
)

type Options struct {
	Reservation       *mgmtpath.Reservation
	Ready             chan<- struct{}
	Combined          bool
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
	BootID     string `json:"bootId"`

	ManagementReservation netcfg.ManagementHealth     `json:"managementReservation"`
	IEC104Enforcement     engine.IEC104Enforcement    `json:"iec104Enforcement"`
	IPv4Forwarding        netcfg.IPv4ForwardingStatus `json:"ipv4Forwarding"`
}

// engineBootID identifies this process, independent of wall-clock time.
var engineBootID = rand.Text()

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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	addr := opts.Addr
	if addr == "" {
		addr = ListenAddr(opts.Combined)
	}
	if err := opts.Reservation.ValidateEngineBind(addr); err != nil {
		return err
	}
	logger := logging.NewService("engine")
	logging.InstallSlogBridge(logger.Desugar())
	ownership := newOwnershipManager(logger)
	ownership.reservation = opts.Reservation

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

	engineCfg := initialEngineConfig(ifaces, enforceEnabled, enforceTable)
	engineCfg.Enforce.ManagementReservation = opts.Reservation
	engineCfg.Events = dpevents.NewStore(4096)
	engineCfg.OnError = func(err error) {
		logger.Errorf("data plane capture error: %v", err)
	}
	dpEngine, err := engine.New(engineCfg)
	if err != nil {
		return fmt.Errorf("failed to init dp engine: %w", err)
	}
	guard, err := netcfg.StartManagementGuard(ctx, opts.Reservation, func(f netcfg.ManagementFault) {
		logger.Errorf("reserved management path fault: %s interface=%s address=%s service=%s", f.Reason, f.Interface, f.Address, f.Service)
		dpEngine.Events().Append(dpevents.Event{Kind: "management.reservation.fault", Timestamp: f.Time, Attributes: map[string]any{"interface": f.Interface, "address": f.Address, "service": f.Service, "reason": f.Reason}})
	})
	if err != nil {
		return fmt.Errorf("reserved management path startup: %w", err)
	}
	defer guard.Close()
	ownership.guard = guard
	// The engine is the only AV owner: clamd, FreshClam and the scan worker
	// live with this process and stop with it.
	avMgr := services.NewAVManager(ctx, services.DefaultAVOptions())
	defer func() {
		if err := avMgr.Stop(); err != nil {
			logger.Errorf("stop antivirus: %v", err)
		}
	}()
	wireAVEvents(avMgr, dpEngine)
	avMgr.StartWorker()
	dpEngine.SetAVSink(&avSinkAdapter{av: avMgr})
	// Start capture (no-op if no interfaces).
	go func() {
		if err := dpEngine.StartWithRetry(ctx); err != nil {
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
	// Captures outlive their start request; close their files on shutdown.
	defer func() { _ = pcapMgr.Stop() }()
	mux.HandleFunc("/health", healthHandler(dpEngine, guard))
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if dpEngine == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("/internal/apply_rules", applyRulesHandler(dpEngine))
	mux.HandleFunc("/internal/rules", getRulesHandler(dpEngine))
	mux.HandleFunc("/internal/rules/preview", previewRuleHandler(dpEngine))
	mux.HandleFunc("/internal/ruleset/preview", previewRulesetHandler(dpEngine))
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
	metrics.SetIEC104PressureReader(dpEngine.IEC104PressureMetrics)
	// Combined mode shares this registry with management; split mode needs
	// its own engine scrape endpoint for live dataplane metrics.
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/internal/diagnostics/iec104", iec104PressureHandler(dpEngine))
	mux.HandleFunc("/internal/inventory", inventoryHandler(dpEngine))
	mux.HandleFunc("/internal/inventory/", inventoryItemHandler(dpEngine))
	mux.HandleFunc("/internal/conntrack", conntrackHandler(dpEngine))
	mux.HandleFunc("/internal/blocks/host", blockHostHandler(dpEngine))
	mux.HandleFunc("/internal/blocks/flow", blockFlowHandler(dpEngine))
	mux.HandleFunc("/internal/services", servicesHandler(logger, dpEngine, ownership, dhcpMgr, avMgr))
	registerAVHandlers(mux, avMgr)
	mux.HandleFunc("/internal/trust", trustHandler(avMgr))
	mux.HandleFunc("/internal/wireguard/status", wireguardStatusHandler())
	mux.HandleFunc("/internal/dhcp/leases", dhcpLeasesHandler(dhcpMgr))
	mux.HandleFunc("/internal/simulation", simulationHandler(simMgr))

	logger.Infof("containd engine starting on %s", addr)
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if opts.Ready != nil {
		close(opts.Ready)
	}
	errCh := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
