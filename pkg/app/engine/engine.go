// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/common/enginetransport"
	"github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dhcpd"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/engine"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
	"github.com/tonylturner/containd/pkg/dp/pcap"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
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
	Status     string                  `json:"status"`
	Component  string                  `json:"component"`
	Build      string                  `json:"build"`
	CommitHash string                  `json:"commitHash,omitempty"`
	BootID     string                  `json:"bootId"`
	Protection engine.ProtectionStatus `json:"protection"`

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
	nics, err := interfaceAddrs()
	if err != nil {
		return fmt.Errorf("engine listener: %w", err)
	}
	apiPath, err := engineListener(addr, opts.Combined, opts.Reservation, nics)
	if err != nil {
		return err
	}
	tlsConfig, err := enginetransport.ListenerTLS(addr)
	if err != nil {
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
	engineCfg.Enforce.EngineAPI = apiPath
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
	// The scanning gate runs beside the data plane while it enforces and
	// drives the data plane's gate admission switch.
	gateMgr := newGateManager(logger, avMgr, dpEngine, dpEngine.Events(), enforce.DefaultGatePlainPort, enforce.DefaultGateMasqPort)
	coordinator := newProtectionCoordinator(ctx, dpEngine, logger)
	defer coordinator.close()
	gateMgr.protection = dpEngine
	gateMgr.lifetime = ctx
	engine.SetGateCloser(gateMgr)
	defer engine.SetGateCloser(nil)
	defer gateMgr.close()
	gateMgr.setEnforcing(enforceEnabled)
	// Startup capture uses the same lifetime and join discipline as later applies.
	coordinator.start()

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

	evidenceStore, err := sqlite.Open(common.Env("CONTAIND_EVIDENCE_DB", "/data/evidence.db"), sqlite.Options{CompatibleProof: func(v learn.Versions) bool { return learn.CompatibleVersions(v) && v.Decoder == decoderVersion }, WatchMetadata: func() (evidence.Dataset, error) { return evidenceMetadata(dpEngine) }})
	if err != nil {
		return fmt.Errorf("evidence authority unavailable: %w", err)
	}
	defer func() { _ = evidenceStore.Close() }()
	watchCtx, stopWatchWorker := context.WithCancel(ctx)
	evidenceCollector := newEvidenceWatch(watchCtx, evidenceStore, dpEngine)
	defer func() {
		dpEngine.SetLearnWatchHook(nil)
		stopWatchWorker()
		<-evidenceCollector.done
		<-evidenceCollector.maintained
	}()
	learnerAPI := &evidenceAPI{store: evidenceStore, watch: evidenceCollector, generator: &learn.Generator{Store: evidenceStore, Certifier: &learn.CompilerCertifier{Store: evidenceStore}, CountWithheld: evidenceStore.CountWithheld}}
	mux := http.NewServeMux()
	learnerAPI.register(mux)
	pcapMgr := pcap.NewManager(common.Env("CONTAIND_PCAP_DIR", "/data/pcaps"))
	// Captures outlive their start request; close their files on shutdown.
	defer func() { _ = pcapMgr.Stop() }()
	mux.HandleFunc("/health", healthHandler(dpEngine, guard))
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if dpEngine == nil || evidenceCollector.err() != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("/internal/protection/retry", coordinator.retryHandler(gateMgr))
	mux.HandleFunc("/internal/apply_rules", applyRulesHandler(dpEngine, gateMgr, coordinator))
	mux.HandleFunc("/internal/rules", getRulesHandler(dpEngine))
	mux.HandleFunc("/internal/rules/preview", previewRuleHandler(dpEngine))
	mux.HandleFunc("/internal/ruleset/preview", previewRulesetHandler(dpEngine))
	mux.HandleFunc("/internal/ruleset_status", rulesetStatusHandler(dpEngine))
	mux.HandleFunc("/internal/config", configHandler(logger, gateFollower{Engine: dpEngine, gate: gateMgr}, simMgr, coordinator))
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
	mux.HandleFunc("/internal/pcap/analyze", pcapAnalyzeUploadHandler(pcapMgr, dpEngine, evidenceStore))
	mux.HandleFunc("/internal/pcap/analyze/", pcapAnalyzeNameHandler(pcapMgr, dpEngine, evidenceStore))
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
	mux.HandleFunc("/internal/anomalies", anomaliesHandler(dpEngine))
	mux.HandleFunc("/internal/signatures", signaturesHandler(dpEngine))
	mux.HandleFunc("/internal/signatures/matches", signatureMatchesHandler(dpEngine))
	mux.HandleFunc("/internal/conntrack", conntrackHandler(dpEngine))
	mux.HandleFunc("/internal/firewall/counters", ruleCountersHandler(dpEngine))
	mux.HandleFunc("/internal/firewall/shadow-counters", shadowCountersHandler(dpEngine))
	mux.HandleFunc("/internal/blocks/host", blockHostHandler(dpEngine, gateMgr))
	mux.HandleFunc("/internal/blocks/flow", blockFlowHandler(dpEngine, gateMgr))
	mux.HandleFunc("/internal/blocks/clear", clearBlocksHandler(dpEngine))
	mux.HandleFunc("/internal/services", servicesHandler(logger, dpEngine, ownership, dhcpMgr, avMgr, gateMgr, coordinator))
	registerAVHandlers(mux, avMgr, gateMgr)
	mux.HandleFunc("/internal/trust", trustHandler(avMgr))
	mux.HandleFunc("/internal/wireguard/status", wireguardStatusHandler())
	mux.HandleFunc("/internal/dhcp/leases", dhcpLeasesHandler(dhcpMgr))
	mux.HandleFunc("/internal/simulation", simulationHandler(simMgr))

	logger.Infof("containd engine starting on %s", addr)
	server := engineServer(addr, mux, tlsConfig)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if opts.Ready != nil {
		close(opts.Ready)
	}
	errCh := make(chan error, 1)
	go func() {
		if err := serveEngine(server, listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

// engineServer is the single assembly point for all registration families.
func engineServer(addr string, handler http.Handler, config *tls.Config) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, TLSConfig: config, Protocols: protocols}
}

func serveEngine(server *http.Server, listener net.Listener) error {
	if server.TLSConfig != nil {
		return server.ServeTLS(listener, "", "")
	}
	return server.Serve(listener)
}
