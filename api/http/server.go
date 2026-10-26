// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	engineclient "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/common/trust"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	cpservices "github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/cp/users"
	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dhcpd"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/inventory"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
	"github.com/tonylturner/containd/pkg/dp/pcap"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/signatures"
	"github.com/tonylturner/containd/pkg/dp/stats"
)

// This file is the HTTP server/bootstrap facade for the management API.
// Keep route registration and shared wiring here; place endpoint bodies in
// focused sibling files grouped by domain (for example: *_handlers.go).

// NewServer builds a Gin engine with versioned routes for management APIs.
func NewServer(store config.Store, auditStore audit.Store) *gin.Engine {
	return NewServerWithEngine(store, auditStore, nil)
}

// EngineClient is an optional interface for pushing compiled snapshots to the data plane.
type EngineClient interface {
	Configure(ctx context.Context, cfg config.DataPlaneConfig) error
	ConfigureInterfaces(ctx context.Context, ifaces []config.Interface) error
	ConfigureInterfacesReplace(ctx context.Context, ifaces []config.Interface) error
	ConfigureRouting(ctx context.Context, routing config.RoutingConfig) error
	ConfigureRoutingReplace(ctx context.Context, routing config.RoutingConfig) error
	ConfigureServices(ctx context.Context, services config.ServicesConfig) error
	ListInterfaceState(ctx context.Context) ([]config.InterfaceState, error)
	ApplyRules(ctx context.Context, snap rules.Snapshot) error
	RulesetStatus(ctx context.Context) (dpengine.RulesetStatus, error)
	PcapConfig(ctx context.Context) (config.PCAPConfig, error)
	SetPcapConfig(ctx context.Context, cfg config.PCAPConfig) (config.PCAPConfig, error)
	StartPcap(ctx context.Context, cfg config.PCAPConfig) (pcap.Status, error)
	StopPcap(ctx context.Context) (pcap.Status, error)
	PcapStatus(ctx context.Context) (pcap.Status, error)
	ListPcaps(ctx context.Context) ([]pcap.Item, error)
	UploadPcap(ctx context.Context, filename string, r io.Reader) (pcap.Item, error)
	DeletePcap(ctx context.Context, name string) error
	TagPcap(ctx context.Context, req pcap.TagRequest) error
	ReplayPcap(ctx context.Context, req pcap.ReplayRequest) error
	DownloadPcap(ctx context.Context, name string) (*http.Response, error)
	BlockHostTemp(ctx context.Context, ip net.IP, ttl time.Duration) error
	BlockFlowTemp(ctx context.Context, srcIP, dstIP net.IP, proto string, dport string, ttl time.Duration) error
	// ClearBlocks removes every temporary block and connection revocation.
	ClearBlocks(ctx context.Context) error

	// Antivirus: the engine is the only scanner owner; management delegates.
	AVStatus(ctx context.Context) (map[string]any, error)
	TriggerAVUpdate(ctx context.Context) error
	ListAVDefs(ctx context.Context) (cpservices.AVDefinitionList, error)
	UploadAVDef(ctx context.Context, name string, r io.Reader) (cpservices.AVDefinition, error)
	DeleteAVDef(ctx context.Context, name string) error
	// ConfigureTrust distributes the additional CA bundle to the engine.
	ConfigureTrust(ctx context.Context, b trust.Bundle) error
}

// RulePreviewClient delegates impact evaluation to the engine's live policy context.
type RulePreviewClient interface {
	PreviewRule(ctx context.Context, entry rules.Entry) (dpengine.PreviewRuleResponse, error)
}

type TelemetryClient interface {
	ListEvents(ctx context.Context, limit int) ([]dpevents.Event, error)
	ListFlows(ctx context.Context, limit int) ([]dpevents.FlowSummary, error)
}

type ConntrackClient interface {
	ListConntrack(ctx context.Context, limit int) ([]dpengine.TaggedConnection, error)
}

type ConntrackKiller interface {
	DeleteConntrack(ctx context.Context, req conntrack.KillRequest) (conntrack.KillResult, error)
}

type DHCPLeasesClient interface {
	ListDHCPLeases(ctx context.Context) ([]dhcpd.Lease, error)
}

type WireGuardStatusClient interface {
	GetWireGuardStatus(ctx context.Context, iface string) (netcfg.WireGuardStatus, error)
}

// SimulationClient is an optional interface for controlling the synthetic traffic generator.
type SimulationClient interface {
	SimulationStatus(ctx context.Context) (engineclient.SimulationStatus, error)
	SimulationControl(ctx context.Context, action string) (engineclient.SimulationStatus, error)
}

// InventoryClient is an optional interface for querying the ICS asset inventory.
type InventoryClient interface {
	IEC104Inventory(ctx context.Context) (inventory.IEC104Snapshot, error)
	ListInventory(ctx context.Context) ([]inventory.DiscoveredAsset, error)
	GetInventoryAsset(ctx context.Context, ip string) (*inventory.DiscoveredAsset, error)
	ClearInventory(ctx context.Context) error
}

// AnomalyClient is an optional interface for protocol anomaly detection.
type AnomalyClient interface {
	ListAnomalies(ctx context.Context, limit int) ([]anomaly.Anomaly, error)
	ClearAnomalies(ctx context.Context) error
}

// LearnClient is an optional interface for ICS learn mode.
type LearnClient interface {
	ListLearnProfiles(ctx context.Context) ([]learn.LearnedProfile, error)
	GenerateLearnRules(ctx context.Context) ([]config.Rule, error)
	ClearLearnData(ctx context.Context) error
}

// SignaturesClient is an optional interface for ICS signature-based detection.
type SignaturesClient interface {
	ListSignatures(ctx context.Context) ([]signatures.Signature, error)
	AddSignature(ctx context.Context, sig signatures.Signature) error
	RemoveSignature(ctx context.Context, id string) (bool, error)
	ListSignatureMatches(ctx context.Context, limit int) ([]signatures.Match, error)
}

// StatsClient is an optional interface for querying protocol and flow statistics.
type StatsClient interface {
	ListProtoStats(ctx context.Context) ([]stats.ProtoStats, error)
	ListTopTalkers(ctx context.Context, n int) ([]stats.FlowStats, error)
}

type ServicesValidator interface {
	Validate(ctx context.Context, cfg config.ServicesConfig) error
}

// ServicesApplier is an optional interface for applying services config
// (syslog/proxies/etc.) when commits are made.
type ServicesApplier interface {
	Apply(ctx context.Context, cfg config.ServicesConfig) error
}

// NewServerWithEngine builds a Gin engine and optionally wires engine commit hooks.
func NewServerWithEngine(store config.Store, auditStore audit.Store, engine EngineClient) *gin.Engine {
	return NewServerWithEngineAndServices(store, auditStore, engine, nil, nil)
}

// NewServerWithEngineAndServices builds a Gin engine and optionally wires engine, services, and users stores.
// opts may contain ManagementGuardHealth, ManagementListenerFaults and
// FactoryResetSessions providers.
func NewServerWithEngineAndServices(store config.Store, auditStore audit.Store, engine EngineClient, services ServicesApplier, userStore users.Store, opts ...any) *gin.Engine {
	var guardHealth ManagementGuardHealth
	var listenerFaults ManagementListenerFaults
	var resetSessions FactoryResetSessions
	for _, opt := range opts {
		if provider, ok := opt.(FactoryResetSessions); ok {
			resetSessions = provider
		}
		if provider, ok := opt.(ManagementGuardHealth); ok {
			guardHealth = provider
		}
		if provider, ok := opt.(ManagementListenerFaults); ok {
			listenerFaults = provider
		}
	}
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	r.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		if c.Request != nil && c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000")
		}
		c.Next()
	})
	// Avoid trusting all proxies by default; this prevents spoofed ClientIP via X-Forwarded-For.
	// Override via CONTAIND_TRUSTED_PROXIES="127.0.0.1,::1" (comma-separated CIDRs/IPs).
	proxiesEnv := strings.TrimSpace(os.Getenv("CONTAIND_TRUSTED_PROXIES"))
	proxies := []string{"127.0.0.1", "::1"}
	if proxiesEnv != "" {
		parts := strings.Split(proxiesEnv, ",")
		var cleaned []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				cleaned = append(cleaned, p)
			}
		}
		if len(cleaned) > 0 {
			proxies = cleaned
		}
	}
	_ = r.SetTrustedProxies(proxies)
	if auditStore != nil {
		r.Use(withAuditStore(auditStore))
	}

	api := r.Group("/api/v1")
	api.Use(limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit))
	// Health is always unauthenticated for liveness.
	api.GET("/health", healthHandler(store, engine))
	// Prometheus metrics endpoint (unauthenticated for scraping).
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
	// Login is always unauthenticated (unless JWT not configured).
	api.POST("/auth/login", rateLimitSensitive(), loginHandler(userStore))
	api.POST("/auth/login/mfa", rateLimitSensitive(), loginMFAHandler(userStore))
	// Logout is intentionally unauthenticated so clients can always clear cookies
	// even if their session expired or local token state is gone.
	api.POST("/auth/logout", logoutHandler(userStore))
	// All other endpoints require auth (unless lab mode).
	protected := api.Group("")
	protected.Use(enforceSameOriginOnCookieAuth(allowedOriginsFromEnv()))
	protected.Use(authMiddleware(userStore))
	{
		protected.GET("/auth/me", meHandler(userStore))
		protected.GET("/auth/session", authSessionHandler(userStore))
		protected.PATCH("/auth/me", updateMeHandler(userStore))
		protected.POST("/auth/me/password", rateLimitSensitive(), changeMyPasswordHandler(userStore))
		protected.POST("/auth/me/mfa/enroll", rateLimitSensitive(), enrollMyMFAHandler(userStore))
		protected.POST("/auth/me/mfa/enable", rateLimitSensitive(), enableMyMFAHandler(userStore))
		protected.POST("/auth/me/mfa/disable", rateLimitSensitive(), disableMyMFAHandler(userStore))
		protected.GET("/dashboard", dashboardHandler(store, engine, services, userStore, auditStore))
		protected.GET("/system/management-reservation", managementReservationHandler(store, guardHealth, engine, listenerFaults))
		protected.GET("/system/stats", systemStatsHandler())
		protected.GET("/system/inspection", systemInspectionHandler())
		protected.GET("/system/tls", getTLSHandler(store))
		protected.POST("/system/tls/cert", requireAdmin(), setTLSCertHandler(store))
		protected.POST("/system/tls/trusted-ca", requireAdmin(), setTrustedCAHandler(store, engine))
		protected.POST("/system/factory-reset", requireAdmin(), rateLimitSensitive(), factoryResetHandler(store, userStore, engine, services, resetSessions))
		protected.GET("/config", getConfigHandler(store))
		protected.POST("/config", requireAdmin(), saveConfigHandler(store))
		protected.POST("/config/validate", requireAdmin(), validateConfigHandler(store))
		protected.GET("/config/export", exportConfigHandler(store))
		protected.POST("/config/import", requireAdmin(), rateLimitSensitive(), importConfigHandler(store))
		protected.GET("/config/candidate", getCandidateConfigHandler(store))
		protected.POST("/config/candidate", requireAdmin(), saveCandidateConfigHandler(store))
		protected.GET("/config/diff", diffConfigHandler(store))
		protected.GET("/config/backups", listConfigBackupsHandler(store))
		protected.POST("/config/backups", requireAdmin(), createConfigBackupHandler(store))
		protected.GET("/config/backups/:id", downloadConfigBackupHandler(store))
		protected.DELETE("/config/backups/:id", requireAdmin(), deleteConfigBackupHandler())
		protected.POST("/config/commit", requireAdmin(), commitConfigHandler(store, engine, services))
		protected.POST("/config/commit_confirmed", requireAdmin(), commitConfirmedHandler(store, engine, services))
		protected.POST("/config/confirm", requireAdmin(), confirmCommitHandler(store))
		protected.POST("/config/rollback", requireAdmin(), rollbackConfigHandler(store, engine, services))
		protected.GET("/services/syslog", getSyslogHandler(store))
		protected.POST("/services/syslog", requireAdmin(), setSyslogHandler(store))
		protected.PATCH("/services/syslog", requireAdmin(), patchSyslogHandler(store))
		protected.GET("/services/dns", getDNSHandler(store))
		protected.POST("/services/dns", requireAdmin(), setDNSHandler(store, services))
		protected.GET("/services/ntp", getNTPHandler(store))
		protected.POST("/services/ntp", requireAdmin(), setNTPHandler(store))
		protected.GET("/services/dhcp", getDHCPHandler(store))
		protected.POST("/services/dhcp", requireAdmin(), setDHCPHandler(store))
		protected.GET("/services/vpn", getVPNHandler(store))
		protected.POST("/services/vpn", requireAdmin(), setVPNHandler(store))
		protected.POST("/services/vpn/openvpn/profile", requireAdmin(), uploadOpenVPNProfileHandler(store))
		protected.GET("/services/vpn/openvpn/clients", requireAdmin(), listOpenVPNClientsHandler(store))
		protected.POST("/services/vpn/openvpn/clients", requireAdmin(), createOpenVPNClientHandler(store))
		protected.GET("/services/vpn/openvpn/clients/:name", requireAdmin(), downloadOpenVPNClientHandler(store))
		protected.GET("/services/vpn/wireguard/status", getWireGuardStatusHandler(engine))
		protected.GET("/services/av", getAVHandler(store))
		protected.POST("/services/av", requireAdmin(), setAVHandler(store, services))
		protected.POST("/services/av/update", requireAdmin(), triggerAVUpdateHandler(engine))
		protected.GET("/services/av/defs", listAVDefsHandler(engine))
		protected.POST("/services/av/defs", requireAdmin(), uploadAVDefHandler(engine))
		protected.DELETE("/services/av/defs", requireAdmin(), deleteAVDefHandler(engine))
		protected.GET("/services/proxy/forward", getForwardProxyHandler(store))
		protected.POST("/services/proxy/forward", requireAdmin(), setForwardProxyHandler(store))
		protected.GET("/services/proxy/reverse", getReverseProxyHandler(store))
		protected.POST("/services/proxy/reverse", requireAdmin(), setReverseProxyHandler(store))
		protected.GET("/services/status", getServicesStatusHandler(services, engine))
		protected.GET("/events", listEventsHandler(engine, services))
		protected.GET("/events/:id", eventDetailHandler(engine, services))
		protected.GET("/flows", listFlowsHandler(engine))
		protected.GET("/simulation", simulationStatusHandler(engine))
		protected.POST("/simulation", requireAdmin(), simulationControlHandler(engine))
		protected.GET("/stats/protocols", protoStatsHandler(engine))
		protected.GET("/stats/top-talkers", topTalkersHandler(engine))
		protected.GET("/anomalies", listAnomaliesHandler(engine))
		protected.DELETE("/anomalies", requireAdmin(), clearAnomaliesHandler(engine))
		protected.GET("/conntrack", listConntrackHandler(engine))
		protected.GET("/firewall/counters", ruleCountersHandler(engine))
		protected.POST("/conntrack/kill", requireAdmin(), killConntrackHandler(engine))
		protected.GET("/dhcp/leases", dhcpLeasesHandler(engine))
		protected.GET("/dataplane", getDataPlaneHandler(store))
		protected.POST("/dataplane", requireAdmin(), setDataPlaneHandler(store))
		protected.GET("/dataplane/ruleset", requireAdmin(), getRulesetPreviewHandler(store, engine))
		protected.GET("/dataplane/ics-coverage", getICSCoverageHandler(store, engine))
		protected.POST("/dataplane/blocks/host", requireAdmin(), blockHostHandler(engine))
		protected.POST("/dataplane/blocks/flow", requireAdmin(), blockFlowHandler(engine))
		protected.GET("/pcap/config", getPCAPConfigHandler(store))
		protected.POST("/pcap/config", requireAdmin(), setPCAPConfigHandler(store))
		protected.POST("/pcap/start", requireAdmin(), startPCAPHandler(store, engine))
		protected.POST("/pcap/stop", requireAdmin(), stopPCAPHandler(engine))
		protected.GET("/pcap/status", getPCAPStatusHandler(engine))
		protected.GET("/pcap/list", getPCAPListHandler(engine))
		protected.POST("/pcap/upload", requireAdmin(), uploadPCAPHandler(engine))
		protected.GET("/pcap/download/:name", downloadPCAPHandler(engine))
		protected.DELETE("/pcap/:name", requireAdmin(), deletePCAPHandler(engine))
		protected.POST("/pcap/tag", requireAdmin(), tagPCAPHandler(engine))
		protected.POST("/pcap/replay", requireAdmin(), replayPCAPHandler(engine))
		protected.POST("/pcap/analyze", requireAdmin(), analyzePCAPUploadHandler(engine))
		protected.POST("/pcap/analyze/:name", requireAdmin(), analyzePCAPNameHandler(engine))
		protected.GET("/diagnostics/iec104", iec104DiagnosticsHandler(engine))
		protected.GET("/inventory", listInventoryHandler(engine))
		protected.GET("/inventory/iec104", iec104InventoryHandler(engine))
		protected.GET("/inventory/:ip", getInventoryAssetHandler(engine))
		protected.DELETE("/inventory", requireAdmin(), clearInventoryHandler(engine))
		protected.GET("/signatures", listSignaturesHandler(engine))
		protected.POST("/signatures", requireAdmin(), addSignatureHandler(engine))
		protected.DELETE("/signatures/:id", requireAdmin(), deleteSignatureHandler(engine))
		protected.GET("/signatures/matches", listSignatureMatchesHandler(engine))
		protected.GET("/assets", listAssetsHandler(store))
		protected.POST("/assets", requireAdmin(), createAssetHandler(store))
		protected.PATCH("/assets/:id", requireAdmin(), updateAssetHandler(store))
		protected.DELETE("/assets/:id", requireAdmin(), deleteAssetHandler(store))
		protected.GET("/objects", listObjectsHandler(store))
		protected.POST("/objects", requireAdmin(), createObjectHandler(store))
		protected.PATCH("/objects/:id", requireAdmin(), updateObjectHandler(store))
		protected.DELETE("/objects/:id", requireAdmin(), deleteObjectHandler(store))
		protected.GET("/zones", listZonesHandler(store))
		protected.POST("/zones", requireAdmin(), createZoneHandler(store))
		protected.PATCH("/zones/:name", requireAdmin(), updateZoneHandler(store))
		protected.DELETE("/zones/:name", requireAdmin(), deleteZoneHandler(store))
		protected.GET("/interfaces", listInterfacesHandler(store))
		protected.GET("/interfaces/state", interfaceStateHandler(engine))
		protected.POST("/interfaces/assign", requireAdmin(), interfacesAssignHandler(store, engine))
		protected.POST("/interfaces/reconcile", requireAdmin(), interfacesReconcileHandler(store, engine))
		protected.POST("/interfaces", requireAdmin(), createInterfaceHandler(store))
		protected.PATCH("/interfaces/:name", requireAdmin(), updateInterfaceHandler(store))
		protected.DELETE("/interfaces/:name", requireAdmin(), deleteInterfaceHandler(store))
		protected.GET("/routing", getRoutingHandler(store))
		protected.GET("/routing/os", getOSRoutingHandler())
		protected.POST("/routing", requireAdmin(), setRoutingHandler(store))
		protected.POST("/routing/reconcile", requireAdmin(), routingReconcileHandler(store, engine))
		protected.GET("/firewall/nat", getFirewallNATHandler(store))
		protected.POST("/firewall/nat", requireAdmin(), setFirewallNATHandler(store))
		protected.GET("/firewall/rules", listFirewallRulesHandler(store))
		protected.POST("/firewall/rules", requireAdmin(), createFirewallRuleHandler(store))
		protected.PATCH("/firewall/rules/:id", requireAdmin(), updateFirewallRuleHandler(store))
		protected.DELETE("/firewall/rules/:id", requireAdmin(), deleteFirewallRuleHandler(store))
		protected.POST("/firewall/rules/preview", requireAdmin(), previewFirewallRuleHandler(engine))
		protected.GET("/firewall/ics-rules", listICSRulesHandler(store))
		protected.POST("/firewall/ics-rules", requireAdmin(), createICSRuleHandler(store))
		protected.PATCH("/firewall/ics-rules/:id", requireAdmin(), updateICSRuleHandler(store))
		// ICS learn mode.
		protected.GET("/learn/profiles", learnProfilesHandler(engine))
		protected.POST("/learn/generate", requireAdmin(), learnGenerateHandler(engine))
		protected.POST("/learn/apply", requireAdmin(), learnApplyHandler(store, engine))
		protected.DELETE("/learn", requireAdmin(), learnClearHandler(engine))
		protected.GET("/security/conduits", securityConduitsHandler(store))
		protected.GET("/ids/rules", getIDSHandler(store))
		protected.POST("/ids/rules", requireAdmin(), setIDSHandler(store))
		protected.POST("/ids/convert/sigma", convertSigmaHandler())
		protected.POST("/ids/import", requireAdmin(), idsImportHandler(store))
		protected.GET("/ids/export", idsExportHandler(store))
		protected.GET("/ids/sources", idsSourcesHandler())
		protected.GET("/ids/backup", idsBackupHandler(store))
		protected.POST("/ids/restore", requireAdmin(), idsRestoreHandler(store))
		protected.POST("/cli/execute", cliExecuteHandler(store))
		protected.GET("/cli/commands", cliCommandsHandler(store))
		protected.GET("/cli/complete", cliCompleteHandler(store))
		protected.GET("/cli/ws", cliWSHandler(store))
		// Users (admin only).
		protected.GET("/users", requireAdmin(), listUsersHandler(userStore))
		protected.POST("/users", requireAdmin(), rateLimitSensitive(), createUserHandler(userStore))
		protected.PATCH("/users/:id", requireAdmin(), rateLimitSensitive(), updateUserHandler(userStore))
		protected.POST("/users/:id/password", requireAdmin(), rateLimitSensitive(), setUserPasswordHandler(userStore))
		protected.POST("/users/:id/mfa/disable", requireAdmin(), rateLimitSensitive(), disableUserMFAHandler(userStore))
		protected.POST("/users/:id/mfa/require", requireAdmin(), rateLimitSensitive(), requireUserMFAHandler(userStore))
		protected.POST("/users/:id/mfa/clear", requireAdmin(), rateLimitSensitive(), clearUserMFARequirementHandler(userStore))
		protected.POST("/users/:id/mfa/grace", requireAdmin(), rateLimitSensitive(), extendUserMFAGraceHandler(userStore))
		protected.DELETE("/users/:id", requireAdmin(), rateLimitSensitive(), deleteUserHandler(userStore))
		if auditStore != nil {
			auditHandlers(protected, auditStore)
		}
		// Policy templates.
		protected.GET("/templates", listTemplatesHandler())
		protected.POST("/templates/apply", requireAdmin(), applyTemplateHandler(store))
		// ICS protocol templates.
		protected.GET("/templates/ics", listICSTemplatesHandler())
		protected.POST("/templates/ics/apply", requireAdmin(), applyICSTemplateHandler(store))
		// Identity bindings (candidate firewall.identityBindings).
		protected.GET("/identities", listIdentitiesHandler(store))
		protected.POST("/identities", requireAdmin(), setIdentityHandler(store))
		protected.DELETE("/identities/:ip", requireAdmin(), deleteIdentityHandler(store))
	}

	return r
}

func getConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		// Always redact secrets from the runtime config read endpoint.
		// Admins who need unredacted secrets should use the export endpoint
		// with ?redacted=false.
		c.JSON(http.StatusOK, configReadCopy(cfg))
	}
}

func saveConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var cfg config.Config
		if err := c.ShouldBindJSON(&cfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		if !replaceCandidate(c, ctx, store, &cfg) {
			return
		}
		auditLog(c, audit.Record{Action: "config.save", Target: "candidate"})
		c.JSON(http.StatusOK, gin.H{"status": "staged"})
	}
}

func validateConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var cfg config.Config
		if err := c.ShouldBindJSON(&cfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		if err := config.ValidateForStore(store, &cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "valid"})
	}
}

func getCandidateConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.LoadCandidate(c.Request.Context())
		if err != nil {
			if errors.Is(err, config.ErrNotFound) {
				apiError(c, http.StatusNotFound, "candidate config not found")
				return
			}
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, configReadCopy(cfg))
	}
}

func saveCandidateConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var cfg config.Config
		if err := c.ShouldBindJSON(&cfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		stage := stageCandidate
		if cfg.IDS.Rules != nil {
			stage = stageCandidateIDS
		}
		if _, ok := stage(c, store, func(existing *config.Config) bool {
			cfg.RestoreRedactedSecrets(existing)
			if cfg.IDS.Rules == nil {
				cfg.IDS.Rules = existing.IDS.Rules
			}
			*existing = cfg
			return true
		}); !ok {
			return
		}
		auditLog(c, audit.Record{Action: "config.save_candidate", Target: "candidate"})
		c.JSON(http.StatusOK, gin.H{"status": "staged"})
	}
}

// ApplyRunningConfig replays the current stored running config through the same
// serialized apply path used by commits and rollback.
func ApplyRunningConfig(ctx context.Context, store config.Store, engine EngineClient, services ServicesApplier) ([]string, error) {
	return applyRunningConfig(ctx, store, engine, services)
}

// runningConfigApplyMu protects replay and running-store mutations coupled to
// runtime applies. Hold it before loading a config to modify, through its apply.
var runningConfigApplyMu sync.Mutex

func applyRunningConfig(ctx context.Context, store config.Store, engine EngineClient, services ServicesApplier) ([]string, error) {
	// Load only after acquiring the lock: a queued replay must not push a
	// snapshot read before a newer commit's apply.
	runningConfigApplyMu.Lock()
	defer runningConfigApplyMu.Unlock()
	return applyRunningConfigLocked(ctx, store, engine, services, nil)
}

// applyRunningConfigLocked is the single apply sequence. Callers must hold
// runningConfigApplyMu, including across any preceding store mutation.
func applyRunningConfigLocked(ctx context.Context, store config.Store, engine EngineClient, services ServicesApplier, previous *config.Config) (warnings []string, applyErr error) {
	defer func() { applyErr = recordRuntimeApplyResult(ctx, store, applyErr) }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := config.CheckManagementBootFault(ctx, store); err != nil {
		return nil, err
	}
	cfg, err := store.Load(ctx)
	if err != nil {
		if errors.Is(err, config.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return applyConfigSnapshot(ctx, store, engine, services, previous, cfg)
}

// applyConfigSnapshot must not load or mutate the store: a transition holds its
// mutex across this callback. Validation uses only immutable boot authority.
func applyConfigSnapshot(ctx context.Context, store config.Store, engine EngineClient, services ServicesApplier, previous, cfg *config.Config) ([]string, error) {
	// Bind unbound default logical interfaces to discovered kernel devices
	// before applying them. Explicit bindings are applied exactly as staged
	// and validated. Keep this change in memory only: applying a previously
	// loaded snapshot must never persist it over a newer store mutation.
	// Bootstrap owns persisted default device bindings.
	if err := config.ValidateForStore(store, cfg); err != nil {
		return nil, err
	}
	// Reserved bindings were persisted by bootstrap. Never normalize them during
	// replay: preflight must precede every runtime side effect.
	if config.ReservationForStore(store) == nil {
		bindUnboundDefaultInterfaceDevices(cfg)
	}
	if err := config.ValidateForStore(store, cfg); err != nil {
		return nil, err
	}
	if services != nil {
		if err := services.Apply(ctx, cfg.Services); err != nil {
			return nil, err
		}
	}
	var warnings []string
	if engine == nil {
		return nil, errors.New("engine unavailable")
	}
	// Auxiliary infrastructure remains best-effort. Dataplane configuration
	// and ruleset application are mandatory: they control enforcement.
	if err := engine.ConfigureInterfaces(ctx, cfg.Interfaces); err != nil {
		warnings = append(warnings, fmt.Sprintf("interfaces: %v", err))
	}
	if warning := ipv4ForwardingCommitWarning(ctx, cfg, engine); warning != "" {
		warnings = append(warnings, warning)
	}
	if err := engine.ConfigureRouting(ctx, cfg.Routing); err != nil {
		warnings = append(warnings, fmt.Sprintf("routing: %v", err))
	}
	// Trust precedes services so AV clients verify with the current bundle.
	if err := pushTrustedCA(ctx, cfg, engine); err != nil {
		warnings = append(warnings, fmt.Sprintf("trust: %v", err))
	}
	if err := engine.ConfigureServices(ctx, cfg.Services); err != nil {
		warnings = append(warnings, fmt.Sprintf("services: %v", err))
	}
	if err := engine.Configure(ctx, cfg.DataPlane); err != nil {
		return nil, fmt.Errorf("dataplane: %w", err)
	}
	// Replay config on boot/reconnect, but preserve operational captures
	// across promotions that do not change saved capture settings.
	if previous == nil || !reflect.DeepEqual(previous.PCAP, cfg.PCAP) {
		if _, err := engine.SetPcapConfig(ctx, cfg.PCAP); err != nil {
			warnings = append(warnings, fmt.Sprintf("pcap config: %v", err))
		}
		if cfg.PCAP.Enabled {
			if _, err := engine.StartPcap(ctx, cfg.PCAP); err != nil && !strings.Contains(err.Error(), "already running") {
				warnings = append(warnings, fmt.Sprintf("pcap start: %v", err))
			}
		} else {
			if _, err := engine.StopPcap(ctx); err != nil {
				warnings = append(warnings, fmt.Sprintf("pcap stop: %v", err))
			}
		}
	}
	// Always compile and push rules regardless of infrastructure errors.
	snap, err := compile.CompileSnapshot(cfg)
	if err != nil {
		return nil, err
	}
	if err := engine.ApplyRules(ctx, snap); err != nil {
		return nil, fmt.Errorf("ruleset: %w", err)
	}
	return warnings, nil
}

// loadOrInitConfig only supplies an in-memory default for an uninitialized
// store. Bootstrap owns persistence; reads must never modify running/candidate.
func loadOrInitConfig(ctx context.Context, store config.Store) (*config.Config, error) {
	cfg, err := store.Load(ctx)
	if errors.Is(err, config.ErrNotFound) {
		return config.DefaultConfig(), nil
	}
	return cfg, err
}

func withAuditStore(store audit.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if store != nil {
			c.Set("auditStore", store)
			if actor := c.GetHeader("X-User"); actor != "" {
				c.Set("actor", actor)
			}
			if source := c.GetHeader("X-Source"); source != "" {
				c.Set("source", source)
			}
		}
		c.Next()
	}
}

func auditLog(c *gin.Context, rec audit.Record) {
	if c == nil {
		return
	}
	storeVal, ok := c.Get("auditStore")
	if !ok || storeVal == nil {
		return
	}
	store, ok := storeVal.(audit.Store)
	if !ok || store == nil {
		return
	}
	if rec.Actor == "" {
		if actor := c.GetString("actor"); actor != "" {
			rec.Actor = actor
		} else if actor := c.GetHeader("X-User"); actor != "" {
			rec.Actor = actor
		} else {
			rec.Actor = "unknown"
		}
	}
	if rec.Source == "" {
		if src := c.GetString("source"); src != "" {
			rec.Source = src
		} else if src := c.GetHeader("X-Source"); src != "" {
			rec.Source = src
		} else {
			rec.Source = "api"
		}
	}
	if rec.Result == "" {
		rec.Result = "success"
	}
	_ = store.Add(c.Request.Context(), rec)
}
