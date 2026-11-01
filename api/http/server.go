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
	// ConfigureServices applies the services configuration and returns the
	// warnings the engine applied it with.
	ConfigureServices(ctx context.Context, services config.ServicesConfig) ([]string, error)
	ListInterfaceState(ctx context.Context) ([]config.InterfaceState, error)
	ApplyRules(ctx context.Context, snap rules.Snapshot) (dpengine.ProtectionStatus, error)
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
	PreviewRule(ctx context.Context, request dpengine.PreviewRuleRequest) (dpengine.PreviewRuleResponse, error)
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
	GetInventoryAssets(ctx context.Context, ip string) ([]inventory.DiscoveredAsset, error)
	ClearInventory(ctx context.Context) error
}

// AnomalyClient is an optional interface for protocol anomaly detection.
type AnomalyClient interface {
	ListAnomalies(ctx context.Context, limit int) ([]anomaly.Anomaly, error)
	ClearAnomalies(ctx context.Context) error
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
	r.Use(accessLogger(), revisionResponseHeaders(), gin.Recovery())
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
		r.Use(withAuditStore(auditStore), deliverScopeMigrations(store, auditStore))
	}

	api := r.Group("/api/v1")
	// Health is always unauthenticated for liveness.
	api.GET("/health", healthHandler(store, engine, auditStore, services))
	// Prometheus metrics endpoint (unauthenticated for scraping).
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
	// Login is always unauthenticated (unless JWT not configured).
	api.POST("/auth/login", rateLimitSensitive(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), loginHandler(userStore))
	api.POST("/auth/login/mfa", rateLimitSensitive(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), loginMFAHandler(userStore))
	// Logout is intentionally unauthenticated so clients can always clear cookies
	// even if their session expired or local token state is gone.
	api.POST("/auth/logout", limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), logoutHandler(userStore))
	// WebSockets always require a one-use ticket, including cookie clients.
	// Reauthenticate its issuer before upgrade, not the browser's ambient user.
	tickets := newCLITickets()
	api.GET("/cli/ws", tickets.redeem(), authMiddleware(userStore), verifyCLITicketIdentity, cliWSHandler(store))
	// All other endpoints require auth (unless lab mode).
	protected := api.Group("")
	protected.Use(enforceSameOriginOnCookieAuth(allowedOriginsFromEnv()))
	protected.Use(authMiddleware(userStore))
	{
		protected.GET("/auth/me", meHandler(userStore))
		protected.GET("/auth/session", authSessionHandler(userStore))
		protected.PATCH("/auth/me", limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), updateMeHandler(userStore))
		protected.POST("/auth/me/password", rateLimitSensitive(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), changeMyPasswordHandler(userStore))
		protected.POST("/auth/me/mfa/enroll", rateLimitSensitive(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), enrollMyMFAHandler(userStore))
		protected.POST("/auth/me/mfa/enable", rateLimitSensitive(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), enableMyMFAHandler(userStore))
		protected.POST("/auth/me/mfa/disable", rateLimitSensitive(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), disableMyMFAHandler(userStore))
		protected.GET("/evidence/status", evidenceStatusHandler(auditStore, services))
		protected.GET("/dashboard", dashboardHandler(store, engine, services, userStore, auditStore))
		protected.GET("/system/management-reservation", managementReservationHandler(store, guardHealth, engine, listenerFaults))
		protected.GET("/system/stats", systemStatsHandler())
		protected.GET("/system/inspection", systemInspectionHandler())
		protected.GET("/system/tls", getTLSHandler(store))
		protected.POST("/system/tls/cert", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), setTLSCertHandler(store))
		protected.POST("/system/tls/trusted-ca", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), setTrustedCAHandler(store, engine))
		protected.POST("/system/factory-reset", requireAdmin(), rateLimitSensitive(), requireConfigRevision(), factoryResetHandler(store, userStore, engine, services, resetSessions))
		protected.GET("/config", getConfigHandler(store))
		protected.POST("/config", requireAdmin(), requireConfigRevision(), saveConfigHandler(store))
		protected.POST("/config/validate", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), validateConfigHandler(store))
		protected.GET("/config/export", exportConfigHandler(store))
		protected.POST("/config/import", requireAdmin(), rateLimitSensitive(), requireConfigRevision(), importConfigHandler(store))
		protected.GET("/config/candidate", getCandidateConfigHandler(store))
		protected.POST("/config/candidate", requireAdmin(), requireConfigRevision(), saveCandidateConfigHandler(store))
		protected.GET("/config/diff", diffConfigHandler(store))
		protected.GET("/config/backups", listConfigBackupsHandler(store))
		protected.POST("/config/backups", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), createConfigBackupHandler(store))
		protected.GET("/config/backups/:id", downloadConfigBackupHandler(store))
		protected.DELETE("/config/backups/:id", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), deleteConfigBackupHandler())
		protected.POST("/config/commit", requireAdmin(), requireConfigRevision(), commitConfigHandler(store, engine, services))
		protected.POST("/config/commit_confirmed", requireAdmin(), requireConfigRevision(), commitConfirmedHandler(store, engine, services))
		protected.POST("/config/confirm", requireAdmin(), requireConfigRevision(), confirmCommitHandler(store))
		protected.POST("/config/rollback", requireAdmin(), requireConfigRevision(), rollbackConfigHandler(store, engine, services))
		protected.GET("/services/syslog", getSyslogHandler(store))
		protected.POST("/services/syslog", requireAdmin(), requireConfigRevision(), setSyslogHandler(store))
		protected.PATCH("/services/syslog", requireAdmin(), requireConfigRevision(), patchSyslogHandler(store))
		protected.GET("/services/dns", getDNSHandler(store))
		protected.POST("/services/dns", requireAdmin(), requireConfigRevision(), setDNSHandler(store, services))
		protected.GET("/services/ntp", getNTPHandler(store))
		protected.POST("/services/ntp", requireAdmin(), requireConfigRevision(), setNTPHandler(store))
		protected.GET("/services/dhcp", getDHCPHandler(store))
		protected.POST("/services/dhcp", requireAdmin(), requireConfigRevision(), setDHCPHandler(store))
		protected.GET("/services/vpn", getVPNHandler(store))
		protected.POST("/services/vpn", requireAdmin(), requireConfigRevision(), setVPNHandler(store))
		protected.POST("/services/vpn/openvpn/profile", requireAdmin(), requireConfigRevision(), uploadOpenVPNProfileHandler(store))
		protected.GET("/services/vpn/openvpn/clients", requireAdmin(), listOpenVPNClientsHandler(store))
		protected.POST("/services/vpn/openvpn/clients", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), createOpenVPNClientHandler(store))
		protected.GET("/services/vpn/openvpn/clients/:name", requireAdmin(), downloadOpenVPNClientHandler(store))
		protected.GET("/services/vpn/wireguard/status", getWireGuardStatusHandler(engine))
		protected.GET("/services/av", getAVHandler(store))
		protected.POST("/services/av", requireAdmin(), requireConfigRevision(), setAVHandler(store, services))
		protected.POST("/services/av/update", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), triggerAVUpdateHandler(engine))
		protected.GET("/services/av/defs", listAVDefsHandler(engine))
		protected.POST("/services/av/defs", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), uploadAVDefHandler(engine))
		protected.DELETE("/services/av/defs", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), deleteAVDefHandler(engine))
		protected.GET("/services/proxy/forward", getForwardProxyHandler(store))
		protected.POST("/services/proxy/forward", requireAdmin(), requireConfigRevision(), setForwardProxyHandler(store))
		protected.GET("/services/proxy/reverse", getReverseProxyHandler(store))
		protected.POST("/services/proxy/reverse", requireAdmin(), requireConfigRevision(), setReverseProxyHandler(store))
		protected.GET("/services/status", getServicesStatusHandler(services, engine))
		protected.GET("/events", listEventsHandler(engine, services, store))
		protected.GET("/events/:id", eventDetailHandler(engine, services, store))
		protected.GET("/flows", listFlowsHandler(engine))
		protected.GET("/simulation", simulationStatusHandler(engine))
		protected.POST("/simulation", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), simulationControlHandler(engine))
		protected.GET("/stats/protocols", protoStatsHandler(engine))
		protected.GET("/stats/top-talkers", topTalkersHandler(engine))
		protected.GET("/anomalies", listAnomaliesHandler(engine))
		protected.DELETE("/anomalies", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), clearAnomaliesHandler(engine))
		protected.GET("/conntrack", listConntrackHandler(engine))
		protected.GET("/firewall/counters", ruleCountersHandler(engine))
		protected.GET("/firewall/shadow-counters", shadowCountersHandler(engine))
		protected.POST("/conntrack/kill", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), killConntrackHandler(engine))
		protected.GET("/dhcp/leases", dhcpLeasesHandler(engine))
		protected.GET("/dataplane", getDataPlaneHandler(store))
		protected.POST("/dataplane", requireAdmin(), requireConfigRevision(), setDataPlaneHandler(store))
		protected.GET("/dataplane/ruleset", requireAdmin(), getRulesetPreviewHandler(store, engine))
		protected.GET("/dataplane/ruleset/status", getInstalledRulesetStatusHandler(engine))
		protected.GET("/dataplane/protection", getProtectionHandler(engine))
		protected.POST("/dataplane/protection/retry", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), retryProtectionHandler(engine))
		protected.GET("/dataplane/ics-coverage", getICSCoverageHandler(store, engine))
		protected.POST("/dataplane/blocks/host", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), blockHostHandler(engine))
		protected.POST("/dataplane/blocks/flow", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), blockFlowHandler(engine))
		protected.GET("/pcap/config", getPCAPConfigHandler(store))
		protected.POST("/pcap/config", requireAdmin(), requireConfigRevision(), setPCAPConfigHandler(store))
		protected.POST("/pcap/start", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), startPCAPHandler(store, engine))
		protected.POST("/pcap/stop", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), stopPCAPHandler(engine))
		protected.GET("/pcap/status", getPCAPStatusHandler(engine))
		protected.GET("/pcap/list", getPCAPListHandler(engine))
		protected.POST("/pcap/upload", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), uploadPCAPHandler(engine))
		protected.GET("/pcap/download/:name", downloadPCAPHandler(engine))
		protected.DELETE("/pcap/:name", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), deletePCAPHandler(engine))
		protected.POST("/pcap/tag", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), tagPCAPHandler(engine))
		protected.POST("/pcap/replay", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), replayPCAPHandler(engine))
		protected.POST("/pcap/analyze", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), analyzePCAPUploadHandler(engine))
		protected.POST("/pcap/analyze/:name", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), analyzePCAPNameHandler(engine))
		protected.GET("/diagnostics/iec104", iec104DiagnosticsHandler(engine))
		protected.GET("/inventory", listInventoryHandler(engine))
		protected.GET("/inventory/iec104", iec104InventoryHandler(engine))
		protected.GET("/inventory/:ip", getInventoryAssetsHandler(engine))
		protected.DELETE("/inventory", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), clearInventoryHandler(engine))
		protected.GET("/signatures", listSignaturesHandler(engine))
		protected.POST("/signatures", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), addSignatureHandler(engine))
		protected.DELETE("/signatures/:id", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), deleteSignatureHandler(engine))
		protected.GET("/signatures/matches", listSignatureMatchesHandler(engine))
		protected.GET("/assets", listAssetsHandler(store))
		protected.POST("/assets", requireAdmin(), requireConfigRevision(), createAssetHandler(store))
		protected.PATCH("/assets/:id", requireAdmin(), requireConfigRevision(), updateAssetHandler(store))
		protected.DELETE("/assets/:id", requireAdmin(), requireConfigRevision(), deleteAssetHandler(store))
		protected.GET("/objects", listObjectsHandler(store))
		protected.POST("/objects", requireAdmin(), requireConfigRevision(), createObjectHandler(store))
		protected.PATCH("/objects/:id", requireAdmin(), requireConfigRevision(), updateObjectHandler(store))
		protected.DELETE("/objects/:id", requireAdmin(), requireConfigRevision(), deleteObjectHandler(store))
		protected.GET("/zones", listZonesHandler(store))
		protected.POST("/zones", requireAdmin(), requireConfigRevision(), createZoneHandler(store))
		protected.PATCH("/zones/:name", requireAdmin(), requireConfigRevision(), updateZoneHandler(store))
		protected.DELETE("/zones/:name", requireAdmin(), requireConfigRevision(), deleteZoneHandler(store))
		protected.GET("/interfaces", listInterfacesHandler(store))
		protected.GET("/interfaces/state", interfaceStateHandler(engine))
		protected.POST("/interfaces/assign", requireAdmin(), requireConfigRevision(), interfacesAssignHandler(store, engine))
		protected.POST("/interfaces/reconcile", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), interfacesReconcileHandler(store, engine))
		protected.POST("/interfaces", requireAdmin(), requireConfigRevision(), createInterfaceHandler(store))
		protected.PATCH("/interfaces/:name", requireAdmin(), requireConfigRevision(), updateInterfaceHandler(store))
		protected.DELETE("/interfaces/:name", requireAdmin(), requireConfigRevision(), deleteInterfaceHandler(store))
		protected.GET("/routing", getRoutingHandler(store))
		protected.GET("/routing/os", getOSRoutingHandler())
		protected.POST("/routing", requireAdmin(), requireConfigRevision(), setRoutingHandler(store))
		protected.POST("/routing/reconcile", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), routingReconcileHandler(store, engine))
		protected.GET("/firewall/nat", getFirewallNATHandler(store))
		protected.POST("/firewall/nat", requireAdmin(), requireConfigRevision(), setFirewallNATHandler(store))
		protected.POST("/firewall/port-forwards", requireAdmin(), requireConfigRevision(), publishPortForwardHandler(store))
		protected.DELETE("/firewall/port-forwards/:id", requireAdmin(), requireConfigRevision(), deletePortForwardHandler(store))
		protected.POST("/firewall/rules/:id/move", requireAdmin(), requireConfigRevision(), moveFirewallRuleHandler(store))
		protected.GET("/firewall/rules", listFirewallRulesHandler(store))
		protected.POST("/firewall/rules", requireAdmin(), requireConfigRevision(), createFirewallRuleHandler(store))
		protected.PATCH("/firewall/rules/:id", requireAdmin(), requireConfigRevision(), updateFirewallRuleHandler(store))
		protected.DELETE("/firewall/rules/:id", requireAdmin(), requireConfigRevision(), deleteFirewallRuleHandler(store))
		protected.POST("/firewall/rules/preview", requireAdmin(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), previewFirewallRuleHandler(store, engine))
		protected.GET("/firewall/ics-rules", listICSRulesHandler(store))
		protected.POST("/firewall/ics-rules", requireAdmin(), requireConfigRevision(), createICSRuleHandler(store))
		protected.PATCH("/firewall/ics-rules/:id", requireAdmin(), requireConfigRevision(), updateICSRuleHandler(store))
		registerEvidenceRoutes(protected, store, engine)
		protected.GET("/security/conduits", securityConduitsHandler(store))
		protected.GET("/ids/rules", getIDSHandler(store))
		protected.POST("/ids/rules", requireAdmin(), requireConfigRevision(), setIDSHandler(store))
		protected.POST("/ids/convert/sigma", limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), convertSigmaHandler())
		protected.POST("/ids/import", requireAdmin(), requireConfigRevision(), idsImportHandler(store))
		protected.GET("/ids/export", idsExportHandler(store))
		protected.GET("/ids/sources", idsSourcesHandler())
		protected.GET("/ids/backup", idsBackupHandler(store))
		protected.POST("/ids/restore", requireAdmin(), requireConfigRevision(), idsRestoreHandler(store))
		protected.POST("/cli/execute", limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), cliExecuteHandler(store))
		protected.GET("/cli/commands", cliCommandsHandler(store))
		protected.GET("/cli/complete", cliCompleteHandler(store))
		protected.POST("/cli/ws/ticket", limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), tickets.issue())
		// Users (admin only).
		protected.GET("/users", requireAdmin(), listUsersHandler(userStore))
		protected.POST("/users", requireAdmin(), rateLimitSensitive(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), createUserHandler(userStore))
		protected.PATCH("/users/:id", requireAdmin(), rateLimitSensitive(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), updateUserHandler(userStore))
		protected.POST("/users/:id/password", requireAdmin(), rateLimitSensitive(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), setUserPasswordHandler(userStore))
		protected.POST("/users/:id/mfa/disable", requireAdmin(), rateLimitSensitive(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), disableUserMFAHandler(userStore))
		protected.POST("/users/:id/mfa/require", requireAdmin(), rateLimitSensitive(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), requireUserMFAHandler(userStore))
		protected.POST("/users/:id/mfa/clear", requireAdmin(), rateLimitSensitive(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), clearUserMFARequirementHandler(userStore))
		protected.POST("/users/:id/mfa/grace", requireAdmin(), rateLimitSensitive(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), extendUserMFAGraceHandler(userStore))
		protected.DELETE("/users/:id", requireAdmin(), rateLimitSensitive(), limitRequestBody(defaultJSONBodyLimit, defaultMultipartBodyLimit), deleteUserHandler(userStore))
		if auditStore != nil {
			auditHandlers(protected, auditStore)
		}
		// Policy templates.
		protected.GET("/templates", listTemplatesHandler())
		protected.POST("/templates/apply", requireAdmin(), requireConfigRevision(), applyTemplateHandler(store))
		// ICS protocol templates.
		protected.GET("/templates/ics", listICSTemplatesHandler())
		protected.POST("/templates/ics/apply", requireAdmin(), requireICSTemplateRevision(), applyICSTemplateHandler(store))
		// Identity bindings (candidate firewall.identityBindings).
		protected.GET("/identities", listIdentitiesHandler(store))
		protected.POST("/identities", requireAdmin(), requireConfigRevision(), setIdentityHandler(store))
		protected.DELETE("/identities/:ip", requireAdmin(), requireConfigRevision(), deleteIdentityHandler(store))
	}

	return r
}

func getConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := readRunningOrDefault(c, store)
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
		cfg, err := readCandidate(c, store)
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
	warnings, _, err = applyConfigSnapshot(ctx, store, engine, services, previous, cfg)
	return warnings, err
}

// applyConfigSnapshot must not load or mutate the store: a transition holds its
// mutex across this callback. Validation uses only immutable boot authority.
func applyConfigSnapshot(ctx context.Context, store config.Store, engine EngineClient, services ServicesApplier, previous, cfg *config.Config) ([]string, dpengine.ProtectionStatus, error) {
	ctx = engineclient.NewApplyContext(ctx)
	// Bind unbound default logical interfaces to discovered kernel devices
	// before applying them. Explicit bindings are applied exactly as staged
	// and validated. Keep this change in memory only: applying a previously
	// loaded snapshot must never persist it over a newer store mutation.
	// Bootstrap owns persisted default device bindings.
	if err := config.ValidateForStore(store, cfg); err != nil {
		return nil, dpengine.ProtectionStatus{}, err
	}
	// Reserved bindings were persisted by bootstrap. Never normalize them during
	// replay: preflight must precede every runtime side effect.
	if config.ReservationForStore(store) == nil {
		bindUnboundDefaultInterfaceDevices(cfg)
	}
	if err := config.ValidateForStore(store, cfg); err != nil {
		return nil, dpengine.ProtectionStatus{}, err
	}
	scanWarnings, err := config.ValidateScanSelection(cfg)
	if err != nil {
		return nil, dpengine.ProtectionStatus{}, err
	}
	if services != nil {
		if err := services.Apply(ctx, cfg.Services); err != nil {
			return nil, dpengine.ProtectionStatus{}, err
		}
	}
	warnings := scanWarnings
	if engine == nil {
		return nil, dpengine.ProtectionStatus{}, errors.New("engine unavailable")
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
	serviceWarnings, err := engine.ConfigureServices(ctx, cfg.Services)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("services: %v", err))
	}
	for _, warning := range serviceWarnings {
		warnings = append(warnings, "services: "+warning)
	}
	if err := engine.Configure(ctx, cfg.DataPlane); err != nil {
		return nil, dpengine.ProtectionStatus{}, fmt.Errorf("dataplane: %w", err)
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
		return nil, dpengine.ProtectionStatus{}, err
	}
	observation, err := engine.ApplyRules(ctx, snap)
	if err != nil {
		return nil, dpengine.ProtectionStatus{}, fmt.Errorf("ruleset: %w", err)
	}
	return warnings, engineclient.NormalizeProtection(observation, engineclient.ApplyID(ctx)), nil
}
