// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/kballard/go-shellquote"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	engineclient "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cli"
	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/identity"
	cpids "github.com/tonylturner/containd/pkg/cp/ids"
	cpservices "github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/cp/templates"
	"github.com/tonylturner/containd/pkg/cp/users"
	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/dhcpd"
	"github.com/tonylturner/containd/pkg/dp/enforce"
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
}

type TelemetryClient interface {
	ListEvents(ctx context.Context, limit int) ([]dpevents.Event, error)
	ListFlows(ctx context.Context, limit int) ([]dpevents.FlowSummary, error)
}

type ConntrackClient interface {
	ListConntrack(ctx context.Context, limit int) ([]conntrack.Entry, error)
}

type ConntrackKiller interface {
	DeleteConntrack(ctx context.Context, req conntrack.DeleteRequest) error
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

type AVUpdater interface {
	TriggerAVUpdate(ctx context.Context) error
}

type AVDefsManager interface {
	CustomDefsPath() string
}

// NewServerWithEngine builds a Gin engine and optionally wires engine commit hooks.
func NewServerWithEngine(store config.Store, auditStore audit.Store, engine EngineClient) *gin.Engine {
	return NewServerWithEngineAndServices(store, auditStore, engine, nil, nil)
}

// NewServerWithEngineAndServices builds a Gin engine and optionally wires engine, services, and users stores.
// opts may contain an *identity.Resolver as the first element; if absent identity endpoints are not registered.
func NewServerWithEngineAndServices(store config.Store, auditStore audit.Store, engine EngineClient, services ServicesApplier, userStore users.Store, opts ...any) *gin.Engine {
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
	// Health is always unauthenticated for liveness.
	api.GET("/health", healthHandler)
	// Prometheus metrics endpoint (unauthenticated for scraping).
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
	// Login is always unauthenticated (unless JWT not configured).
	api.POST("/auth/login", rateLimitSensitive(), loginHandler(userStore))
	// Logout is intentionally unauthenticated so clients can always clear cookies
	// even if their session expired or local token state is gone.
	api.POST("/auth/logout", logoutHandler(userStore))
	// All other endpoints require auth (unless lab mode).
	protected := api.Group("")
	protected.Use(authMiddleware(userStore))
	{
		protected.GET("/auth/me", meHandler(userStore))
		protected.GET("/auth/session", authSessionHandler(userStore))
		protected.PATCH("/auth/me", updateMeHandler(userStore))
		protected.POST("/auth/me/password", rateLimitSensitive(), changeMyPasswordHandler(userStore))
		protected.GET("/dashboard", dashboardHandler(store, engine, services, userStore, auditStore))
		protected.GET("/system/stats", systemStatsHandler())
		protected.GET("/system/inspection", systemInspectionHandler())
		protected.GET("/system/tls", getTLSHandler(store))
		protected.POST("/system/tls/cert", requireAdmin(), setTLSCertHandler(store))
		protected.POST("/system/tls/trusted-ca", requireAdmin(), setTrustedCAHandler(store))
		protected.POST("/system/factory-reset", requireAdmin(), rateLimitSensitive(), factoryResetHandler(store, userStore))
		protected.GET("/config", getConfigHandler(store))
		protected.POST("/config", requireAdmin(), saveConfigHandler(store))
		protected.POST("/config/validate", requireAdmin(), validateConfigHandler())
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
		protected.POST("/services/syslog", requireAdmin(), setSyslogHandler(store, services))
		protected.PATCH("/services/syslog", requireAdmin(), patchSyslogHandler(store, services))
		protected.GET("/services/dns", getDNSHandler(store))
		protected.POST("/services/dns", requireAdmin(), setDNSHandler(store, services))
		protected.GET("/services/ntp", getNTPHandler(store))
		protected.POST("/services/ntp", requireAdmin(), setNTPHandler(store, services))
		protected.GET("/services/dhcp", getDHCPHandler(store))
		protected.POST("/services/dhcp", requireAdmin(), setDHCPHandler(store, services, engine))
		protected.GET("/services/vpn", getVPNHandler(store))
		protected.POST("/services/vpn", requireAdmin(), setVPNHandler(store, services, engine))
		protected.POST("/services/vpn/openvpn/profile", requireAdmin(), uploadOpenVPNProfileHandler(store, services, engine))
		protected.GET("/services/vpn/openvpn/clients", requireAdmin(), listOpenVPNClientsHandler(store))
		protected.POST("/services/vpn/openvpn/clients", requireAdmin(), createOpenVPNClientHandler(store))
		protected.GET("/services/vpn/openvpn/clients/:name", requireAdmin(), downloadOpenVPNClientHandler(store))
		protected.GET("/services/vpn/wireguard/status", getWireGuardStatusHandler(engine))
		protected.GET("/services/av", getAVHandler(store))
		protected.POST("/services/av", requireAdmin(), setAVHandler(store, services))
		protected.POST("/services/av/update", requireAdmin(), triggerAVUpdateHandler(services))
		protected.GET("/services/av/defs", listAVDefsHandler(store, services))
		protected.POST("/services/av/defs", requireAdmin(), uploadAVDefHandler(store, services))
		protected.DELETE("/services/av/defs", requireAdmin(), deleteAVDefHandler(store, services))
		protected.GET("/services/proxy/forward", getForwardProxyHandler(store))
		protected.POST("/services/proxy/forward", requireAdmin(), setForwardProxyHandler(store, services))
		protected.GET("/services/proxy/reverse", getReverseProxyHandler(store))
		protected.POST("/services/proxy/reverse", requireAdmin(), setReverseProxyHandler(store, services))
		protected.GET("/services/status", getServicesStatusHandler(services))
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
		protected.POST("/conntrack/kill", requireAdmin(), killConntrackHandler(engine))
		protected.GET("/dhcp/leases", dhcpLeasesHandler(engine))
		protected.GET("/dataplane", getDataPlaneHandler(store))
		protected.POST("/dataplane", requireAdmin(), setDataPlaneHandler(store, engine))
		protected.GET("/dataplane/ruleset", requireAdmin(), getRulesetPreviewHandler(store, engine))
		protected.POST("/dataplane/blocks/host", requireAdmin(), blockHostHandler(engine))
		protected.POST("/dataplane/blocks/flow", requireAdmin(), blockFlowHandler(engine))
		protected.GET("/pcap/config", getPCAPConfigHandler(store))
		protected.POST("/pcap/config", requireAdmin(), setPCAPConfigHandler(store, engine))
		protected.POST("/pcap/start", requireAdmin(), startPCAPHandler(store, engine))
		protected.POST("/pcap/stop", requireAdmin(), stopPCAPHandler(store, engine))
		protected.GET("/pcap/status", getPCAPStatusHandler(engine))
		protected.GET("/pcap/list", getPCAPListHandler(engine))
		protected.POST("/pcap/upload", requireAdmin(), uploadPCAPHandler(engine))
		protected.GET("/pcap/download/:name", downloadPCAPHandler(engine))
		protected.DELETE("/pcap/:name", requireAdmin(), deletePCAPHandler(engine))
		protected.POST("/pcap/tag", requireAdmin(), tagPCAPHandler(engine))
		protected.POST("/pcap/replay", requireAdmin(), replayPCAPHandler(engine))
		protected.POST("/pcap/analyze", requireAdmin(), analyzePCAPUploadHandler(engine))
		protected.POST("/pcap/analyze/:name", requireAdmin(), analyzePCAPNameHandler(engine))
		protected.GET("/inventory", listInventoryHandler(engine))
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
		protected.GET("/interfaces/state", interfaceStateHandler(store, engine))
		protected.POST("/interfaces/assign", requireAdmin(), interfacesAssignHandler(store, engine, services))
		protected.POST("/interfaces/reconcile", requireAdmin(), interfacesReconcileHandler(store, engine))
		protected.POST("/interfaces", requireAdmin(), createInterfaceHandler(store, engine, services))
		protected.PATCH("/interfaces/:name", requireAdmin(), updateInterfaceHandler(store, engine, services))
		protected.DELETE("/interfaces/:name", requireAdmin(), deleteInterfaceHandler(store, engine, services))
		protected.GET("/routing", getRoutingHandler(store))
		protected.GET("/routing/os", getOSRoutingHandler())
		protected.POST("/routing", requireAdmin(), setRoutingHandler(store, engine, services))
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
		protected.POST("/ids/rules", requireAdmin(), setIDSHandler(store, engine, services))
		protected.POST("/ids/convert/sigma", convertSigmaHandler())
		protected.POST("/ids/import", requireAdmin(), idsImportHandler(store, engine, services))
		protected.POST("/ids/export", idsExportHandler(store))
		protected.GET("/ids/sources", idsSourcesHandler())
		protected.GET("/ids/backup", idsBackupHandler(store))
		protected.POST("/ids/restore", requireAdmin(), idsRestoreHandler(store, engine, services))
		protected.POST("/cli/execute", cliExecuteHandler(store))
		protected.GET("/cli/commands", cliCommandsHandler(store))
		protected.GET("/cli/complete", cliCompleteHandler(store))
		protected.GET("/cli/ws", cliWSHandler(store))
		// Users (admin only).
		protected.GET("/users", requireAdmin(), listUsersHandler(userStore))
		protected.POST("/users", requireAdmin(), rateLimitSensitive(), createUserHandler(userStore))
		protected.PATCH("/users/:id", requireAdmin(), rateLimitSensitive(), updateUserHandler(userStore))
		protected.POST("/users/:id/password", requireAdmin(), rateLimitSensitive(), setUserPasswordHandler(userStore))
		protected.DELETE("/users/:id", requireAdmin(), rateLimitSensitive(), deleteUserHandler(userStore))
		if auditStore != nil {
			auditHandlers(protected, auditStore)
		}
		// Policy templates.
		protected.GET("/templates", listTemplatesHandler())
		protected.POST("/templates/apply", requireAdmin(), applyTemplateHandler(store))
		// ICS protocol templates.
		protected.GET("/templates/ics", listICSTemplatesHandler())
		protected.POST("/templates/ics/apply", requireAdmin(), applyICSTemplateHandler())
		// Identity resolver routes (optional).
		for _, o := range opts {
			if resolver, ok := o.(*identity.Resolver); ok && resolver != nil {
				protected.GET("/identities", listIdentitiesHandler(resolver))
				protected.POST("/identities", requireAdmin(), setIdentityHandler(resolver))
				protected.DELETE("/identities/:ip", requireAdmin(), deleteIdentityHandler(resolver))
			}
		}
	}

	return r
}

func listInventoryHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		ic, ok := engine.(InventoryClient)
		if !ok || ic == nil {
			c.JSON(http.StatusOK, []inventory.DiscoveredAsset{})
			return
		}
		assets, err := ic.ListInventory(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		if assets == nil {
			assets = []inventory.DiscoveredAsset{}
		}
		c.JSON(http.StatusOK, assets)
	}
}

func getInventoryAssetHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		ic, ok := engine.(InventoryClient)
		if !ok || ic == nil {
			apiError(c, http.StatusNotFound, "inventory not available")
			return
		}
		ip := c.Param("ip")
		asset, err := ic.GetInventoryAsset(c.Request.Context(), ip)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		if asset == nil {
			apiError(c, http.StatusNotFound, "asset not found")
			return
		}
		c.JSON(http.StatusOK, asset)
	}
}

func clearInventoryHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		ic, ok := engine.(InventoryClient)
		if !ok || ic == nil {
			apiError(c, http.StatusNotImplemented, "inventory not available")
			return
		}
		if err := ic.ClearInventory(c.Request.Context()); err != nil {
			apiError(c, http.StatusInternalServerError, err.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "cleared"})
	}
}

func dhcpLeasesHandler(engine any) gin.HandlerFunc {
	type resp struct {
		Leases []dhcpd.Lease `json:"leases"`
	}
	return func(c *gin.Context) {
		cl, ok := engine.(DHCPLeasesClient)
		if !ok || cl == nil {
			apiError(c, http.StatusServiceUnavailable, "engine dhcp leases not available")
			return
		}
		leases, err := cl.ListDHCPLeases(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		c.JSON(http.StatusOK, resp{Leases: leases})
	}
}

type syslogPatch struct {
	Action     string                  `json:"action,omitempty"`
	Format     string                  `json:"format,omitempty"`
	Forwarder  *config.SyslogForwarder `json:"forwarder,omitempty"`
	BatchSize  int                     `json:"batchSize,omitempty"`
	FlushEvery int                     `json:"flushEvery,omitempty"` // seconds
}

// patchSyslogHandler supports incremental updates (format set, forwarder add/del, batch/flush tweaks).
func patchSyslogHandler(store config.Store, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var patch syslogPatch
		if err := c.ShouldBindJSON(&patch); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		cur := cfg.Services.Syslog
		if patch.Format != "" {
			cur.Format = patch.Format
		}
		if patch.BatchSize > 0 {
			cur.BatchSize = patch.BatchSize
		}
		if patch.FlushEvery > 0 {
			cur.FlushEvery = patch.FlushEvery
		}
		if patch.Forwarder != nil {
			f := *patch.Forwarder
			if err := cpservices.ValidateSyslogForwarder(f); err != nil {
				apiError(c, http.StatusBadRequest, err.Error())
				return
			}
			switch strings.ToLower(strings.TrimSpace(patch.Action)) {
			case "add":
				cur.Forwarders = append(cur.Forwarders, f)
			case "del":
				var next []config.SyslogForwarder
				for _, existing := range cur.Forwarders {
					if existing.Address == f.Address && existing.Port == f.Port {
						continue
					}
					next = append(next, existing)
				}
				cur.Forwarders = next
			default:
				// no-op if action unknown
			}
		}
		cfg.Services.Syslog = cur
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if services != nil {
			if err := services.Apply(c.Request.Context(), cfg.Services); err != nil {
				apiError(c, http.StatusBadGateway, err.Error())
				return
			}
		}
		c.JSON(http.StatusOK, cfg.Services.Syslog)
	}
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"component": "mgmt",
		"build":     config.BuildVersion,
		"time":      time.Now().UTC().Format(time.RFC3339Nano),
	})
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
		c.JSON(http.StatusOK, cfg.RedactedCopy())
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
		if err := store.Save(ctx, &cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "config.save", Target: "running"})
		c.JSON(http.StatusOK, gin.H{"status": "saved"})
	}
}

func validateConfigHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var cfg config.Config
		if err := c.ShouldBindJSON(&cfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		if err := cfg.Validate(); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "valid"})
	}
}

func exportConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.Load(c.Request.Context())
		if err != nil {
			if errors.Is(err, config.ErrNotFound) {
				apiError(c, http.StatusNotFound, "config not found")
				return
			}
			internalError(c, err)
			return
		}
		// Exports are redacted by default; only admins can request unredacted.
		wantRedacted := true
		switch strings.ToLower(strings.TrimSpace(c.Query("redacted"))) {
		case "0", "false", "no":
			wantRedacted = false
		case "1", "true", "yes":
			wantRedacted = true
		case "":
			// default redacted
		default:
			apiError(c, http.StatusBadRequest, "invalid redacted query value")
			return
		}
		if !wantRedacted && c.GetString(ctxRoleKey) != string(roleAdmin) {
			apiError(c, http.StatusForbidden, "admin role required for unredacted export")
			return
		}
		if wantRedacted {
			cfg = cfg.RedactedCopy()
		}
		c.JSON(http.StatusOK, cfg)
	}
}

func importConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		const maxImportSize = 10 << 20 // 10 MB
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxImportSize+1))
		if err != nil {
			apiError(c, http.StatusBadRequest, "failed to read body")
			return
		}
		if int64(len(body)) > maxImportSize {
			apiError(c, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		var cfg config.Config
		if err := json.Unmarshal(body, &cfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		if err := cfg.Validate(); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := store.Save(c.Request.Context(), &cfg); err != nil {
			internalError(c, err)
			return
		}
		auditLog(c, audit.Record{Action: "config.import", Target: "running"})
		c.JSON(http.StatusOK, gin.H{"status": "imported"})
	}
}

type configBackupMeta struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	CreatedAt    time.Time `json:"createdAt"`
	Redacted     bool      `json:"redacted"`
	IDSRuleCount int       `json:"idsRuleCount,omitempty"`
}

type configBackupInfo struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	CreatedAt    time.Time `json:"createdAt"`
	Redacted     bool      `json:"redacted"`
	Size         int64     `json:"size"`
	IDSRuleCount int       `json:"idsRuleCount,omitempty"`
}

type configBackupRequest struct {
	Name     string `json:"name"`
	Redacted bool   `json:"redacted"`
}

func configBackupDir() string {
	if v := common.EnvTrimmed("CONTAIND_CONFIG_BACKUP_DIR", ""); v != "" {
		return v
	}
	if dbPath := common.EnvTrimmed("CONTAIND_CONFIG_DB", ""); dbPath != "" {
		return filepath.Join(filepath.Dir(dbPath), "config-backups")
	}
	return filepath.Join("data", "config-backups")
}

func configBackupPaths(id string) (string, string) {
	// Sanitize to prevent path traversal: only allow alphanumeric, hyphens, underscores.
	clean := filepath.Base(id)
	for _, r := range clean {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			clean = ""
			break
		}
	}
	if clean == "" || clean == "." || clean == ".." {
		clean = "invalid"
	}
	dir := configBackupDir()
	return filepath.Join(dir, clean+".json"), filepath.Join(dir, clean+".meta.json")
}

func newConfigBackupID() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

func sanitizeBackupFilename(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "containd-config-backup"
	}
	var out strings.Builder
	out.Grow(len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			out.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			out.WriteRune(r)
		case r >= '0' && r <= '9':
			out.WriteRune(r)
		case r == '-' || r == '_' || r == ' ':
			out.WriteRune(r)
		default:
			out.WriteRune('_')
		}
	}
	return strings.TrimSpace(out.String())
}

func listConfigBackupsHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		dir := configBackupDir()
		entries, err := os.ReadDir(dir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				c.JSON(http.StatusOK, []configBackupInfo{})
				return
			}
			internalError(c, err)
			return
		}
		isAdmin := c.GetString(ctxRoleKey) == string(roleAdmin)
		backups := make([]configBackupInfo, 0, len(entries))
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".meta.json") {
				continue
			}
			metaPath := filepath.Join(dir, entry.Name())
			metaBytes, err := os.ReadFile(metaPath)
			if err != nil {
				continue
			}
			var meta configBackupMeta
			if err := json.Unmarshal(metaBytes, &meta); err != nil {
				continue
			}
			if !isAdmin && !meta.Redacted {
				continue
			}
			jsonPath, _ := configBackupPaths(meta.ID)
			info, err := os.Stat(jsonPath)
			if err != nil {
				continue
			}
			backups = append(backups, configBackupInfo{
				ID:           meta.ID,
				Name:         meta.Name,
				CreatedAt:    meta.CreatedAt,
				Redacted:     meta.Redacted,
				Size:         info.Size(),
				IDSRuleCount: meta.IDSRuleCount,
			})
		}
		sort.Slice(backups, func(i, j int) bool {
			return backups[i].CreatedAt.After(backups[j].CreatedAt)
		})
		c.JSON(http.StatusOK, backups)
	}
}

func createConfigBackupHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req configBackupRequest
		if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
			apiError(c, http.StatusBadRequest, "invalid request")
			return
		}
		cfg, err := store.Load(c.Request.Context())
		if err != nil {
			if errors.Is(err, config.ErrNotFound) {
				apiError(c, http.StatusNotFound, "config not found")
				return
			}
			internalError(c, err)
			return
		}
		if req.Redacted {
			cfg = cfg.RedactedCopy()
		}
		if err := os.MkdirAll(configBackupDir(), 0o750); err != nil {
			internalError(c, err)
			return
		}
		id, err := newConfigBackupID()
		if err != nil {
			apiError(c, http.StatusInternalServerError, "failed to generate backup id")
			return
		}
		now := time.Now().UTC()
		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = fmt.Sprintf("Backup %s", now.Format("2006-01-02 15:04 UTC"))
		}
		// Also capture IDS rules count for metadata.
		idsRules, _ := store.LoadIDSRules(c.Request.Context())
		meta := configBackupMeta{
			ID:           id,
			Name:         name,
			CreatedAt:    now,
			Redacted:     req.Redacted,
			IDSRuleCount: len(idsRules),
		}
		jsonPath, metaPath := configBackupPaths(id)
		idsPath := jsonPath[:len(jsonPath)-len(".json")] + ".ids.json"
		tmpJSON := jsonPath + ".tmp"
		tmpMeta := metaPath + ".tmp"
		tmpIDS := idsPath + ".tmp"
		payload, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			apiError(c, http.StatusInternalServerError, "failed to serialize config")
			return
		}
		if err := os.WriteFile(tmpJSON, payload, 0o600); err != nil {
			apiError(c, http.StatusInternalServerError, "failed to write backup")
			return
		}
		metaBytes, err := json.Marshal(meta)
		if err != nil {
			_ = os.Remove(tmpJSON)
			apiError(c, http.StatusInternalServerError, "failed to write backup metadata")
			return
		}
		if err := os.WriteFile(tmpMeta, metaBytes, 0o600); err != nil {
			_ = os.Remove(tmpJSON)
			apiError(c, http.StatusInternalServerError, "failed to write backup metadata")
			return
		}
		if err := os.Rename(tmpJSON, jsonPath); err != nil {
			_ = os.Remove(tmpJSON)
			_ = os.Remove(tmpMeta)
			apiError(c, http.StatusInternalServerError, "failed to persist backup")
			return
		}
		if err := os.Rename(tmpMeta, metaPath); err != nil {
			_ = os.Remove(jsonPath)
			_ = os.Remove(tmpMeta)
			apiError(c, http.StatusInternalServerError, "failed to persist backup metadata")
			return
		}
		// Write IDS rules as separate file alongside config backup.
		if len(idsRules) > 0 {
			idsPayload, _ := json.MarshalIndent(idsRules, "", "  ")
			if err := os.WriteFile(tmpIDS, idsPayload, 0o600); err == nil {
				_ = os.Rename(tmpIDS, idsPath)
			}
		}
		info, _ := os.Stat(jsonPath)
		auditLog(c, audit.Record{Action: "config.backup.create", Target: "running"})
		c.JSON(http.StatusOK, configBackupInfo{
			ID:           meta.ID,
			Name:         meta.Name,
			CreatedAt:    meta.CreatedAt,
			Redacted:     meta.Redacted,
			Size:         info.Size(),
			IDSRuleCount: meta.IDSRuleCount,
		})
	}
}

func downloadConfigBackupHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := strings.TrimSpace(c.Param("id"))
		if id == "" {
			apiError(c, http.StatusBadRequest, "backup id required")
			return
		}
		_, metaPath := configBackupPaths(id)
		metaBytes, err := os.ReadFile(metaPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				apiError(c, http.StatusNotFound, "backup not found")
				return
			}
			internalError(c, err)
			return
		}
		var meta configBackupMeta
		if err := json.Unmarshal(metaBytes, &meta); err != nil {
			apiError(c, http.StatusInternalServerError, "backup metadata corrupted")
			return
		}
		if !meta.Redacted && c.GetString(ctxRoleKey) != string(roleAdmin) {
			apiError(c, http.StatusForbidden, "admin role required for unredacted backup")
			return
		}
		jsonPath, _ := configBackupPaths(id)
		f, err := os.Open(jsonPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				apiError(c, http.StatusNotFound, "backup not found")
				return
			}
			internalError(c, err)
			return
		}
		defer f.Close()
		filename := sanitizeBackupFilename(meta.Name) + ".json"
		c.Header("Content-Type", "application/json")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
		c.Status(http.StatusOK)
		_, _ = io.Copy(c.Writer, f)
	}
}

func deleteConfigBackupHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := strings.TrimSpace(c.Param("id"))
		if id == "" {
			apiError(c, http.StatusBadRequest, "backup id required")
			return
		}
		jsonPath, metaPath := configBackupPaths(id)
		idsPath := jsonPath[:len(jsonPath)-len(".json")] + ".ids.json"
		if err := os.Remove(metaPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			internalError(c, err)
			return
		}
		if err := os.Remove(jsonPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			internalError(c, err)
			return
		}
		_ = os.Remove(idsPath) // best-effort cleanup of IDS rules file
		auditLog(c, audit.Record{Action: "config.backup.delete", Target: "running"})
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
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
		c.JSON(http.StatusOK, cfg.RedactedCopy())
	}
}

func saveCandidateConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var cfg config.Config
		if err := c.ShouldBindJSON(&cfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		// Restore secrets that were redacted in the read response so
		// round-tripping redacted config doesn't wipe stored secrets.
		if existing, err := store.Load(c.Request.Context()); err == nil {
			cfg.RestoreRedactedSecrets(existing)
		}
		if err := store.SaveCandidate(c.Request.Context(), &cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "config.save_candidate", Target: "candidate"})
		c.JSON(http.StatusOK, gin.H{"status": "saved"})
	}
}

func commitConfigHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := store.Commit(c.Request.Context()); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		warnings, err := applyRunningConfig(c.Request.Context(), store, engine, services)
		if err != nil {
			internalError(c, err)
			return
		}
		setWarningHeader(c, warnings)
		auditLog(c, audit.Record{Action: "config.commit", Target: "running"})
		c.JSON(http.StatusOK, gin.H{"status": "committed"})
	}
}

func commitConfirmedHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		const defaultTTLSeconds = 60
		body, _ := io.ReadAll(io.LimitReader(c.Request.Body, 4096))
		ttlSeconds := int64(defaultTTLSeconds)
		if len(body) > 0 {
			var req struct {
				TTLSeconds int64 `json:"ttl_seconds"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
				return
			}
			if req.TTLSeconds > 0 {
				ttlSeconds = req.TTLSeconds
			}
		}
		if err := store.CommitConfirmed(c.Request.Context(), time.Duration(ttlSeconds)*time.Second); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		warnings, err := applyRunningConfig(c.Request.Context(), store, engine, services)
		if err != nil {
			internalError(c, err)
			return
		}
		setWarningHeader(c, warnings)
		auditLog(c, audit.Record{Action: "config.commit_confirmed", Target: "running"})
		c.JSON(http.StatusOK, gin.H{"status": "committed"})
	}
}

func confirmCommitHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := store.ConfirmCommit(c.Request.Context()); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "config.confirm_commit", Target: "running"})
		c.JSON(http.StatusOK, gin.H{"status": "confirmed"})
	}
}

func rollbackConfigHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := store.Rollback(c.Request.Context()); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		warnings, err := applyRunningConfig(c.Request.Context(), store, engine, services)
		if err != nil {
			internalError(c, err)
			return
		}
		setWarningHeader(c, warnings)
		auditLog(c, audit.Record{Action: "config.rollback", Target: "running"})
		c.JSON(http.StatusOK, gin.H{"status": "rolled back"})
	}
}

func applyRunningConfig(ctx context.Context, store config.Store, engine EngineClient, services ServicesApplier) ([]string, error) {
	cfg, err := store.Load(ctx)
	if err != nil {
		if errors.Is(err, config.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if services != nil {
		if err := services.Apply(ctx, cfg.Services); err != nil {
			return nil, err
		}
	}
	var warnings []string
	if engine != nil {
		// Infrastructure steps (interfaces, routing, services, pcap) may fail in
		// unprivileged environments (e.g. Docker without NET_ADMIN). Collect those
		// errors but always proceed to compile and apply rules so that IDS/firewall
		// rule evaluation works even when nftables is unavailable.
		if err := engine.ConfigureInterfaces(ctx, cfg.Interfaces); err != nil {
			warnings = append(warnings, fmt.Sprintf("interfaces: %v", err))
		}
		if err := engine.ConfigureRouting(ctx, cfg.Routing); err != nil {
			warnings = append(warnings, fmt.Sprintf("routing: %v", err))
		}
		if err := engine.ConfigureServices(ctx, cfg.Services); err != nil {
			warnings = append(warnings, fmt.Sprintf("services: %v", err))
		}
		if err := engine.Configure(ctx, cfg.DataPlane); err != nil {
			warnings = append(warnings, fmt.Sprintf("dataplane: %v", err))
		}
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
		// Load IDS rules from separate storage and inject for compilation.
		idsRules, idsErr := store.LoadIDSRules(ctx)
		if idsErr != nil {
			warnings = append(warnings, fmt.Sprintf("ids rules: %v", idsErr))
		} else {
			cfg.IDS.Rules = idsRules
		}
		// Always compile and push rules regardless of infrastructure errors.
		snap, err := compile.CompileSnapshot(cfg)
		if err != nil {
			return nil, err
		}
		if err := engine.ApplyRules(ctx, snap); err != nil {
			return nil, err
		}
	}
	return warnings, nil
}

func diffConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		running, err := store.Load(c.Request.Context())
		if err != nil && !errors.Is(err, config.ErrNotFound) {
			internalError(c, err)
			return
		}
		candidate, err := store.LoadCandidate(c.Request.Context())
		if err != nil && !errors.Is(err, config.ErrNotFound) {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"running":   running.RedactedCopy(),
			"candidate": candidate.RedactedCopy(),
		})
	}
}

func applyServiceRuntime(ctx context.Context, servicesCfg config.ServicesConfig, services ServicesApplier, engine EngineClient) []string {
	var warnings []string
	if services != nil {
		if err := services.Apply(ctx, servicesCfg); err != nil {
			warnings = append(warnings, fmt.Sprintf("services: %v", err))
		}
	}
	if engine != nil {
		if err := engine.ConfigureServices(ctx, servicesCfg); err != nil {
			warnings = append(warnings, fmt.Sprintf("engine services: %v", err))
		}
	}
	return warnings
}

func getSyslogHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Services.Syslog)
	}
}

func setSyslogHandler(store config.Store, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var syslogCfg config.SyslogConfig
		if err := c.ShouldBindJSON(&syslogCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		cfg.Services.Syslog = syslogCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		setWarningHeader(c, applyServiceRuntime(c.Request.Context(), cfg.Services, services, nil))
		c.JSON(http.StatusOK, cfg.Services.Syslog)
	}
}

func getDNSHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Services.DNS)
	}
}

func setDNSHandler(store config.Store, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var dnsCfg config.DNSConfig
		if err := c.ShouldBindJSON(&dnsCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		if v, ok := services.(ServicesValidator); ok && v != nil {
			next := cfg.Services
			next.DNS = dnsCfg
			if err := v.Validate(c.Request.Context(), next); err != nil {
				apiError(c, http.StatusBadRequest, err.Error())
				return
			}
		}
		cfg.Services.DNS = dnsCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		setWarningHeader(c, applyServiceRuntime(c.Request.Context(), cfg.Services, services, nil))
		auditLog(c, audit.Record{Action: "services.dns.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.Services.DNS)
	}
}

func getNTPHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Services.NTP)
	}
}

func setNTPHandler(store config.Store, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var ntpCfg config.NTPConfig
		if err := c.ShouldBindJSON(&ntpCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		cfg.Services.NTP = ntpCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		setWarningHeader(c, applyServiceRuntime(c.Request.Context(), cfg.Services, services, nil))
		auditLog(c, audit.Record{Action: "services.ntp.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.Services.NTP)
	}
}

func getAVHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Services.AV)
	}
}

func setAVHandler(store config.Store, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var avCfg config.AVConfig
		if err := c.ShouldBindJSON(&avCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		if v, ok := services.(ServicesValidator); ok && v != nil {
			next := cfg.Services
			next.AV = avCfg
			if err := v.Validate(c.Request.Context(), next); err != nil {
				apiError(c, http.StatusBadRequest, err.Error())
				return
			}
		}
		cfg.Services.AV = avCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		setWarningHeader(c, applyServiceRuntime(c.Request.Context(), cfg.Services, services, nil))
		auditLog(c, audit.Record{Action: "services.av.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.Services.AV)
	}
}

func triggerAVUpdateHandler(services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		updater, ok := services.(AVUpdater)
		if !ok || updater == nil {
			apiError(c, http.StatusNotImplemented, "av updater not available")
			return
		}
		if err := updater.TriggerAVUpdate(c.Request.Context()); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusAccepted, gin.H{"status": "freshclam started"})
	}
}

func listAVDefsHandler(store config.Store, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		path := "/data/clamav/custom"
		if am, ok := services.(AVDefsManager); ok && am != nil && am.CustomDefsPath() != "" {
			path = am.CustomDefsPath()
		} else if strings.TrimSpace(cfg.Services.AV.ClamAV.CustomDefsPath) != "" {
			path = cfg.Services.AV.ClamAV.CustomDefsPath
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			if os.IsNotExist(err) {
				c.JSON(http.StatusOK, gin.H{"files": []string{}})
				return
			}
			internalError(c, err)
			return
		}
		var files []string
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			files = append(files, e.Name())
		}
		c.JSON(http.StatusOK, gin.H{"files": files, "path": path})
	}
}

func uploadAVDefHandler(store config.Store, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		path := "/data/clamav/custom"
		if am, ok := services.(AVDefsManager); ok && am != nil && am.CustomDefsPath() != "" {
			path = am.CustomDefsPath()
		} else if strings.TrimSpace(cfg.Services.AV.ClamAV.CustomDefsPath) != "" {
			path = cfg.Services.AV.ClamAV.CustomDefsPath
		}
		if err := os.MkdirAll(path, 0o755); err != nil {
			internalError(c, err)
			return
		}
		file, err := c.FormFile("file")
		if err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "file is required", err.Error())
			return
		}
		name := filepath.Base(file.Filename)
		if name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
			apiError(c, http.StatusBadRequest, "invalid filename")
			return
		}
		dst := filepath.Join(path, name)
		if !strings.HasPrefix(filepath.Clean(dst), filepath.Clean(path)) {
			apiError(c, http.StatusBadRequest, "invalid filename")
			return
		}
		if err := c.SaveUploadedFile(file, dst); err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "uploaded", "file": name})
	}
}

func deleteAVDefHandler(store config.Store, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		file := strings.TrimSpace(c.Query("file"))
		if file == "" {
			apiError(c, http.StatusBadRequest, "file query parameter required")
			return
		}
		path := "/data/clamav/custom"
		if am, ok := services.(AVDefsManager); ok && am != nil && am.CustomDefsPath() != "" {
			path = am.CustomDefsPath()
		} else if strings.TrimSpace(cfg.Services.AV.ClamAV.CustomDefsPath) != "" {
			path = cfg.Services.AV.ClamAV.CustomDefsPath
		}
		target := filepath.Join(path, filepath.Base(file))
		if err := os.Remove(target); err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "deleted", "file": filepath.Base(file)})
	}
}

func getDHCPHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Services.DHCP)
	}
}

func setDHCPHandler(store config.Store, services ServicesApplier, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		var dhcpCfg config.DHCPConfig
		if err := c.ShouldBindJSON(&dhcpCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		cfg.Services.DHCP = dhcpCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		setWarningHeader(c, applyServiceRuntime(c.Request.Context(), cfg.Services, services, engine))
		auditLog(c, audit.Record{Action: "services.dhcp.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.Services.DHCP)
	}
}

func getVPNHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		// Redact VPN secrets (WireGuard private keys, OpenVPN credentials/PEM).
		redacted := cfg.Services.VPN.RedactedVPNCopy()
		c.JSON(http.StatusOK, redacted)
	}
}

func setVPNHandler(store config.Store, services ServicesApplier, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		var vpnCfg config.VPNConfig
		if err := c.ShouldBindJSON(&vpnCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		vpnCfg.RestoreRedactedSecrets(cfg.Services.VPN)
		cfg.Services.VPN = vpnCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		setWarningHeader(c, applyServiceRuntime(c.Request.Context(), cfg.Services, services, engine))
		auditLog(c, audit.Record{Action: "services.vpn.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.Services.VPN)
	}
}

func uploadOpenVPNProfileHandler(store config.Store, services ServicesApplier, engine EngineClient) gin.HandlerFunc {
	type req struct {
		Name string `json:"name"`
		OVPN string `json:"ovpn"`
	}
	return func(c *gin.Context) {
		var r req
		if err := c.ShouldBindJSON(&r); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		name := strings.TrimSpace(r.Name)
		if name == "" {
			name = "client"
		}
		name = sanitizeProfileName(name)
		if name == "" {
			apiError(c, http.StatusBadRequest, "invalid profile name")
			return
		}
		ovpn := strings.TrimSpace(r.OVPN)
		if ovpn == "" {
			apiError(c, http.StatusBadRequest, "ovpn content is empty")
			return
		}
		if len(ovpn) > 1_000_000 {
			apiError(c, http.StatusRequestEntityTooLarge, "ovpn content too large")
			return
		}
		if err := ensureOpenVPNConfigForegroundString(ovpn); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}

		// Persist under /data so it survives container restarts.
		base := "/data/openvpn/profiles"
		if v := strings.TrimSpace(os.Getenv("CONTAIND_OPENVPN_DIR")); v != "" {
			base = v
		}
		if err := os.MkdirAll(base, 0o700); err != nil {
			internalError(c, err)
			return
		}
		path := filepath.Join(base, name+".ovpn")
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(ovpn+"\n"), 0o600); err != nil {
			internalError(c, err)
			return
		}
		if err := os.Rename(tmp, path); err != nil {
			_ = os.Remove(tmp)
			internalError(c, err)
			return
		}

		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		cfg.Services.VPN.OpenVPN.ConfigPath = path
		// Explicit profile uploads are considered "advanced" mode; prefer them over managed config.
		cfg.Services.VPN.OpenVPN.Managed = nil
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		setWarningHeader(c, applyServiceRuntime(c.Request.Context(), cfg.Services, services, engine))
		auditLog(c, audit.Record{Action: "services.vpn.openvpn.profile.upload", Target: name})
		c.JSON(http.StatusOK, gin.H{"configPath": path, "vpn": cfg.Services.VPN})
	}
}

func sanitizeProfileName(in string) string {
	in = strings.ToLower(strings.TrimSpace(in))
	var b strings.Builder
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			// drop
		}
	}
	out := strings.Trim(b.String(), "._-")
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func ensureOpenVPNConfigForegroundString(s string) error {
	lines := strings.Split(s, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "daemon" {
			return fmt.Errorf("openvpn profile contains 'daemon' directive; remove it (supervisor requires foreground)")
		}
	}
	return nil
}

func openVPNBaseDir() string {
	base := "/data/openvpn"
	if v := strings.TrimSpace(os.Getenv("CONTAIND_OPENVPN_DIR")); v != "" {
		base = v
		if strings.HasSuffix(base, "/profiles") {
			base = filepath.Dir(base)
		}
	}
	return base
}

func openVPNManagedServerPKIDir() string {
	return filepath.Join(openVPNBaseDir(), "managed", "server", "pki")
}

func openVPNManagedServerClientsDir() string {
	return filepath.Join(openVPNManagedServerPKIDir(), "clients")
}

func listOpenVPNClientsHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		if !cfg.Services.VPN.OpenVPN.Enabled || strings.TrimSpace(cfg.Services.VPN.OpenVPN.Mode) != "server" || cfg.Services.VPN.OpenVPN.Server == nil {
			apiError(c, http.StatusBadRequest, "openvpn server is not configured")
			return
		}
		dir := openVPNManagedServerClientsDir()
		ents, err := os.ReadDir(dir)
		if err != nil {
			// If missing, treat as empty.
			if os.IsNotExist(err) {
				c.JSON(http.StatusOK, gin.H{"clients": []string{}})
				return
			}
			internalError(c, err)
			return
		}
		var out []string
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasSuffix(name, ".crt") {
				out = append(out, strings.TrimSuffix(name, ".crt"))
			}
		}
		sort.Strings(out)
		c.JSON(http.StatusOK, gin.H{"clients": out})
	}
}

func createOpenVPNClientHandler(store config.Store) gin.HandlerFunc {
	type req struct {
		Name string `json:"name"`
	}
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		if !cfg.Services.VPN.OpenVPN.Enabled || strings.TrimSpace(cfg.Services.VPN.OpenVPN.Mode) != "server" || cfg.Services.VPN.OpenVPN.Server == nil {
			apiError(c, http.StatusBadRequest, "openvpn server is not configured")
			return
		}
		var r req
		if err := c.ShouldBindJSON(&r); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		name := strings.TrimSpace(r.Name)
		if name == "" {
			apiError(c, http.StatusBadRequest, "name is required")
			return
		}
		if strings.ContainsAny(name, "/\\ ") {
			apiError(c, http.StatusBadRequest, "name contains invalid characters")
			return
		}
		pkiDir := openVPNManagedServerPKIDir()
		caCertPath, caKeyPath, err := cpservices.EnsureOpenVPNCA(pkiDir)
		if err != nil {
			internalError(c, err)
			return
		}
		// Ensure server cert exists too, so the PKI is complete.
		_, _, _ = cpservices.EnsureOpenVPNServerCert(pkiDir, caCertPath, caKeyPath)
		clientCertPath, _, err := cpservices.EnsureOpenVPNClientCert(pkiDir, caCertPath, caKeyPath, name)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		clientName := strings.TrimSuffix(filepath.Base(clientCertPath), ".crt")
		auditLog(c, audit.Record{Action: "services.vpn.openvpn.client.create", Target: clientName})
		c.JSON(http.StatusOK, gin.H{"name": clientName})
	}
}

func downloadOpenVPNClientHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := strings.TrimSpace(c.Param("name"))
		if name == "" {
			apiError(c, http.StatusBadRequest, "name is required")
			return
		}
		if strings.ContainsAny(name, "/\\ ") {
			apiError(c, http.StatusBadRequest, "name contains invalid characters")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		ovpn := cfg.Services.VPN.OpenVPN
		if !ovpn.Enabled || strings.TrimSpace(ovpn.Mode) != "server" || ovpn.Server == nil {
			apiError(c, http.StatusBadRequest, "openvpn server is not configured")
			return
		}
		publicEndpoint := strings.TrimSpace(ovpn.Server.PublicEndpoint)
		if publicEndpoint == "" {
			apiError(c, http.StatusBadRequest, "openvpn.server.publicEndpoint is required to generate client profiles")
			return
		}
		proto := strings.ToLower(strings.TrimSpace(ovpn.Server.Proto))
		if proto == "" {
			proto = "udp"
		}
		port := ovpn.Server.ListenPort
		if port == 0 {
			port = 1194
		}

		pkiDir := openVPNManagedServerPKIDir()
		caCertPath, caKeyPath, err := cpservices.EnsureOpenVPNCA(pkiDir)
		if err != nil {
			internalError(c, err)
			return
		}
		_, _, _ = cpservices.EnsureOpenVPNServerCert(pkiDir, caCertPath, caKeyPath)
		clientCertPath, clientKeyPath, err := cpservices.EnsureOpenVPNClientCert(pkiDir, caCertPath, caKeyPath, name)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		caPEM, err := os.ReadFile(caCertPath)
		if err != nil {
			internalError(c, err)
			return
		}
		certPEM, err := os.ReadFile(clientCertPath)
		if err != nil {
			internalError(c, err)
			return
		}
		keyPEM, err := os.ReadFile(clientKeyPath)
		if err != nil {
			internalError(c, err)
			return
		}

		var b strings.Builder
		b.WriteString("client\n")
		b.WriteString("dev tun\n")
		b.WriteString("nobind\n")
		b.WriteString("persist-key\n")
		b.WriteString("persist-tun\n")
		b.WriteString("remote " + publicEndpoint + " " + strconv.Itoa(port) + "\n")
		if proto == "tcp" {
			b.WriteString("proto tcp-client\n")
		} else {
			b.WriteString("proto udp\n")
		}
		b.WriteString("remote-cert-tls server\n")
		b.WriteString("verb 3\n")
		writeInlineBlock(&b, "ca", caPEM)
		writeInlineBlock(&b, "cert", certPEM)
		writeInlineBlock(&b, "key", keyPEM)

		clientName := strings.TrimSuffix(filepath.Base(clientCertPath), ".crt")
		auditLog(c, audit.Record{Action: "services.vpn.openvpn.client.download", Target: clientName})
		c.Header("Content-Type", "application/x-openvpn-profile")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", clientName+".ovpn"))
		c.String(http.StatusOK, b.String())
	}
}

func writeInlineBlock(b *strings.Builder, tag string, pemBytes []byte) {
	b.WriteString("<" + tag + ">\n")
	b.Write(pemBytes)
	if len(pemBytes) == 0 || pemBytes[len(pemBytes)-1] != '\n' {
		b.WriteString("\n")
	}
	b.WriteString("</" + tag + ">\n")
}

func getWireGuardStatusHandler(engine any) gin.HandlerFunc {
	return func(c *gin.Context) {
		cl, ok := engine.(WireGuardStatusClient)
		if !ok || cl == nil {
			apiError(c, http.StatusServiceUnavailable, "engine wireguard status not available")
			return
		}
		iface := strings.TrimSpace(c.Query("iface"))
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		st, err := cl.GetWireGuardStatus(ctx, iface)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		c.JSON(http.StatusOK, st)
	}
}

func getForwardProxyHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Services.Proxy.Forward)
	}
}

func setForwardProxyHandler(store config.Store, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var forwardCfg config.ForwardProxyConfig
		if err := c.ShouldBindJSON(&forwardCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		cfg.Services.Proxy.Forward = forwardCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		setWarningHeader(c, applyServiceRuntime(c.Request.Context(), cfg.Services, services, nil))
		auditLog(c, audit.Record{Action: "services.proxy.forward.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.Services.Proxy.Forward)
	}
}

func getReverseProxyHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Services.Proxy.Reverse)
	}
}

func setReverseProxyHandler(store config.Store, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var reverseCfg config.ReverseProxyConfig
		if err := c.ShouldBindJSON(&reverseCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		cfg.Services.Proxy.Reverse = reverseCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		setWarningHeader(c, applyServiceRuntime(c.Request.Context(), cfg.Services, services, nil))
		auditLog(c, audit.Record{Action: "services.proxy.reverse.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.Services.Proxy.Reverse)
	}
}

func getServicesStatusHandler(services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		if services == nil {
			c.JSON(http.StatusOK, gin.H{"status": "unavailable"})
			return
		}
		if s, ok := services.(interface{ Status() any }); ok {
			c.JSON(http.StatusOK, s.Status())
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "unknown"})
	}
}

func listEventsHandler(engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := 500
		if q := c.Query("limit"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 5000 {
				limit = v
			}
		}

		out := []dpevents.Event{}
		var engineErr error

		if tc, ok := engine.(TelemetryClient); ok && tc != nil {
			evs, err := tc.ListEvents(c.Request.Context(), limit)
			if err != nil {
				engineErr = err
			} else {
				out = append(out, evs...)
			}
		}

		if s, ok := services.(interface {
			ListTelemetryEvents(limit int) []dpevents.Event
		}); ok && s != nil {
			out = append(out, s.ListTelemetryEvents(limit)...)
		}

		if engineErr != nil && len(out) > 0 {
			// Surface the error as a synthetic event so operators can see it in the UI.
			out = append(out, dpevents.Event{
				Proto:     "system",
				Kind:      "system.engine.telemetry_error",
				Timestamp: time.Now().UTC(),
				Attributes: map[string]any{
					"error": engineErr.Error(),
				},
			})
		}

		sort.Slice(out, func(i, j int) bool {
			return out[i].Timestamp.After(out[j].Timestamp)
		})
		if limit > 0 && len(out) > limit {
			out = out[:limit]
		}
		c.JSON(http.StatusOK, out)
	}
}

func eventDetailHandler(engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		idStr := c.Param("id")
		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			apiError(c, http.StatusBadRequest, "invalid event ID")
			return
		}

		var all []dpevents.Event
		if tc, ok := engine.(TelemetryClient); ok && tc != nil {
			evs, err := tc.ListEvents(c.Request.Context(), 5000)
			if err == nil {
				all = append(all, evs...)
			}
		}
		if s, ok := services.(interface {
			ListTelemetryEvents(limit int) []dpevents.Event
		}); ok && s != nil {
			all = append(all, s.ListTelemetryEvents(5000)...)
		}

		for _, ev := range all {
			if ev.ID == id {
				c.JSON(http.StatusOK, ev)
				return
			}
		}
		apiError(c, http.StatusNotFound, "event not found")
	}
}

func listFlowsHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		tc, ok := engine.(TelemetryClient)
		if !ok || tc == nil {
			c.JSON(http.StatusOK, []dpevents.FlowSummary{})
			return
		}
		limit := 200
		if q := c.Query("limit"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 5000 {
				limit = v
			}
		}
		flows, err := tc.ListFlows(c.Request.Context(), limit)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		if flows == nil {
			flows = []dpevents.FlowSummary{}
		}
		c.JSON(http.StatusOK, flows)
	}
}

func simulationStatusHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(SimulationClient)
		if !ok || sc == nil {
			c.JSON(http.StatusOK, engineclient.SimulationStatus{Running: false})
			return
		}
		st, err := sc.SimulationStatus(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		c.JSON(http.StatusOK, st)
	}
}

func simulationControlHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(SimulationClient)
		if !ok || sc == nil {
			apiError(c, http.StatusBadRequest, "simulation unavailable")
			return
		}
		var req struct {
			Action string `json:"action"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || (req.Action != "start" && req.Action != "stop") {
			apiError(c, http.StatusBadRequest, `action must be "start" or "stop"`)
			return
		}
		st, err := sc.SimulationControl(c.Request.Context(), req.Action)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "simulation." + req.Action, Target: "synth"})
		c.JSON(http.StatusOK, st)
	}
}

func protoStatsHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(StatsClient)
		if !ok || sc == nil {
			c.JSON(http.StatusOK, []stats.ProtoStats{})
			return
		}
		result, err := sc.ListProtoStats(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		if result == nil {
			result = []stats.ProtoStats{}
		}
		c.JSON(http.StatusOK, result)
	}
}

func topTalkersHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(StatsClient)
		if !ok || sc == nil {
			c.JSON(http.StatusOK, []stats.FlowStats{})
			return
		}
		n := 10
		if q := c.Query("n"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 1000 {
				n = v
			}
		}
		result, err := sc.ListTopTalkers(c.Request.Context(), n)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		if result == nil {
			result = []stats.FlowStats{}
		}
		c.JSON(http.StatusOK, result)
	}
}

func listAnomaliesHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		ac, ok := engine.(AnomalyClient)
		if !ok || ac == nil {
			c.JSON(http.StatusOK, []anomaly.Anomaly{})
			return
		}
		limit := 200
		if q := c.Query("limit"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 5000 {
				limit = v
			}
		}
		anomalies, err := ac.ListAnomalies(c.Request.Context(), limit)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		if anomalies == nil {
			anomalies = []anomaly.Anomaly{}
		}
		c.JSON(http.StatusOK, anomalies)
	}
}

func clearAnomaliesHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		ac, ok := engine.(AnomalyClient)
		if !ok || ac == nil {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
			return
		}
		if err := ac.ClearAnomalies(c.Request.Context()); err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

func listConntrackHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		cc, ok := engine.(ConntrackClient)
		if !ok || cc == nil {
			c.JSON(http.StatusOK, []conntrack.Entry{})
			return
		}
		limit := 200
		if q := c.Query("limit"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v > 0 {
				limit = v
			}
		}
		ents, err := cc.ListConntrack(c.Request.Context(), limit)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		c.JSON(http.StatusOK, ents)
	}
}

func killConntrackHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		ck, ok := engine.(ConntrackKiller)
		if !ok || ck == nil {
			apiError(c, http.StatusNotImplemented, "conntrack delete not supported")
			return
		}
		var req conntrack.DeleteRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		if err := ck.DeleteConntrack(c.Request.Context(), req); err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "conntrack.delete", Target: "dataplane"})
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	}
}

func getDataPlaneHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.DataPlane)
	}
}

func getRulesetPreviewHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		snap, err := compile.CompileSnapshot(cfg)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		comp := enforce.NewCompiler()
		ruleset, err := comp.CompileFirewall(&snap)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}

		resp := gin.H{
			"snapshot": snap,
			"ruleset":  ruleset,
		}
		if engine != nil {
			type rulesetStatusClient interface {
				RulesetStatus(ctx context.Context) (dpengine.RulesetStatus, error)
			}
			if ec, ok := engine.(rulesetStatusClient); ok && ec != nil {
				if st, err := ec.RulesetStatus(c.Request.Context()); err == nil {
					resp["engineStatus"] = st
				} else {
					resp["engineStatusError"] = err.Error()
				}
			}
		}
		c.JSON(http.StatusOK, resp)
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

func blockHostHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		var req blockHostRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		ip := net.ParseIP(strings.TrimSpace(req.IP))
		if ip == nil || ip.To4() == nil {
			apiError(c, http.StatusBadRequest, "invalid ip")
			return
		}
		if req.TTLSeconds < 0 {
			apiError(c, http.StatusBadRequest, "ttlSeconds must be >= 0")
			return
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		if err := engine.BlockHostTemp(c.Request.Context(), ip, ttl); err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "dataplane.block_host", Target: ip.String()})
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

func blockFlowHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		var req blockFlowRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		srcIP := net.ParseIP(strings.TrimSpace(req.SrcIP))
		dstIP := net.ParseIP(strings.TrimSpace(req.DstIP))
		if srcIP == nil || srcIP.To4() == nil || dstIP == nil || dstIP.To4() == nil {
			apiError(c, http.StatusBadRequest, "invalid flow ip")
			return
		}
		if strings.TrimSpace(req.Proto) == "" || strings.TrimSpace(req.DstPort) == "" {
			apiError(c, http.StatusBadRequest, "proto and dstPort required")
			return
		}
		if req.TTLSeconds < 0 {
			apiError(c, http.StatusBadRequest, "ttlSeconds must be >= 0")
			return
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		if err := engine.BlockFlowTemp(c.Request.Context(), srcIP, dstIP, strings.ToLower(strings.TrimSpace(req.Proto)), strings.TrimSpace(req.DstPort), ttl); err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "dataplane.block_flow", Target: fmt.Sprintf("%s->%s", srcIP, dstIP)})
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

func getIDSHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		rules, err := store.LoadIDSRules(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		resp := cfg.IDS
		resp.Rules = rules
		c.JSON(http.StatusOK, resp)
	}
}

func setIDSHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var idsCfg config.IDSConfig
		if err := c.ShouldBindJSON(&idsCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		// Save rules to separate storage.
		if err := store.SaveIDSRules(c.Request.Context(), idsCfg.Rules); err != nil {
			apiError(c, http.StatusInternalServerError, err.Error())
			return
		}
		// Save IDS settings (enabled, rule groups) in config without rules.
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		cfg.IDS.Enabled = idsCfg.Enabled
		cfg.IDS.RuleGroups = idsCfg.RuleGroups
		cfg.IDS.Rules = nil // rules are in separate storage
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		// Push updated rules to the engine so IDS evaluation takes effect immediately.
		_, _ = applyRunningConfig(c.Request.Context(), store, engine, services)
		auditLog(c, audit.Record{Action: "ids.rules.set", Target: "running"})
		idsCfg.Rules = nil // don't echo all rules back
		c.JSON(http.StatusOK, idsCfg)
	}
}

func convertSigmaHandler() gin.HandlerFunc {
	type req struct {
		SigmaYAML string `json:"sigmaYAML"`
	}
	return func(c *gin.Context) {
		var r req
		if err := c.ShouldBindJSON(&r); err != nil || r.SigmaYAML == "" {
			apiError(c, http.StatusBadRequest, "missing sigmaYAML")
			return
		}
		rule, err := cpids.ConvertSigmaYAML([]byte(r.SigmaYAML))
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, rule)
	}
}

// idsImportHandler accepts rules in any supported format and merges them into
// the IDS configuration.  Body is multipart form: "file" (the rule file) and
// "format" (suricata|snort|yara|sigma, optional — auto-detected if omitted).
func idsImportHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		file, header, err := c.Request.FormFile("file")
		if err != nil {
			apiError(c, http.StatusBadRequest, "missing file upload")
			return
		}
		defer file.Close()

		data, err := io.ReadAll(file)
		if err != nil {
			apiError(c, http.StatusBadRequest, "failed to read file")
			return
		}

		format := c.PostForm("format")
		if format == "" {
			format = cpids.DetectFormat(header.Filename, data)
		}
		if format == "" {
			apiError(c, http.StatusBadRequest, "could not detect rule format; specify format parameter")
			return
		}

		rules, err := cpids.ImportRules(data, format)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}

		// Merge into existing rules (stored separately from config).
		existingRules, err := store.LoadIDSRules(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		existing := make(map[string]bool, len(existingRules))
		for _, r := range existingRules {
			existing[r.ID] = true
		}
		added := 0
		skipped := 0
		for _, r := range rules {
			if existing[r.ID] {
				skipped++
				continue
			}
			existingRules = append(existingRules, r)
			existing[r.ID] = true
			added++
		}
		if err := store.SaveIDSRules(c.Request.Context(), existingRules); err != nil {
			apiError(c, http.StatusInternalServerError, err.Error())
			return
		}
		_, _ = applyRunningConfig(c.Request.Context(), store, engine, services)
		auditLog(c, audit.Record{Action: "ids.rules.import", Target: format})

		c.JSON(http.StatusOK, gin.H{
			"imported": added,
			"skipped":  skipped,
			"total":    len(existingRules),
			"format":   format,
		})
	}
}

// idsExportHandler exports current rules in the requested format.
// Query param: ?format=suricata|snort|yara|sigma
func idsExportHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		format := c.Query("format")
		if format == "" {
			format = "suricata"
		}

		rules, err := store.LoadIDSRules(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		data, err := cpids.ExportRules(rules, format)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}

		ext := map[string]string{
			"suricata": ".rules", "snort": ".rules",
			"yara": ".yar", "sigma": ".yml",
		}
		contentType := "text/plain; charset=utf-8"
		if format == "sigma" {
			contentType = "text/yaml; charset=utf-8"
		}

		now := time.Now()
		dateStr := fmt.Sprintf("%02d%02d%02d", now.Year()%100, now.Month(), now.Day())
		filename := fmt.Sprintf("%s-%s%s", format, dateStr, ext[format])
		c.Header("Content-Disposition", "attachment; filename="+filename)
		c.Data(http.StatusOK, contentType, data)
	}
}

// idsSourcesHandler returns the catalog of external rule sources.
func idsSourcesHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, cpids.BuiltinSources)
	}
}

// idsBackupHandler exports all IDS rules as a standalone JSON file.
func idsBackupHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		rules, err := store.LoadIDSRules(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		c.Header("Content-Disposition", "attachment; filename=containd-ids-rules.json")
		c.JSON(http.StatusOK, rules)
	}
}

// idsRestoreHandler replaces all IDS rules from an uploaded JSON file.
func idsRestoreHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		const maxSize = 50 << 20 // 50 MB — rule sets can be large
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxSize+1))
		if err != nil {
			apiError(c, http.StatusBadRequest, "failed to read body")
			return
		}
		if int64(len(body)) > maxSize {
			apiError(c, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		var rules []config.IDSRule
		if err := json.Unmarshal(body, &rules); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		if err := store.SaveIDSRules(c.Request.Context(), rules); err != nil {
			internalError(c, err)
			return
		}
		_, _ = applyRunningConfig(c.Request.Context(), store, engine, services)
		auditLog(c, audit.Record{Action: "ids.rules.restore", Target: "running"})
		c.JSON(http.StatusOK, gin.H{"status": "restored", "count": len(rules)})
	}
}

func cliExecuteHandler(store config.Store) gin.HandlerFunc {
	type req struct {
		Line string `json:"line"`
	}
	type resp struct {
		Output string `json:"output"`
		Error  string `json:"error,omitempty"`
	}
	return func(c *gin.Context) {
		var r req
		if err := c.ShouldBindJSON(&r); err != nil {
			apiError(c, http.StatusBadRequest, "invalid JSON")
			return
		}
		// Treat blank input as a no-op; the UI console may send empty lines.
		if strings.TrimSpace(r.Line) == "" {
			c.JSON(http.StatusOK, resp{Output: ""})
			return
		}
		ctx, reg := cliRegistryForRequest(c, store)
		var buf bytes.Buffer
		if err := reg.ParseAndExecute(ctx, r.Line, &buf); err != nil {
			c.JSON(http.StatusOK, resp{Output: buf.String(), Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, resp{Output: buf.String()})
	}
}

func cliCommandsHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, reg := cliRegistryForRequest(c, store)
		role := cli.RoleView
		if strings.EqualFold(c.GetString(ctxRoleKey), string(cli.RoleAdmin)) {
			role = cli.RoleAdmin
		}
		c.JSON(http.StatusOK, reg.CommandsForRole(role))
	}
}

func cliCompleteHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		line := c.Query("line")
		if strings.TrimSpace(line) == "" {
			c.JSON(http.StatusOK, []string{})
			return
		}
		tokens, err := shellquote.Split(line)
		if err != nil {
			c.JSON(http.StatusOK, []string{})
			return
		}
		if strings.HasSuffix(line, " ") {
			tokens = append(tokens, "")
		}
		_, reg := cliRegistryForRequest(c, store)
		role := cli.RoleView
		if strings.EqualFold(c.GetString(ctxRoleKey), string(cli.RoleAdmin)) {
			role = cli.RoleAdmin
		}
		cmds := reg.CommandsForRole(role)
		cmdName, args := matchCommandTokens(tokens, cmds)
		if cmdName == "" {
			c.JSON(http.StatusOK, []string{})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusOK, []string{})
			return
		}
		suggestions := completeCLIArgs(cmdName, args, cfg, cmds)
		c.JSON(http.StatusOK, suggestions)
	}
}

func cliWSHandler(store config.Store) gin.HandlerFunc {
	type req struct {
		Line string `json:"line"`
	}
	type resp struct {
		Output string `json:"output"`
		Error  string `json:"error,omitempty"`
	}
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin == "" {
				return false
			}
			u, err := url.Parse(origin)
			if err != nil || u.Host == "" {
				return false
			}
			return strings.EqualFold(u.Host, r.Host)
		},
	}
	return func(c *gin.Context) {
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		ctx, reg := cliRegistryForRequest(c, store)
		_ = conn.WriteJSON(resp{Output: "containd in-app CLI. Type 'show version'."})
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			line := strings.TrimSpace(string(msg))
			if strings.HasPrefix(line, "{") {
				var r req
				if err := json.Unmarshal(msg, &r); err == nil && strings.TrimSpace(r.Line) != "" {
					line = r.Line
				}
			}
			if strings.TrimSpace(line) == "" {
				_ = conn.WriteJSON(resp{Output: ""})
				continue
			}
			var buf bytes.Buffer
			if err := reg.ParseAndExecute(ctx, line, &buf); err != nil {
				_ = conn.WriteJSON(resp{Output: buf.String(), Error: err.Error()})
				continue
			}
			_ = conn.WriteJSON(resp{Output: buf.String()})
		}
	}
}

func cliRegistryForRequest(c *gin.Context, store config.Store) (context.Context, *cli.Registry) {
	loopbackHostPort := func(addr string, defaultPort string) string {
		addr = strings.TrimSpace(addr)
		port := defaultPort
		if addr == "" {
			return "127.0.0.1:" + port
		}
		if strings.HasPrefix(addr, ":") {
			if p := strings.TrimSpace(strings.TrimPrefix(addr, ":")); p != "" {
				port = p
			}
			return "127.0.0.1:" + port
		}
		if _, p, err := net.SplitHostPort(addr); err == nil && strings.TrimSpace(p) != "" {
			port = strings.TrimSpace(p)
		}
		return "127.0.0.1:" + port
	}

	// Prefer an in-process loopback URL rather than reusing the incoming
	// request Host/scheme. This avoids:
	// - HTTPS self-signed verification errors for internal calls
	// - SSRF-style token exfiltration via crafted Host headers
	baseURL := ""
	var httpClient cli.HTTPClient
	if cfg, err := store.Load(c.Request.Context()); err == nil && cfg != nil {
		enableHTTP := cfg.System.Mgmt.EnableHTTP == nil || *cfg.System.Mgmt.EnableHTTP
		enableHTTPS := cfg.System.Mgmt.EnableHTTPS == nil || *cfg.System.Mgmt.EnableHTTPS

		httpAddr := firstNonEmpty(cfg.System.Mgmt.HTTPListenAddr, cfg.System.Mgmt.ListenAddr, ":8080")
		httpsAddr := firstNonEmpty(cfg.System.Mgmt.HTTPSListenAddr, ":8443")

		// Always prefer HTTP for internal calls when enabled.
		if enableHTTP {
			baseURL = "http://" + loopbackHostPort(httpAddr, "8080")
		} else if enableHTTPS {
			baseURL = "https://" + loopbackHostPort(httpsAddr, "8443")
			httpClient = &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
		}
	}
	if baseURL == "" {
		// Fallback (should be rare): infer from the request and keep the current Host.
		scheme := "http"
		if c.Request.TLS != nil {
			scheme = "https"
		}
		if proto := strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")); proto != "" {
			proto = strings.ToLower(strings.TrimSpace(strings.Split(proto, ",")[0]))
			if proto == "http" || proto == "https" {
				scheme = proto
			}
		}
		baseURL = scheme + "://" + c.Request.Host
	}
	apiClient := &cli.API{BaseURL: baseURL}
	if httpClient != nil {
		apiClient.Client = httpClient
	}
	// Pass through the caller's bearer token so in-app console commands
	// can access the same protected endpoints as the UI session.
	if tok := strings.TrimSpace(bearerOrCookie(c)); tok != "" {
		apiClient.Token = tok
	}
	ctx := cli.WithRole(c.Request.Context(), c.GetString(ctxRoleKey))
	reg := cli.NewRegistry(store, apiClient)
	return ctx, reg
}

func matchCommandTokens(tokens []string, available []string) (string, []string) {
	if len(tokens) == 0 {
		return "", nil
	}
	tokensForMatch := tokens
	if len(tokensForMatch) > 0 && tokensForMatch[len(tokensForMatch)-1] == "" {
		tokensForMatch = tokensForMatch[:len(tokensForMatch)-1]
	}
	availSet := map[string]struct{}{}
	for _, a := range available {
		availSet[a] = struct{}{}
	}
	for i := len(tokensForMatch); i > 0; i-- {
		candidate := strings.ToLower(strings.Join(tokensForMatch[:i], " "))
		if _, ok := availSet[candidate]; ok {
			args := tokensForMatch[i:]
			if len(tokens) > 0 && tokens[len(tokens)-1] == "" {
				args = append(args, "")
			}
			return candidate, args
		}
	}
	return "", nil
}

func completeCLIArgs(cmd string, args []string, cfg *config.Config, allCommands []string) []string {
	prefix := ""
	if len(args) > 0 {
		prefix = args[len(args)-1]
	}
	argIndex := len(args) - 1
	prev := ""
	if len(args) >= 2 {
		prev = strings.ToLower(strings.TrimSpace(args[len(args)-2]))
	}
	ifaces := interfaceNames(cfg)
	zones := zoneNames(cfg)
	rules := firewallRuleIDs(cfg)
	portForwards := portForwardIDs(cfg)
	gateways := gatewayAddresses(cfg)
	switch cmd {
	case "help":
		if argIndex == 0 {
			return filterPrefix(allCommands, prefix)
		}
	case "show help":
		if argIndex == 0 {
			return filterPrefix(filterCommandPrefix(allCommands, "show "), prefix)
		}
	case "set help":
		if argIndex == 0 {
			return filterPrefix(filterCommandPrefix(allCommands, "set "), prefix)
		}
	case "set zone":
		if argIndex == 0 {
			return filterPrefix(zones, prefix)
		}
	case "set interface":
		if argIndex == 0 {
			return filterPrefix(ifaces, prefix)
		}
		if argIndex == 1 {
			return filterPrefix(zones, prefix)
		}
		if argIndex >= 2 {
			return filterPrefix([]string{"<cidr...>", "none"}, prefix)
		}
	case "set interface ip":
		if argIndex == 0 {
			return filterPrefix(ifaces, prefix)
		}
		if argIndex == 1 {
			return filterPrefix([]string{"static", "dhcp", "none"}, prefix)
		}
		if argIndex >= 2 && len(args) >= 2 && strings.EqualFold(strings.TrimSpace(args[1]), "static") {
			return filterPrefix([]string{"<cidr>", "[gateway]"}, prefix)
		}
	case "set interface zone":
		if argIndex == 0 {
			return filterPrefix(ifaces, prefix)
		}
		if argIndex == 1 {
			return filterPrefix(zones, prefix)
		}
	case "set interface bind":
		if argIndex == 0 {
			return filterPrefix(ifaces, prefix)
		}
	case "set interface bridge":
		if argIndex == 0 {
			return filterPrefix(ifaces, prefix)
		}
		if argIndex == 1 {
			return filterPrefix(zones, prefix)
		}
		if argIndex == 2 {
			if len(ifaces) > 0 {
				return filterPrefix(ifaces, prefix)
			}
			return filterPrefix([]string{"<members_csv>"}, prefix)
		}
		if argIndex >= 3 {
			return filterPrefix([]string{"<cidr...>"}, prefix)
		}
	case "set interface vlan":
		if argIndex == 0 {
			return filterPrefix(ifaces, prefix)
		}
		if argIndex == 1 {
			return filterPrefix(zones, prefix)
		}
		if argIndex == 2 {
			return filterPrefix(ifaces, prefix)
		}
		if argIndex == 3 {
			return filterPrefix([]string{"<vlan_id>"}, prefix)
		}
		if argIndex >= 4 {
			return filterPrefix([]string{"<cidr...>"}, prefix)
		}
	case "assign interfaces":
		if argIndex >= 0 {
			suggestions := append([]string{"auto"}, ifaceAssignHints(ifaces)...)
			return filterPrefix(suggestions, prefix)
		}
	case "set firewall rule":
		if argIndex == 0 {
			return filterPrefix(rules, prefix)
		}
		if argIndex == 1 {
			return filterPrefix([]string{"ALLOW", "DENY", "allow", "deny"}, prefix)
		}
		if argIndex == 2 || argIndex == 3 {
			return filterPrefix(zones, prefix)
		}
	case "delete firewall rule":
		if argIndex == 0 {
			return filterPrefix(rules, prefix)
		}
	case "set port-forward del", "set port-forward enable", "set port-forward disable":
		if argIndex == 0 {
			return filterPrefix(portForwards, prefix)
		}
	case "set port-forward add":
		if argIndex == 1 {
			return filterPrefix(zones, prefix)
		}
		if argIndex == 2 {
			return filterPrefix([]string{"tcp", "udp"}, prefix)
		}
		if prev == "sources" {
			return filterPrefix([]string{"<cidr1,cidr2>"}, prefix)
		}
		if prev == "desc" {
			return filterPrefix([]string{"<text>"}, prefix)
		}
	case "set dataplane":
		if argIndex == 0 {
			return filterPrefix([]string{"enforcement"}, prefix)
		}
		if argIndex == 1 && strings.EqualFold(strings.TrimSpace(args[0]), "enforcement") {
			return filterPrefix([]string{"on", "off", "true", "false"}, prefix)
		}
		if argIndex >= 3 && strings.EqualFold(strings.TrimSpace(args[0]), "enforcement") {
			return filterPrefix(ifaces, prefix)
		}
	case "set proxy forward":
		if argIndex == 0 {
			return filterPrefix([]string{"on", "off", "true", "false"}, prefix)
		}
		if argIndex >= 2 {
			return filterPrefix(zones, prefix)
		}
	case "set proxy reverse":
		if argIndex == 0 {
			return filterPrefix([]string{"on", "off", "true", "false"}, prefix)
		}
	case "set nat":
		if argIndex == 0 {
			return filterPrefix([]string{"on", "off"}, prefix)
		}
		if prev == "egress" {
			if len(zones) > 0 {
				return filterPrefix(append([]string{"default"}, zones...), prefix)
			}
			return filterPrefix([]string{"default", "<zone>"}, prefix)
		}
		if prev == "sources" {
			if len(zones) > 0 {
				return filterPrefix(append([]string{"default"}, zones...), prefix)
			}
			return filterPrefix([]string{"default", "<zone1,zone2>"}, prefix)
		}
		return filterPrefix(append([]string{"egress", "sources"}, zones...), prefix)
	case "diag reach":
		if argIndex == 0 {
			return filterPrefix(ifaces, prefix)
		}
		if argIndex == 2 {
			return filterPrefix([]string{"tcp", "udp", "icmp"}, prefix)
		}
	case "diag capture":
		if argIndex == 0 {
			return filterPrefix(ifaces, prefix)
		}
	case "set route add", "set route del":
		if argIndex == 0 {
			return filterPrefix([]string{"default", "<dst>"}, prefix)
		}
		if prev == "via" || prev == "gw" || prev == "gateway" {
			if len(gateways) > 0 {
				return filterPrefix(gateways, prefix)
			}
			return filterPrefix([]string{"<gw>"}, prefix)
		}
		if prev == "dev" || prev == "iface" {
			return filterPrefix(ifaces, prefix)
		}
		return filterPrefix([]string{"via", "dev", "iface", "table", "metric", "gw", "gateway"}, prefix)
	case "set ip rule add":
		if argIndex == 0 {
			return filterPrefix([]string{"<table>"}, prefix)
		}
		if prev == "src" {
			return filterPrefix([]string{"<cidr>"}, prefix)
		}
		if prev == "dst" {
			return filterPrefix([]string{"<cidr>"}, prefix)
		}
		if prev == "priority" {
			return filterPrefix([]string{"<n>"}, prefix)
		}
		return filterPrefix([]string{"src", "dst", "priority"}, prefix)
	case "set ip rule del":
		if argIndex == 0 {
			return filterPrefix([]string{"<table>"}, prefix)
		}
		if prev == "src" {
			return filterPrefix([]string{"<cidr>"}, prefix)
		}
		if prev == "dst" {
			return filterPrefix([]string{"<cidr>"}, prefix)
		}
		if prev == "priority" {
			return filterPrefix([]string{"<n>"}, prefix)
		}
		return filterPrefix([]string{"src", "dst", "priority", "all"}, prefix)
	case "set syslog format":
		if argIndex == 0 {
			return filterPrefix([]string{"rfc5424", "json"}, prefix)
		}
	case "set syslog forwarder add":
		if argIndex == 0 {
			return filterPrefix([]string{"<address>"}, prefix)
		}
		if argIndex == 1 {
			return filterPrefix([]string{"<port>"}, prefix)
		}
		if argIndex == 2 {
			return filterPrefix([]string{"udp", "tcp"}, prefix)
		}
	case "set syslog forwarder del":
		if argIndex == 0 {
			return filterPrefix([]string{"<address>"}, prefix)
		}
		if argIndex == 1 {
			return filterPrefix([]string{"<port>"}, prefix)
		}
	}
	if hints := usageHints(cmd, argIndex, args); len(hints) > 0 {
		return filterPrefix(hints, prefix)
	}
	return nil
}

func filterPrefix(candidates []string, prefix string) []string {
	if len(candidates) == 0 {
		return nil
	}
	needle := strings.ToLower(strings.TrimSpace(prefix))
	seen := map[string]struct{}{}
	out := make([]string, 0, len(candidates))
	for _, cand := range candidates {
		c := strings.TrimSpace(cand)
		if c == "" {
			continue
		}
		if needle != "" && !strings.HasPrefix(strings.ToLower(c), needle) {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func interfaceNames(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		if strings.TrimSpace(iface.Name) != "" {
			out = append(out, iface.Name)
		}
	}
	return out
}

func zoneNames(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Zones))
	for _, z := range cfg.Zones {
		if strings.TrimSpace(z.Name) != "" {
			out = append(out, z.Name)
		}
	}
	return out
}

func firewallRuleIDs(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Firewall.Rules))
	for _, r := range cfg.Firewall.Rules {
		if strings.TrimSpace(r.ID) != "" {
			out = append(out, r.ID)
		}
	}
	return out
}

func portForwardIDs(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Firewall.NAT.PortForwards))
	for _, pf := range cfg.Firewall.NAT.PortForwards {
		if strings.TrimSpace(pf.ID) != "" {
			out = append(out, pf.ID)
		}
	}
	return out
}

func gatewayAddresses(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Routing.Gateways))
	for _, gw := range cfg.Routing.Gateways {
		if strings.TrimSpace(gw.Address) != "" {
			out = append(out, gw.Address)
		}
	}
	return out
}

func ifaceAssignHints(ifaces []string) []string {
	out := make([]string, 0, len(ifaces))
	for _, name := range ifaces {
		if strings.TrimSpace(name) == "" {
			continue
		}
		out = append(out, name+"=")
	}
	return out
}

func filterCommandPrefix(commands []string, prefix string) []string {
	out := make([]string, 0, len(commands))
	for _, cmd := range commands {
		if strings.HasPrefix(cmd, prefix) {
			out = append(out, cmd)
		}
	}
	return out
}

func usageHints(cmd string, argIndex int, args []string) []string {
	switch cmd {
	case "convert sigma":
		if argIndex == 0 {
			return []string{"<sigma.yml>"}
		}
	case "factory reset":
		if argIndex == 0 {
			return []string{"NUCLEAR"}
		}
	case "commit confirmed":
		if argIndex == 0 {
			return []string{"<ttl_seconds>"}
		}
	case "import config":
		if argIndex == 0 {
			return []string{"<path>"}
		}
	case "export config":
		if argIndex == 0 {
			return []string{"<path>"}
		}
	case "diag ping":
		if argIndex == 0 {
			return []string{"<host>"}
		}
		if argIndex == 1 {
			return []string{"[count]"}
		}
	case "diag traceroute":
		if argIndex == 0 {
			return []string{"<host>"}
		}
		if argIndex == 1 {
			return []string{"[max_hops]"}
		}
	case "diag tcptraceroute":
		if argIndex == 0 {
			return []string{"<host>"}
		}
		if argIndex == 1 {
			return []string{"<port>"}
		}
		if argIndex == 2 {
			return []string{"[max_hops]"}
		}
	case "diag reach":
		if argIndex == 0 {
			return []string{"<src_iface>"}
		}
		if argIndex == 1 {
			return []string{"<dst_host|dst_ip|dst_iface>"}
		}
		if argIndex == 2 {
			return []string{"tcp", "udp", "icmp", "[tcp_port]"}
		}
		if argIndex == 3 {
			return []string{"[port]"}
		}
	case "diag capture":
		if argIndex == 0 {
			return []string{"<iface>"}
		}
		if argIndex == 1 {
			return []string{"[seconds]"}
		}
		if argIndex == 2 {
			return []string{"[file]"}
		}
	case "diag routing reconcile", "diag interfaces reconcile":
		if argIndex == 0 {
			return []string{"REPLACE"}
		}
	case "set syslog format":
		if argIndex == 0 {
			return []string{"rfc5424", "json"}
		}
	case "set syslog forwarder add":
		if argIndex == 0 {
			return []string{"<address>"}
		}
		if argIndex == 1 {
			return []string{"<port>"}
		}
		if argIndex == 2 {
			return []string{"udp", "tcp"}
		}
	case "set syslog forwarder del":
		if argIndex == 0 {
			return []string{"<address>"}
		}
		if argIndex == 1 {
			return []string{"<port>"}
		}
	case "set system hostname":
		if argIndex == 0 {
			return []string{"<name>"}
		}
	case "set system mgmt listen":
		if argIndex == 0 {
			return []string{"<addr>"}
		}
	case "set system mgmt http listen":
		if argIndex == 0 {
			return []string{"<addr>"}
		}
	case "set system mgmt https listen":
		if argIndex == 0 {
			return []string{"<addr>"}
		}
	case "set system mgmt http enable":
		if argIndex == 0 {
			return []string{"true", "false"}
		}
	case "set system mgmt https enable":
		if argIndex == 0 {
			return []string{"true", "false"}
		}
	case "set system mgmt redirect-http-to-https":
		if argIndex == 0 {
			return []string{"true", "false"}
		}
	case "set system mgmt hsts":
		if argIndex == 0 {
			return []string{"true", "false"}
		}
		if argIndex == 1 {
			return []string{"[max_age_seconds]"}
		}
	case "set system ssh listen":
		if argIndex == 0 {
			return []string{"<addr>"}
		}
	case "set system ssh allow-password":
		if argIndex == 0 {
			return []string{"true", "false"}
		}
	case "set system ssh authorized-keys-dir":
		if argIndex == 0 {
			return []string{"<dir>"}
		}
	case "set interface ip":
		if argIndex == 2 && len(args) >= 2 && strings.EqualFold(strings.TrimSpace(args[1]), "static") {
			return []string{"<cidr>", "[gateway]"}
		}
	case "set interface bind":
		if argIndex == 1 {
			return []string{"<os_iface>"}
		}
	case "set interface bridge":
		if argIndex == 2 {
			return []string{"<members_csv>"}
		}
	case "set interface vlan":
		if argIndex == 3 {
			return []string{"<vlan_id>"}
		}
	case "set firewall rule":
		if argIndex == 0 {
			return []string{"<id>"}
		}
		if argIndex == 1 {
			return []string{"ALLOW", "DENY"}
		}
	case "delete firewall rule":
		if argIndex == 0 {
			return []string{"<id>"}
		}
	case "set port-forward add":
		if argIndex == 0 {
			return []string{"<id>"}
		}
		if argIndex == 2 {
			return []string{"tcp", "udp"}
		}
		if argIndex == 3 {
			return []string{"<listen_port>"}
		}
		if argIndex == 4 {
			return []string{"<dest_ip[:dest_port]>"}
		}
		if argIndex >= 5 {
			return []string{"sources", "desc", "off"}
		}
	case "set port-forward del", "set port-forward enable", "set port-forward disable":
		if argIndex == 0 {
			return []string{"<id>"}
		}
	case "set proxy forward":
		if argIndex == 0 {
			return []string{"on", "off", "true", "false"}
		}
		if argIndex == 1 {
			return []string{"[port]"}
		}
	case "set proxy reverse":
		if argIndex == 0 {
			return []string{"on", "off", "true", "false"}
		}
	case "set nat":
		if argIndex == 0 {
			return []string{"on", "off"}
		}
		if argIndex >= 1 {
			return []string{"egress", "sources"}
		}
	case "set dataplane":
		if argIndex == 0 {
			return []string{"enforcement"}
		}
		if argIndex == 1 {
			return []string{"on", "off", "true", "false"}
		}
		if argIndex == 2 {
			return []string{"[table]"}
		}
	case "set route add", "set route del":
		if argIndex == 0 {
			return []string{"default"}
		}
		if argIndex >= 1 {
			return []string{"via", "dev", "iface", "table", "metric", "gw", "gateway"}
		}
	case "set ip rule add":
		if argIndex >= 1 {
			return []string{"src", "dst", "priority"}
		}
	case "set ip rule del":
		if argIndex >= 1 {
			return []string{"src", "dst", "priority", "all"}
		}
	}
	return nil
}

func getFirewallNATHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Firewall.NAT)
	}
}

func setFirewallNATHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var nat config.NATConfig
		if err := c.ShouldBindJSON(&nat); err != nil {
			apiError(c, http.StatusBadRequest, "invalid NAT payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		cfg.Firewall.NAT = nat
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "firewall.nat.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.Firewall.NAT)
	}
}

func setDataPlaneHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		var dp config.DataPlaneConfig
		if err := c.ShouldBindJSON(&dp); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		cfg.DataPlane = dp
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		// Apply runtime dataplane changes immediately (including DPI inspect-all).
		if engine != nil {
			if err := engine.Configure(c.Request.Context(), cfg.DataPlane); err != nil {
				apiError(c, http.StatusBadGateway, err.Error())
				return
			}
		}
		auditLog(c, audit.Record{Action: "dataplane.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.DataPlane)
	}
}

func getPCAPConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			httpError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.PCAP)
	}
}

func setPCAPConfigHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req config.PCAPConfig
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			httpError(c, err)
			return
		}
		cfg.PCAP = req
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			httpError(c, err)
			return
		}
		if engine != nil {
			if _, err := engine.SetPcapConfig(c.Request.Context(), cfg.PCAP); err != nil {
				apiError(c, http.StatusBadRequest, err.Error())
				return
			}
		}
		auditLog(c, audit.Record{Action: "pcap.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.PCAP)
	}
}

func startPCAPHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			httpError(c, err)
			return
		}
		cfg.PCAP.Enabled = true
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			httpError(c, err)
			return
		}
		if engine == nil {
			c.JSON(http.StatusOK, gin.H{"status": "pcap start queued"})
			return
		}
		status, err := engine.StartPcap(c.Request.Context(), cfg.PCAP)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "pcap.start", Target: "running"})
		c.JSON(http.StatusOK, status)
	}
}

func stopPCAPHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			httpError(c, err)
			return
		}
		cfg.PCAP.Enabled = false
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			httpError(c, err)
			return
		}
		if engine == nil {
			c.JSON(http.StatusOK, gin.H{"status": "pcap stop queued"})
			return
		}
		status, err := engine.StopPcap(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "pcap.stop", Target: "running"})
		c.JSON(http.StatusOK, status)
	}
}

func getPCAPStatusHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			c.JSON(http.StatusOK, pcap.Status{Running: false})
			return
		}
		status, err := engine.PcapStatus(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, status)
	}
}

func getPCAPListHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			c.JSON(http.StatusOK, []pcap.Item{})
			return
		}
		items, err := engine.ListPcaps(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, items)
	}
}

func uploadPCAPHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		if err := c.Request.ParseMultipartForm(64 << 20); err != nil {
			apiError(c, http.StatusBadRequest, "invalid multipart form")
			return
		}
		file, header, err := c.Request.FormFile("file")
		if err != nil {
			apiError(c, http.StatusBadRequest, "file required")
			return
		}
		defer file.Close()
		// Validate PCAP/PCAPng magic bytes.
		var magic [4]byte
		if _, err := io.ReadFull(file, magic[:]); err != nil {
			apiError(c, http.StatusBadRequest, "file too small or unreadable")
			return
		}
		switch {
		case magic == [4]byte{0xd4, 0xc3, 0xb2, 0xa1}: // pcap LE
		case magic == [4]byte{0xa1, 0xb2, 0xc3, 0xd4}: // pcap BE
		case magic == [4]byte{0x0a, 0x0d, 0x0d, 0x0a}: // pcapng
		default:
			apiError(c, http.StatusBadRequest, "not a valid pcap/pcapng file")
			return
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			apiError(c, http.StatusInternalServerError, "failed to rewind file")
			return
		}
		item, err := engine.UploadPcap(c.Request.Context(), filepath.Base(header.Filename), file)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "pcap.upload", Target: item.Name})
		c.JSON(http.StatusOK, item)
	}
}

func downloadPCAPHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := strings.TrimSpace(c.Param("name"))
		if name == "" {
			apiError(c, http.StatusBadRequest, "name required")
			return
		}
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		resp, err := engine.DownloadPcap(c.Request.Context(), name)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		defer resp.Body.Close()
		c.Header("Content-Type", resp.Header.Get("Content-Type"))
		c.Header("Content-Length", resp.Header.Get("Content-Length"))
		c.Header("Content-Disposition", resp.Header.Get("Content-Disposition"))
		_, _ = io.Copy(c.Writer, resp.Body)
	}
}

func deletePCAPHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := strings.TrimSpace(c.Param("name"))
		if name == "" {
			apiError(c, http.StatusBadRequest, "name required")
			return
		}
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		if err := engine.DeletePcap(c.Request.Context(), name); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "pcap.delete", Target: name})
		c.Status(http.StatusNoContent)
	}
}

func tagPCAPHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		var req pcap.TagRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := engine.TagPcap(c.Request.Context(), req); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "pcap.tag", Target: req.Name})
		c.Status(http.StatusNoContent)
	}
}

func replayPCAPHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		var req pcap.ReplayRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := engine.ReplayPcap(c.Request.Context(), req); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "pcap.replay", Target: req.Name})
		c.Status(http.StatusAccepted)
	}
}

func analyzePCAPUploadHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := c.Request.ParseMultipartForm(64 << 20); err != nil {
			apiError(c, http.StatusBadRequest, "invalid multipart form")
			return
		}
		file, _, err := c.Request.FormFile("file")
		if err != nil {
			apiError(c, http.StatusBadRequest, "file required")
			return
		}
		defer file.Close()
		// Validate PCAP magic bytes.
		var magic [4]byte
		if _, err := io.ReadFull(file, magic[:]); err != nil {
			apiError(c, http.StatusBadRequest, "file too small or unreadable")
			return
		}
		switch {
		case magic == [4]byte{0xd4, 0xc3, 0xb2, 0xa1}: // pcap LE
		case magic == [4]byte{0xa1, 0xb2, 0xc3, 0xd4}: // pcap BE
		case magic == [4]byte{0x0a, 0x0d, 0x0d, 0x0a}: // pcapng
		default:
			apiError(c, http.StatusBadRequest, "not a valid pcap/pcapng file")
			return
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			apiError(c, http.StatusInternalServerError, "failed to rewind file")
			return
		}
		result, err := pcap.AnalyzeForPolicy(file, dpengine.DefaultDecoders()...)
		if err != nil {
			apiError(c, http.StatusBadRequest, "analysis failed: "+err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "pcap.analyze", Target: "upload"})
		c.JSON(http.StatusOK, result)
	}
}

func analyzePCAPNameHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := strings.TrimSpace(c.Param("name"))
		if name == "" {
			apiError(c, http.StatusBadRequest, "name required")
			return
		}
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		resp, err := engine.DownloadPcap(c.Request.Context(), name)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		defer resp.Body.Close()
		result, err := pcap.AnalyzeForPolicy(resp.Body, dpengine.DefaultDecoders()...)
		if err != nil {
			apiError(c, http.StatusBadRequest, "analysis failed: "+err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "pcap.analyze", Target: name})
		c.JSON(http.StatusOK, result)
	}
}

func listAssetsHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Assets)
	}
}

func createAssetHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var a config.Asset
		if err := c.ShouldBindJSON(&a); err != nil || a.ID == "" {
			apiError(c, http.StatusBadRequest, "invalid asset payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		for _, existing := range cfg.Assets {
			if existing.ID == a.ID {
				apiError(c, http.StatusBadRequest, "asset already exists")
				return
			}
			if existing.Name != "" && existing.Name == a.Name {
				apiError(c, http.StatusBadRequest, "asset name already exists")
				return
			}
		}
		cfg.Assets = append(cfg.Assets, a)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "assets.create", Target: a.ID})
		c.JSON(http.StatusOK, a)
	}
}

func updateAssetHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var a config.Asset
		if err := c.ShouldBindJSON(&a); err != nil {
			apiError(c, http.StatusBadRequest, "invalid asset payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		updated := false
		for i, existing := range cfg.Assets {
			if existing.ID == id {
				if a.ID == "" {
					a.ID = existing.ID
				}
				if a.Name == "" {
					a.Name = existing.Name
				}
				cfg.Assets[i] = a
				updated = true
				break
			}
		}
		if !updated {
			apiError(c, http.StatusNotFound, "asset not found")
			return
		}
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "assets.update", Target: id})
		c.JSON(http.StatusOK, a)
	}
}

func deleteAssetHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		original := len(cfg.Assets)
		filtered := make([]config.Asset, 0, len(cfg.Assets))
		for _, a := range cfg.Assets {
			if a.ID != id {
				filtered = append(filtered, a)
			}
		}
		if len(filtered) == original {
			apiError(c, http.StatusNotFound, "asset not found")
			return
		}
		cfg.Assets = filtered
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			internalError(c, err)
			return
		}
		auditLog(c, audit.Record{Action: "assets.delete", Target: id})
		c.Status(http.StatusNoContent)
	}
}

func listObjectsHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Objects)
	}
}

func createObjectHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var obj config.Object
		if err := c.ShouldBindJSON(&obj); err != nil || obj.ID == "" {
			apiError(c, http.StatusBadRequest, "invalid object payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		for _, existing := range cfg.Objects {
			if existing.ID == obj.ID {
				apiError(c, http.StatusBadRequest, "object already exists")
				return
			}
			if existing.Name != "" && existing.Name == obj.Name {
				apiError(c, http.StatusBadRequest, "object name already exists")
				return
			}
		}
		cfg.Objects = append(cfg.Objects, obj)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "objects.create", Target: obj.ID})
		c.JSON(http.StatusOK, obj)
	}
}

func updateObjectHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var obj config.Object
		if err := c.ShouldBindJSON(&obj); err != nil {
			apiError(c, http.StatusBadRequest, "invalid object payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		updated := false
		for i, existing := range cfg.Objects {
			if existing.ID == id {
				if obj.ID == "" {
					obj.ID = existing.ID
				}
				if obj.Name == "" {
					obj.Name = existing.Name
				}
				if obj.Type == "" {
					obj.Type = existing.Type
				}
				if obj.Addresses == nil {
					obj.Addresses = existing.Addresses
				}
				if obj.Members == nil {
					obj.Members = existing.Members
				}
				if obj.Protocols == nil {
					obj.Protocols = existing.Protocols
				}
				if obj.Tags == nil {
					obj.Tags = existing.Tags
				}
				cfg.Objects[i] = obj
				updated = true
				break
			}
		}
		if !updated {
			apiError(c, http.StatusNotFound, "object not found")
			return
		}
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "objects.update", Target: id})
		c.JSON(http.StatusOK, obj)
	}
}

func deleteObjectHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		original := len(cfg.Objects)
		filtered := make([]config.Object, 0, len(cfg.Objects))
		for _, obj := range cfg.Objects {
			if obj.ID != id {
				filtered = append(filtered, obj)
			}
		}
		if len(filtered) == original {
			apiError(c, http.StatusNotFound, "object not found")
			return
		}
		cfg.Objects = filtered
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			internalError(c, err)
			return
		}
		auditLog(c, audit.Record{Action: "objects.delete", Target: id})
		c.Status(http.StatusNoContent)
	}
}

func listZonesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Zones)
	}
}

func createZoneHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var z config.Zone
		if err := c.ShouldBindJSON(&z); err != nil || z.Name == "" {
			apiError(c, http.StatusBadRequest, "invalid zone payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		for _, existing := range cfg.Zones {
			if existing.Name == z.Name {
				apiError(c, http.StatusBadRequest, "zone already exists")
				return
			}
		}
		cfg.Zones = append(cfg.Zones, z)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, z)
	}
}

func deleteZoneHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		for _, iface := range cfg.Interfaces {
			if iface.Zone == name {
				apiError(c, http.StatusBadRequest, "zone in use by interface")
				return
			}
		}
		for _, rule := range cfg.Firewall.Rules {
			for _, z := range append(rule.SourceZones, rule.DestZones...) {
				if z == name {
					apiError(c, http.StatusBadRequest, "zone in use by firewall rule")
					return
				}
			}
		}
		original := len(cfg.Zones)
		filtered := make([]config.Zone, 0, len(cfg.Zones))
		for _, z := range cfg.Zones {
			if z.Name != name {
				filtered = append(filtered, z)
			}
		}
		if len(filtered) == original {
			apiError(c, http.StatusNotFound, "zone not found")
			return
		}
		cfg.Zones = filtered
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			internalError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func updateZoneHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")

		// Read raw JSON for partial merge.
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			apiError(c, http.StatusBadRequest, "failed to read request body")
			return
		}
		var patch map[string]interface{}
		if err := json.Unmarshal(body, &patch); err != nil {
			apiError(c, http.StatusBadRequest, "invalid zone payload")
			return
		}

		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		idx := -1
		for i, existing := range cfg.Zones {
			if existing.Name == name {
				idx = i
				break
			}
		}
		if idx < 0 {
			apiError(c, http.StatusNotFound, "zone not found")
			return
		}
		z := &cfg.Zones[idx]

		if v, ok := patch["name"]; ok {
			if s, ok := v.(string); ok {
				z.Name = s
			}
		}
		if v, ok := patch["alias"]; ok {
			if s, ok := v.(string); ok {
				z.Alias = s
			}
		}
		if v, ok := patch["description"]; ok {
			if s, ok := v.(string); ok {
				z.Description = s
			}
		}
		if v, ok := patch["slTarget"]; ok {
			if f, ok := v.(float64); ok {
				z.SLTarget = int(f)
			}
		}
		if v, ok := patch["consequence"]; ok {
			if s, ok := v.(string); ok {
				z.Consequence = s
			}
		}
		if v, ok := patch["slOverrides"]; ok {
			if m, ok := v.(map[string]interface{}); ok {
				if z.SLOverrides == nil {
					z.SLOverrides = make(map[string]bool)
				}
				for k, val := range m {
					if b, ok := val.(bool); ok {
						z.SLOverrides[k] = b
					}
				}
			}
		}

		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, *z)
	}
}

func listInterfacesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Interfaces)
	}
}

func interfaceStateHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Ensure config exists (so default interfaces are seeded).
		if _, err := loadOrInitConfig(c.Request.Context(), store); err != nil {
			internalError(c, err)
			return
		}
		if engine == nil {
			c.JSON(http.StatusOK, []config.InterfaceState{})
			return
		}
		st, err := engine.ListInterfaceState(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		c.JSON(http.StatusOK, st)
	}
}

func interfacesAssignHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		var req struct {
			Mode     string            `json:"mode"`
			Mappings map[string]string `json:"mappings"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, "invalid request")
			return
		}
		mode := strings.ToLower(strings.TrimSpace(req.Mode))
		if mode == "" {
			if len(req.Mappings) > 0 {
				mode = "explicit"
			}
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}

		state, err := engine.ListInterfaceState(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		deviceSet := map[string]struct{}{}
		type candidate struct {
			name   string
			index  int
			hasMAC bool
		}
		candidates := make([]candidate, 0, len(state))
		for _, st := range state {
			if strings.TrimSpace(st.Name) == "" {
				continue
			}
			deviceSet[st.Name] = struct{}{}
			if st.Name != "lo" && isAutoAssignableDevice(st.Name, st.MAC) {
				mac := strings.TrimSpace(strings.ToLower(st.MAC))
				hasMAC := mac != "" && mac != "00:00:00:00:00:00"
				candidates = append(candidates, candidate{name: st.Name, index: st.Index, hasMAC: hasMAC})
			}
		}
		sort.SliceStable(candidates, func(i, j int) bool {
			// Prefer NICs with a real MAC if we have it.
			if candidates[i].hasMAC != candidates[j].hasMAC {
				return candidates[i].hasMAC
			}
			// Prefer kernel index ordering when available; fall back to name.
			if candidates[i].index > 0 && candidates[j].index > 0 && candidates[i].index != candidates[j].index {
				return candidates[i].index < candidates[j].index
			}
			return candidates[i].name < candidates[j].name
		})

		ifaceByName := map[string]*config.Interface{}
		for i := range cfg.Interfaces {
			ifaceByName[cfg.Interfaces[i].Name] = &cfg.Interfaces[i]
		}

		assignments := map[string]string{}
		switch mode {
		case "auto":
			// Assign default logical interfaces to detected kernel interfaces.
			//
			// Note: In Docker-based lab mode, interface numbering (eth0/eth1/...) can vary depending
			// on network attach order. To keep the appliance UX stable, try to match interface roles
			// by the IPv4 subnets currently present on each interface (configurable via env vars,
			// defaulting to this repo's docker-compose subnets). Fall back to index ordering.
			order := []string{"wan", "dmz", "lan1", "lan2", "lan3", "lan4", "lan5", "lan6"}
			subnetByLogical := map[string]string{
				"wan":  envOrDefault("CONTAIND_AUTO_WAN_SUBNET", "192.168.240.0/24"),
				"dmz":  envOrDefault("CONTAIND_AUTO_DMZ_SUBNET", "192.168.241.0/24"),
				"lan1": envOrDefault("CONTAIND_AUTO_LAN1_SUBNET", "192.168.242.0/24"),
				"lan2": envOrDefault("CONTAIND_AUTO_LAN2_SUBNET", "192.168.243.0/24"),
				"lan3": envOrDefault("CONTAIND_AUTO_LAN3_SUBNET", "192.168.244.0/24"),
				"lan4": envOrDefault("CONTAIND_AUTO_LAN4_SUBNET", "192.168.245.0/24"),
				"lan5": envOrDefault("CONTAIND_AUTO_LAN5_SUBNET", "192.168.246.0/24"),
				"lan6": envOrDefault("CONTAIND_AUTO_LAN6_SUBNET", "192.168.247.0/24"),
			}
			needed := 0
			for _, logical := range order {
				if _, ok := ifaceByName[logical]; ok {
					needed++
				}
			}
			if needed == 0 {
				apiError(c, http.StatusBadRequest, "no default interfaces present")
				return
			}
			if len(candidates) < needed {
				apiError(c, http.StatusBadRequest, fmt.Sprintf("not enough eligible kernel interfaces (%d) for defaults (%d)", len(candidates), needed))
				return
			}

			stateByName := map[string]config.InterfaceState{}
			for _, st := range state {
				if strings.TrimSpace(st.Name) == "" {
					continue
				}
				stateByName[st.Name] = st
			}
			usedDev := map[string]bool{}

			// If Docker Compose provides stable interface names (e.g. "wan", "dmz", "lan1"...),
			// prefer those exact/prefix matches first.
			for _, logical := range order {
				if _, ok := ifaceByName[logical]; !ok {
					continue
				}
				for _, cand := range candidates {
					if usedDev[cand.name] {
						continue
					}
					if cand.name == logical || strings.HasPrefix(cand.name, logical) {
						assignments[logical] = cand.name
						usedDev[cand.name] = true
						break
					}
				}
			}

			// Match by IPv4 subnet on the interface (e.g. docker-compose lab subnets).
			for _, logical := range order {
				if _, ok := ifaceByName[logical]; !ok {
					continue
				}
				if _, already := assignments[logical]; already {
					continue
				}
				cidr := strings.TrimSpace(subnetByLogical[logical])
				if cidr == "" {
					continue
				}
				for _, cand := range candidates {
					if usedDev[cand.name] {
						continue
					}
					st, ok := stateByName[cand.name]
					if !ok {
						continue
					}
					if ifaceHasIPv4InCIDR(st.Addrs, cidr) {
						assignments[logical] = cand.name
						usedDev[cand.name] = true
						break
					}
				}
			}

			// Fall back: use the kernel's default-route egress device for WAN if still unassigned.
			if _, ok := ifaceByName["wan"]; ok {
				if _, already := assignments["wan"]; !already {
					defDev := strings.TrimSpace(detectKernelDefaultRouteIface())
					if defDev != "" && !usedDev[defDev] {
						if st, ok := stateByName[defDev]; ok && isAutoAssignableDevice(defDev, st.MAC) {
							assignments["wan"] = defDev
							usedDev[defDev] = true
						}
					}
				}
			}

			remaining := make([]candidate, 0, len(candidates))
			for _, cand := range candidates {
				if usedDev[cand.name] {
					continue
				}
				remaining = append(remaining, cand)
			}
			idx := 0
			for _, logical := range order {
				if _, ok := ifaceByName[logical]; !ok {
					continue
				}
				if _, already := assignments[logical]; already {
					continue
				}
				if idx >= len(remaining) {
					apiError(c, http.StatusBadRequest, "not enough eligible kernel interfaces to complete auto-assign")
					return
				}
				assignments[logical] = remaining[idx].name
				idx++
			}
		case "explicit":
			if len(req.Mappings) == 0 {
				apiError(c, http.StatusBadRequest, "mappings required")
				return
			}
			for k, v := range req.Mappings {
				k = strings.TrimSpace(k)
				v = strings.TrimSpace(v)
				if k == "" {
					continue
				}
				// Allow clearing via empty/none.
				if strings.EqualFold(v, "none") || v == "-" {
					v = ""
				}
				assignments[k] = v
			}
		default:
			apiError(c, http.StatusBadRequest, "mode must be auto or explicit")
			return
		}

		used := map[string]string{} // device -> logical
		for logical, dev := range assignments {
			if _, ok := ifaceByName[logical]; !ok {
				apiError(c, http.StatusBadRequest, "unknown interface: "+logical)
				return
			}
			if dev == "" {
				continue
			}
			if _, ok := deviceSet[dev]; !ok {
				apiError(c, http.StatusBadRequest, "unknown kernel device: "+dev)
				return
			}
			if prev, ok := used[dev]; ok && prev != logical {
				apiError(c, http.StatusBadRequest, fmt.Sprintf("device %s already assigned to %s", dev, prev))
				return
			}
			used[dev] = logical
		}

		for logical, dev := range assignments {
			ifaceByName[logical].Device = dev
		}

		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		warnings, err := applyRunningConfig(c.Request.Context(), store, engine, services)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		setWarningHeader(c, warnings)
		auditLog(c, audit.Record{Action: "interfaces.assign", Target: "config"})
		c.JSON(http.StatusOK, gin.H{"interfaces": cfg.Interfaces})
	}
}

func isAutoAssignableDevice(name string, mac string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "lo" {
		return false
	}
	// In appliance mode we want "real" NIC-like devices, not tunnels/virtual plumbing.
	// Users can still explicitly bind to these if they want.
	skipPrefixes := []string{
		"erspan", "gre", "gretap", "ipip", "sit", "ip6tnl",
		"tun", "tap",
		"veth", "br", "docker", "cni", "flannel", "calico",
		"vxlan", "geneve",
		"wg", "tailscale",
		"virbr", "vmnet", "utun",
		"dummy", "ifb", "nlmon",
	}
	for _, p := range skipPrefixes {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	return true
}

func envOrDefault(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

func ifaceHasIPv4InCIDR(addrs []string, cidr string) bool {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return false
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ipnet == nil {
		return false
	}
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		var ip net.IP
		if strings.Contains(a, "/") {
			var ipnet2 *net.IPNet
			ip, ipnet2, err = net.ParseCIDR(a)
			if err != nil || ipnet2 == nil {
				continue
			}
		} else {
			ip = net.ParseIP(a)
			if ip == nil {
				continue
			}
		}
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		if ip4[0] == 169 && ip4[1] == 254 {
			continue
		}
		if ipnet.Contains(ip4) {
			return true
		}
	}
	return false
}

func interfacesReconcileHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		var req struct {
			Confirm string `json:"confirm"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Confirm) != "REPLACE" {
			apiError(c, http.StatusBadRequest, "confirm required: set {\"confirm\":\"REPLACE\"}")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		if err := engine.ConfigureInterfacesReplace(c.Request.Context(), cfg.Interfaces); err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "interfaces.reconcile", Target: "engine"})
		c.JSON(http.StatusOK, gin.H{"status": "reconciled"})
	}
}

func createInterfaceHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var iface config.Interface
		if err := c.ShouldBindJSON(&iface); err != nil || iface.Name == "" {
			apiError(c, http.StatusBadRequest, "invalid interface payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		for _, existing := range cfg.Interfaces {
			if existing.Name == iface.Name {
				apiError(c, http.StatusBadRequest, "interface already exists")
				return
			}
		}
		cfg.Interfaces = append(cfg.Interfaces, iface)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if engine != nil {
			warnings, err := applyRunningConfig(c.Request.Context(), store, engine, services)
			if err != nil {
				apiError(c, http.StatusBadGateway, err.Error())
				return
			}
			setWarningHeader(c, warnings)
		}
		auditLog(c, audit.Record{Action: "interfaces.create", Target: iface.Name})
		c.JSON(http.StatusOK, iface)
	}
}

func deleteInterfaceHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		original := len(cfg.Interfaces)
		filtered := make([]config.Interface, 0, len(cfg.Interfaces))
		for _, i := range cfg.Interfaces {
			if i.Name != name {
				filtered = append(filtered, i)
			}
		}
		if len(filtered) == original {
			apiError(c, http.StatusNotFound, "interface not found")
			return
		}
		cfg.Interfaces = filtered
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			internalError(c, err)
			return
		}
		if engine != nil {
			warnings, err := applyRunningConfig(c.Request.Context(), store, engine, services)
			if err != nil {
				apiError(c, http.StatusBadGateway, err.Error())
				return
			}
			setWarningHeader(c, warnings)
		}
		auditLog(c, audit.Record{Action: "interfaces.delete", Target: name})
		c.Status(http.StatusNoContent)
	}
}

func updateInterfaceHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		var iface config.Interface
		if err := c.ShouldBindJSON(&iface); err != nil {
			apiError(c, http.StatusBadRequest, "invalid interface payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		isAccessUnset := func(a config.InterfaceAccess) bool {
			return a.Mgmt == nil && a.HTTP == nil && a.HTTPS == nil && a.SSH == nil
		}
		updated := false
		for i, existing := range cfg.Interfaces {
			if existing.Name == name {
				if iface.Name == "" {
					iface.Name = existing.Name
				}
				if strings.TrimSpace(iface.Device) == "" {
					iface.Device = existing.Device
				}
				if strings.TrimSpace(iface.Zone) == "" {
					iface.Zone = existing.Zone
				}
				// If addresses are omitted from the JSON payload, keep existing values.
				// An explicit empty list clears addresses.
				if iface.Addresses == nil {
					iface.Addresses = existing.Addresses
				}
				// Access is a struct with pointer fields; if omitted (all nil), keep existing.
				if isAccessUnset(iface.Access) {
					iface.Access = existing.Access
				}
				cfg.Interfaces[i] = iface
				updated = true
				break
			}
		}
		if !updated {
			apiError(c, http.StatusNotFound, "interface not found")
			return
		}
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if engine != nil {
			warnings, err := applyRunningConfig(c.Request.Context(), store, engine, services)
			if err != nil {
				apiError(c, http.StatusBadGateway, err.Error())
				return
			}
			setWarningHeader(c, warnings)
		}
		auditLog(c, audit.Record{Action: "interfaces.update", Target: name})
		c.JSON(http.StatusOK, iface)
	}
}

func getRoutingHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Routing)
	}
}

func setRoutingHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var routingCfg config.RoutingConfig
		if err := c.ShouldBindJSON(&routingCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		cfg.Routing = routingCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		warnings, err := applyRunningConfig(c.Request.Context(), store, engine, services)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		setWarningHeader(c, warnings)
		auditLog(c, audit.Record{Action: "routing.set", Target: "config"})
		c.JSON(http.StatusOK, cfg.Routing)
	}
}

func routingReconcileHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		var req struct {
			Confirm string `json:"confirm"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Confirm) != "REPLACE" {
			apiError(c, http.StatusBadRequest, "confirm required: set {\"confirm\":\"REPLACE\"}")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		if err := engine.ConfigureRoutingReplace(c.Request.Context(), cfg.Routing); err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "routing.reconcile", Target: "engine"})
		c.JSON(http.StatusOK, gin.H{"status": "reconciled"})
	}
}

func listFirewallRulesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Firewall.Rules)
	}
}

func createFirewallRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var r config.Rule
		if err := c.ShouldBindJSON(&r); err != nil || r.ID == "" {
			apiError(c, http.StatusBadRequest, "invalid rule payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		for _, existing := range cfg.Firewall.Rules {
			if existing.ID == r.ID {
				apiError(c, http.StatusBadRequest, "rule already exists")
				return
			}
		}
		if cfg.Firewall.DefaultAction == "" {
			cfg.Firewall.DefaultAction = config.ActionDeny
		}
		cfg.Firewall.Rules = append(cfg.Firewall.Rules, r)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, r)
	}
}

func deleteFirewallRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		original := len(cfg.Firewall.Rules)
		filtered := make([]config.Rule, 0, len(cfg.Firewall.Rules))
		for _, r := range cfg.Firewall.Rules {
			if r.ID != id {
				filtered = append(filtered, r)
			}
		}
		if len(filtered) == original {
			apiError(c, http.StatusNotFound, "rule not found")
			return
		}
		cfg.Firewall.Rules = filtered
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			internalError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func mergeJSONObject(dst, patch map[string]interface{}) map[string]interface{} {
	if dst == nil {
		dst = map[string]interface{}{}
	}
	for key, value := range patch {
		if existing, ok := dst[key].(map[string]interface{}); ok {
			if nested, ok := value.(map[string]interface{}); ok {
				dst[key] = mergeJSONObject(existing, nested)
				continue
			}
		}
		dst[key] = value
	}
	return dst
}

func updateFirewallRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			apiError(c, http.StatusBadRequest, "failed to read request body")
			return
		}
		var patch map[string]interface{}
		if err := json.Unmarshal(body, &patch); err != nil {
			apiError(c, http.StatusBadRequest, "invalid rule payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		updated := false
		for i, existing := range cfg.Firewall.Rules {
			if existing.ID == id {
				currentJSON, err := json.Marshal(existing)
				if err != nil {
					internalError(c, err)
					return
				}
				var merged map[string]interface{}
				if err := json.Unmarshal(currentJSON, &merged); err != nil {
					internalError(c, err)
					return
				}
				merged = mergeJSONObject(merged, patch)
				mergedJSON, err := json.Marshal(merged)
				if err != nil {
					internalError(c, err)
					return
				}
				var rule config.Rule
				if err := json.Unmarshal(mergedJSON, &rule); err != nil {
					apiError(c, http.StatusBadRequest, "invalid rule payload")
					return
				}
				if rule.ID == "" {
					rule.ID = existing.ID
				}
				cfg.Firewall.Rules[i] = rule
				updated = true
				c.Set("updated_rule", rule)
				break
			}
		}
		if !updated {
			apiError(c, http.StatusNotFound, "rule not found")
			return
		}
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if v, ok := c.Get("updated_rule"); ok {
			if rule, ok := v.(config.Rule); ok {
				c.JSON(http.StatusOK, rule)
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"status": "updated"})
	}
}

// previewRuleResponse is the JSON response for rule impact preview.
type previewRuleResponse struct {
	MatchCount    int               `json:"match_count"`
	SampleMatches []dpevents.Event  `json:"sample_matches"`
	TimeRange     *previewTimeRange `json:"time_range"`
	TotalEvents   int               `json:"total_events"`
}

type previewTimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

func previewFirewallRuleHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req config.Rule
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, "invalid rule payload")
			return
		}

		// Convert config.Rule to rules.Entry for matching.
		entry := rules.Entry{
			ID:           req.ID,
			SourceZones:  req.SourceZones,
			DestZones:    req.DestZones,
			Sources:      req.Sources,
			Destinations: req.Destinations,
			Action:       rules.Action(req.Action),
			Identities:   req.Identities,
			ICS: rules.ICSPredicate{
				Protocol:     req.ICS.Protocol,
				FunctionCode: req.ICS.FunctionCode,
				UnitID:       req.ICS.UnitID,
				Addresses:    req.ICS.Addresses,
				ReadOnly:     req.ICS.ReadOnly,
				WriteOnly:    req.ICS.WriteOnly,
				Mode:         req.ICS.Mode,
			},
		}
		if req.Schedule != nil {
			entry.Schedule = rules.SchedulePredicate{
				DaysOfWeek: req.Schedule.DaysOfWeek,
				StartTime:  req.Schedule.StartTime,
				EndTime:    req.Schedule.EndTime,
				Timezone:   req.Schedule.Timezone,
			}
		}
		for _, p := range req.Protocols {
			entry.Protocols = append(entry.Protocols, rules.Protocol{Name: p.Name, Port: p.Port})
		}

		// Get events from the telemetry client.
		tc, ok := engine.(TelemetryClient)
		if !ok || tc == nil {
			c.JSON(http.StatusOK, previewRuleResponse{
				SampleMatches: []dpevents.Event{},
			})
			return
		}

		evs, err := tc.ListEvents(c.Request.Context(), 5000)
		if err != nil {
			apiError(c, http.StatusBadGateway, "failed to fetch events: "+err.Error())
			return
		}

		totalEvents := len(evs)

		// Determine time range.
		var tr *previewTimeRange
		if totalEvents > 0 {
			oldest := evs[0].Timestamp
			newest := evs[0].Timestamp
			for _, ev := range evs[1:] {
				if ev.Timestamp.Before(oldest) {
					oldest = ev.Timestamp
				}
				if ev.Timestamp.After(newest) {
					newest = ev.Timestamp
				}
			}
			tr = &previewTimeRange{Start: oldest, End: newest}
		}

		// Match events against the proposed rule.
		const maxSamples = 50
		var matchCount int
		var samples []dpevents.Event
		for _, ev := range evs {
			ctx := rules.EvalContext{
				SrcIP: net.ParseIP(ev.SrcIP),
				DstIP: net.ParseIP(ev.DstIP),
				Proto: ev.Transport,
				Port:  strconv.Itoa(int(ev.DstPort)),
				Now:   ev.Timestamp,
			}
			if rules.PreviewMatch(entry, ctx) {
				matchCount++
				if len(samples) < maxSamples {
					samples = append(samples, ev)
				}
			}
		}

		if samples == nil {
			samples = []dpevents.Event{}
		}

		c.JSON(http.StatusOK, previewRuleResponse{
			MatchCount:    matchCount,
			SampleMatches: samples,
			TimeRange:     tr,
			TotalEvents:   totalEvents,
		})
	}
}

// hasICSPredicate returns true if the rule has a non-empty ICS predicate.
func hasICSPredicate(r config.Rule) bool {
	return strings.TrimSpace(r.ICS.Protocol) != "" ||
		len(r.ICS.FunctionCode) > 0 ||
		r.ICS.UnitID != nil ||
		len(r.ICS.Addresses) > 0 ||
		r.ICS.ReadOnly ||
		r.ICS.WriteOnly
}

func listICSRulesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		var icsRules []config.Rule
		for _, r := range cfg.Firewall.Rules {
			if hasICSPredicate(r) {
				icsRules = append(icsRules, r)
			}
		}
		if icsRules == nil {
			icsRules = []config.Rule{}
		}
		c.JSON(http.StatusOK, icsRules)
	}
}

func createICSRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var r config.Rule
		if err := c.ShouldBindJSON(&r); err != nil || r.ID == "" {
			apiError(c, http.StatusBadRequest, "invalid rule payload")
			return
		}
		if !hasICSPredicate(r) {
			apiError(c, http.StatusBadRequest, "rule must include an ICS predicate")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		for _, existing := range cfg.Firewall.Rules {
			if existing.ID == r.ID {
				apiError(c, http.StatusBadRequest, "rule already exists")
				return
			}
		}
		if cfg.Firewall.DefaultAction == "" {
			cfg.Firewall.DefaultAction = config.ActionDeny
		}
		cfg.Firewall.Rules = append(cfg.Firewall.Rules, r)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, r)
	}
}

func updateICSRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var rule config.Rule
		if err := c.ShouldBindJSON(&rule); err != nil {
			apiError(c, http.StatusBadRequest, "invalid rule payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		updated := false
		for i, existing := range cfg.Firewall.Rules {
			if existing.ID == id {
				if !hasICSPredicate(existing) {
					apiError(c, http.StatusBadRequest, "rule is not an ICS rule")
					return
				}
				if rule.ID == "" {
					rule.ID = existing.ID
				}
				cfg.Firewall.Rules[i] = rule
				updated = true
				break
			}
		}
		if !updated {
			apiError(c, http.StatusNotFound, "rule not found")
			return
		}
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, rule)
	}
}

func loadOrInitConfig(ctx context.Context, store config.Store) (*config.Config, error) {
	cfg, err := store.Load(ctx)
	if err != nil {
		if errors.Is(err, config.ErrNotFound) {
			def := config.DefaultConfig()
			def.System.Hostname = "containd"
			def.System.Mgmt.ListenAddr = ":8080"
			def.System.Mgmt.HTTPListenAddr = ":8080"
			def.System.Mgmt.HTTPSListenAddr = ":8443"
			t := true
			def.System.Mgmt.EnableHTTP = &t
			def.System.Mgmt.EnableHTTPS = &t
			def.System.Mgmt.TLSCertFile = "/data/tls/server.crt"
			def.System.Mgmt.TLSKeyFile = "/data/tls/server.key"
			def.System.SSH.ListenAddr = ":2222"
			def.System.SSH.AuthorizedKeysDir = "/data/ssh/authorized_keys.d"
			autoBindDefaultInterfaceDevices(def)
			// NOTE: password auth is controlled by runtime bootstrap logic; don't force it in config here.
			_ = store.Save(ctx, def)
			return def, nil
		}
		return nil, err
	}
	if cfg.Firewall.DefaultAction == "" {
		cfg.Firewall.DefaultAction = config.ActionDeny
	}
	// If this is a pre-bind config using default interface names, opportunistically bind.
	// This helps keep config and OS reality aligned in appliance-style setups.
	hadAnyDevice := false
	for _, iface := range cfg.Interfaces {
		if strings.TrimSpace(iface.Device) != "" {
			hadAnyDevice = true
			break
		}
	}
	if !hadAnyDevice {
		autoBindDefaultInterfaceDevices(cfg)
		hasAnyDevice := false
		for _, iface := range cfg.Interfaces {
			if strings.TrimSpace(iface.Device) != "" {
				hasAnyDevice = true
				break
			}
		}
		if hasAnyDevice {
			_ = store.Save(ctx, cfg)
		}
	}
	return cfg, nil
}

func autoBindDefaultInterfaceDevices(cfg *config.Config) {
	if cfg == nil || len(cfg.Interfaces) == 0 {
		return
	}
	// Only auto-bind for the default appliance interface names, and only if not already bound.
	defaultNames := config.DefaultPhysicalInterfaces()
	defaultSet := map[string]struct{}{}
	for _, n := range defaultNames {
		defaultSet[n] = struct{}{}
	}
	for _, iface := range cfg.Interfaces {
		if _, ok := defaultSet[iface.Name]; !ok {
			return
		}
		if strings.TrimSpace(iface.Device) != "" {
			return
		}
	}

	sysIfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	type sysIface struct {
		idx  int
		name string
	}
	candidates := make([]sysIface, 0, len(sysIfaces))
	for _, si := range sysIfaces {
		if si.Name == "lo" {
			continue
		}
		if len(si.HardwareAddr) == 0 {
			continue
		}
		// Keep the same "no tunnels/virtual" approach as interfaces auto-assign.
		// (We don't have MAC strings here; HardwareAddr presence already helps.)
		if !isAutoAssignableDevice(si.Name, si.HardwareAddr.String()) {
			continue
		}
		candidates = append(candidates, sysIface{idx: si.Index, name: si.Name})
	}
	if len(candidates) < len(defaultNames) {
		return
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].idx < candidates[j].idx })

	nameToDev := map[string]string{}
	for i, n := range defaultNames {
		nameToDev[n] = candidates[i].name
	}
	for i := range cfg.Interfaces {
		if dev, ok := nameToDev[cfg.Interfaces[i].Name]; ok {
			cfg.Interfaces[i].Device = dev
		}
	}
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

// --- Identity mapping handlers ---

func listIdentitiesHandler(resolver *identity.Resolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"mappings": resolver.All()})
	}
}

func setIdentityHandler(resolver *identity.Resolver) gin.HandlerFunc {
	type req struct {
		IP         string   `json:"ip"`
		Identities []string `json:"identities"`
	}
	return func(c *gin.Context) {
		var body req
		if err := c.ShouldBindJSON(&body); err != nil {
			apiError(c, http.StatusBadRequest, "invalid request body")
			return
		}
		ip := net.ParseIP(strings.TrimSpace(body.IP))
		if ip == nil {
			apiError(c, http.StatusBadRequest, "invalid IP address")
			return
		}
		if len(body.Identities) == 0 {
			apiError(c, http.StatusBadRequest, "identities must not be empty")
			return
		}
		for _, id := range body.Identities {
			if strings.TrimSpace(id) == "" {
				apiError(c, http.StatusBadRequest, "identity must not be empty")
				return
			}
		}
		resolver.Register(ip, body.Identities)
		c.JSON(http.StatusOK, gin.H{"ip": ip.String(), "identities": body.Identities})
	}
}

func listTemplatesHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, templates.List())
	}
}

func applyTemplateHandler(store config.Store) gin.HandlerFunc {
	type req struct {
		Name string `json:"name"`
	}
	return func(c *gin.Context) {
		var r req
		if err := c.ShouldBindJSON(&r); err != nil || r.Name == "" {
			apiError(c, http.StatusBadRequest, "name is required")
			return
		}
		ctx := c.Request.Context()
		cfg, err := loadOrInitConfig(ctx, store)
		if err != nil {
			internalError(c, err)
			return
		}
		if err := templates.Apply(r.Name, cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := store.Save(ctx, cfg); err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"applied": r.Name, "ruleCount": len(cfg.Firewall.Rules)})
	}
}

// icsTemplateInfo describes an available ICS protocol template for the API.
type icsTemplateInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Protocol    string `json:"protocol"`
}

func listICSTemplatesHandler() gin.HandlerFunc {
	infos := []icsTemplateInfo{
		{Name: "modbus_read_only", Description: "Allow Modbus read operations only (FC 1-4), deny all writes", Protocol: "modbus"},
		{Name: "modbus_register_guard", Description: "Allow Modbus access to specific register address ranges only (requires params.ranges)", Protocol: "modbus"},
		{Name: "dnp3_secure_operations", Description: "Allow normal DNP3 reads, deny dangerous function codes (restart, stop)", Protocol: "dnp3"},
		{Name: "s7comm_read_only", Description: "Allow S7comm read variable, deny write and PLC control", Protocol: "s7comm"},
		{Name: "cip_monitor_only", Description: "Allow CIP read services, deny writes and control commands", Protocol: "cip"},
		{Name: "bacnet_read_only", Description: "Allow BACnet read properties, deny writes and device control", Protocol: "bacnet"},
		{Name: "opcua_monitor_only", Description: "Allow OPC UA browse/read/subscribe, deny writes and node management", Protocol: "opcua"},
	}
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, infos)
	}
}

func applyICSTemplateHandler() gin.HandlerFunc {
	type icsParams struct {
		Ranges []string `json:"ranges,omitempty"`
	}
	type icsReq struct {
		Template    string    `json:"template"`
		SourceZones []string  `json:"source_zones,omitempty"`
		DestZones   []string  `json:"dest_zones,omitempty"`
		Params      icsParams `json:"params,omitempty"`
	}
	return func(c *gin.Context) {
		var r icsReq
		if err := c.ShouldBindJSON(&r); err != nil || r.Template == "" {
			apiError(c, http.StatusBadRequest, "template name is required")
			return
		}

		var rules []config.Rule
		switch r.Template {
		case "modbus_read_only":
			rules = templates.ModbusReadOnly()
		case "modbus_register_guard":
			if len(r.Params.Ranges) == 0 {
				apiError(c, http.StatusBadRequest, "params.ranges is required for modbus_register_guard")
				return
			}
			rules = templates.ModbusRegisterGuard(r.Params.Ranges)
		case "dnp3_secure_operations":
			rules = templates.DNP3SecureOperations()
		case "s7comm_read_only":
			rules = templates.S7commReadOnly()
		case "cip_monitor_only":
			rules = templates.CIPMonitorOnly()
		case "bacnet_read_only":
			rules = templates.BACnetReadOnly()
		case "opcua_monitor_only":
			rules = templates.OPCUAMonitorOnly()
		default:
			apiError(c, http.StatusBadRequest, fmt.Sprintf("unknown ICS template %q", r.Template))
			return
		}

		// Apply source/dest zones if provided.
		if len(r.SourceZones) > 0 || len(r.DestZones) > 0 {
			for i := range rules {
				if len(r.SourceZones) > 0 {
					rules[i].SourceZones = r.SourceZones
				}
				if len(r.DestZones) > 0 {
					rules[i].DestZones = r.DestZones
				}
			}
		}

		c.JSON(http.StatusOK, gin.H{"template": r.Template, "rules": rules})
	}
}

func deleteIdentityHandler(resolver *identity.Resolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := c.Param("ip")
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			apiError(c, http.StatusBadRequest, "invalid IP address")
			return
		}
		resolver.Remove(ip)
		c.JSON(http.StatusOK, gin.H{"deleted": ip.String()})
	}
}

// --- ICS Learn Mode handlers ---

func learnProfilesHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		lc, ok := engine.(LearnClient)
		if !ok || lc == nil {
			c.JSON(http.StatusOK, []learn.LearnedProfile{})
			return
		}
		profiles, err := lc.ListLearnProfiles(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		if profiles == nil {
			profiles = []learn.LearnedProfile{}
		}
		c.JSON(http.StatusOK, profiles)
	}
}

func learnGenerateHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		lc, ok := engine.(LearnClient)
		if !ok || lc == nil {
			c.JSON(http.StatusOK, []config.Rule{})
			return
		}
		genRules, err := lc.GenerateLearnRules(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, genRules)
	}
}

func learnApplyHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		lc, ok := engine.(LearnClient)
		if !ok || lc == nil {
			apiError(c, http.StatusBadRequest, "learn mode not available")
			return
		}
		generated, err := lc.GenerateLearnRules(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		if len(generated) == 0 {
			c.JSON(http.StatusOK, gin.H{"status": "no rules to apply", "count": 0})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		existing := map[string]bool{}
		for _, r := range cfg.Firewall.Rules {
			existing[r.ID] = true
		}
		added := 0
		for _, r := range generated {
			if existing[r.ID] {
				continue
			}
			cfg.Firewall.Rules = append(cfg.Firewall.Rules, r)
			added++
		}
		if cfg.Firewall.DefaultAction == "" {
			cfg.Firewall.DefaultAction = config.ActionDeny
		}
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "applied", "count": added, "rules": generated})
	}
}

func learnClearHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		lc, ok := engine.(LearnClient)
		if !ok || lc == nil {
			c.JSON(http.StatusOK, gin.H{"status": "cleared"})
			return
		}
		if err := lc.ClearLearnData(c.Request.Context()); err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "cleared"})
	}
}

func listSignaturesHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(SignaturesClient)
		if !ok || sc == nil {
			c.JSON(http.StatusOK, []signatures.Signature{})
			return
		}
		sigs, err := sc.ListSignatures(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		if sigs == nil {
			sigs = []signatures.Signature{}
		}
		c.JSON(http.StatusOK, sigs)
	}
}

func addSignatureHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(SignaturesClient)
		if !ok || sc == nil {
			apiError(c, http.StatusNotImplemented, "signatures not available")
			return
		}
		var sig signatures.Signature
		if err := c.ShouldBindJSON(&sig); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if sig.ID == "" {
			apiError(c, http.StatusBadRequest, "signature ID is required")
			return
		}
		if len(sig.Conditions) == 0 {
			apiError(c, http.StatusBadRequest, "at least one condition is required")
			return
		}
		if err := sc.AddSignature(c.Request.Context(), sig); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "signatures.add", Target: sig.ID})
		c.JSON(http.StatusOK, sig)
	}
}

func deleteSignatureHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(SignaturesClient)
		if !ok || sc == nil {
			apiError(c, http.StatusNotImplemented, "signatures not available")
			return
		}
		id := c.Param("id")
		removed, err := sc.RemoveSignature(c.Request.Context(), id)
		if err != nil {
			internalError(c, err)
			return
		}
		if !removed {
			apiError(c, http.StatusNotFound, "signature not found")
			return
		}
		auditLog(c, audit.Record{Action: "signatures.delete", Target: id})
		c.Status(http.StatusNoContent)
	}
}

func listSignatureMatchesHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(SignaturesClient)
		if !ok || sc == nil {
			c.JSON(http.StatusOK, []signatures.Match{})
			return
		}
		limit := 100
		if v := c.Query("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		matches, err := sc.ListSignatureMatches(c.Request.Context(), limit)
		if err != nil {
			internalError(c, err)
			return
		}
		if matches == nil {
			matches = []signatures.Match{}
		}
		c.JSON(http.StatusOK, matches)
	}
}
