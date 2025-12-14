package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/containd/containd/pkg/cli"
	"github.com/containd/containd/pkg/cp/audit"
	"github.com/containd/containd/pkg/cp/compile"
	"github.com/containd/containd/pkg/cp/config"
	cpids "github.com/containd/containd/pkg/cp/ids"
	"github.com/containd/containd/pkg/cp/users"
	"github.com/containd/containd/pkg/dp/conntrack"
	"github.com/containd/containd/pkg/dp/dhcpd"
	dpevents "github.com/containd/containd/pkg/dp/events"
	"github.com/containd/containd/pkg/dp/rules"
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
func NewServerWithEngineAndServices(store config.Store, auditStore audit.Store, engine EngineClient, services ServicesApplier, userStore users.Store) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
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
	// Login is always unauthenticated (unless JWT not configured).
	api.POST("/auth/login", loginHandler(userStore))
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
		protected.POST("/auth/me/password", changeMyPasswordHandler(userStore))
		protected.GET("/system/tls", getTLSHandler(store))
		protected.POST("/system/tls/cert", requireAdmin(), setTLSCertHandler(store))
		protected.POST("/system/tls/trusted-ca", requireAdmin(), setTrustedCAHandler(store))
		protected.POST("/system/factory-reset", requireAdmin(), factoryResetHandler(store, userStore))
		protected.GET("/config", getConfigHandler(store))
		protected.POST("/config", requireAdmin(), saveConfigHandler(store))
		protected.POST("/config/validate", requireAdmin(), validateConfigHandler())
		protected.GET("/config/export", exportConfigHandler(store))
		protected.POST("/config/import", requireAdmin(), importConfigHandler(store))
		protected.GET("/config/candidate", getCandidateConfigHandler(store))
		protected.POST("/config/candidate", requireAdmin(), saveCandidateConfigHandler(store))
		protected.GET("/config/diff", diffConfigHandler(store))
		protected.POST("/config/commit", requireAdmin(), commitConfigHandler(store, engine, services))
		protected.POST("/config/commit_confirmed", requireAdmin(), commitConfirmedHandler(store, engine, services))
		protected.POST("/config/confirm", requireAdmin(), confirmCommitHandler(store))
		protected.POST("/config/rollback", requireAdmin(), rollbackConfigHandler(store, engine, services))
		protected.GET("/services/syslog", getSyslogHandler(store))
		protected.POST("/services/syslog", requireAdmin(), setSyslogHandler(store, services))
		protected.GET("/services/dns", getDNSHandler(store))
		protected.POST("/services/dns", requireAdmin(), setDNSHandler(store, services))
		protected.GET("/services/ntp", getNTPHandler(store))
		protected.POST("/services/ntp", requireAdmin(), setNTPHandler(store, services))
		protected.GET("/services/dhcp", getDHCPHandler(store))
		protected.POST("/services/dhcp", requireAdmin(), setDHCPHandler(store, services, engine))
		protected.GET("/services/vpn", getVPNHandler(store))
		protected.POST("/services/vpn", requireAdmin(), setVPNHandler(store, services, engine))
		protected.GET("/services/proxy/forward", getForwardProxyHandler(store))
		protected.POST("/services/proxy/forward", requireAdmin(), setForwardProxyHandler(store, services))
		protected.GET("/services/proxy/reverse", getReverseProxyHandler(store))
		protected.POST("/services/proxy/reverse", requireAdmin(), setReverseProxyHandler(store, services))
		protected.GET("/services/status", getServicesStatusHandler(services))
			protected.GET("/events", listEventsHandler(engine))
			protected.GET("/flows", listFlowsHandler(engine))
			protected.GET("/conntrack", listConntrackHandler(engine))
			protected.POST("/conntrack/kill", requireAdmin(), killConntrackHandler(engine))
			protected.GET("/dhcp/leases", dhcpLeasesHandler(engine))
			protected.GET("/dataplane", getDataPlaneHandler(store))
			protected.POST("/dataplane", requireAdmin(), setDataPlaneHandler(store, engine))
		protected.GET("/assets", listAssetsHandler(store))
		protected.POST("/assets", requireAdmin(), createAssetHandler(store))
		protected.PATCH("/assets/:id", requireAdmin(), updateAssetHandler(store))
		protected.DELETE("/assets/:id", requireAdmin(), deleteAssetHandler(store))
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
		protected.GET("/ids/rules", getIDSHandler(store))
		protected.POST("/ids/rules", requireAdmin(), setIDSHandler(store))
		protected.POST("/ids/convert/sigma", convertSigmaHandler())
		protected.POST("/cli/execute", cliExecuteHandler(store))
		// Users (admin only).
		protected.GET("/users", requireAdmin(), listUsersHandler(userStore))
		protected.POST("/users", requireAdmin(), createUserHandler(userStore))
		protected.PATCH("/users/:id", requireAdmin(), updateUserHandler(userStore))
		protected.POST("/users/:id/password", requireAdmin(), setUserPasswordHandler(userStore))
		if auditStore != nil {
			auditHandlers(protected, auditStore)
		}
	}

	return r
}

func dhcpLeasesHandler(engine any) gin.HandlerFunc {
	type resp struct {
		Leases []dhcpd.Lease `json:"leases"`
	}
	return func(c *gin.Context) {
		cl, ok := engine.(DHCPLeasesClient)
		if !ok || cl == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "engine dhcp leases not available"})
			return
		}
		leases, err := cl.ListDHCPLeases(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, resp{Leases: leases})
	}
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"component": "ngfw-mgmt",
		"build":     "dev",
		"time":      time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func getConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg)
	}
}

func saveConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var cfg config.Config
		if err := c.ShouldBindJSON(&cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		if err := store.Save(ctx, &cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		if err := cfg.Validate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
				c.JSON(http.StatusNotFound, gin.H{"error": "config not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid redacted query value"})
			return
		}
		if !wantRedacted && c.GetString(ctxRoleKey) != string(roleAdmin) {
			c.JSON(http.StatusForbidden, gin.H{"error": "admin role required for unredacted export"})
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
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
			return
		}
		var cfg config.Config
		if err := json.Unmarshal(body, &cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		if err := cfg.Validate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := store.Save(c.Request.Context(), &cfg); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		auditLog(c, audit.Record{Action: "config.import", Target: "running"})
		c.JSON(http.StatusOK, gin.H{"status": "imported"})
	}
}

func getCandidateConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.LoadCandidate(c.Request.Context())
		if err != nil {
			if errors.Is(err, config.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "candidate config not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg)
	}
}

func saveCandidateConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var cfg config.Config
		if err := c.ShouldBindJSON(&cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		if err := store.SaveCandidate(c.Request.Context(), &cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		auditLog(c, audit.Record{Action: "config.save_candidate", Target: "candidate"})
		c.JSON(http.StatusOK, gin.H{"status": "saved"})
	}
}

func commitConfigHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := store.Commit(c.Request.Context()); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := applyRunningConfig(c.Request.Context(), store, engine, services); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		auditLog(c, audit.Record{Action: "config.commit", Target: "running"})
		c.JSON(http.StatusOK, gin.H{"status": "committed"})
	}
}

func commitConfirmedHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		const defaultTTLSeconds = 60
		body, _ := io.ReadAll(c.Request.Body)
		ttlSeconds := int64(defaultTTLSeconds)
		if len(body) > 0 {
			var req struct {
				TTLSeconds int64 `json:"ttl_seconds"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
				return
			}
			if req.TTLSeconds > 0 {
				ttlSeconds = req.TTLSeconds
			}
		}
		if err := store.CommitConfirmed(c.Request.Context(), time.Duration(ttlSeconds)*time.Second); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := applyRunningConfig(c.Request.Context(), store, engine, services); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		auditLog(c, audit.Record{Action: "config.commit_confirmed", Target: "running"})
		c.JSON(http.StatusOK, gin.H{"status": "committed"})
	}
}

func confirmCommitHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := store.ConfirmCommit(c.Request.Context()); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		auditLog(c, audit.Record{Action: "config.confirm_commit", Target: "running"})
		c.JSON(http.StatusOK, gin.H{"status": "confirmed"})
	}
}

func rollbackConfigHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := store.Rollback(c.Request.Context()); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := applyRunningConfig(c.Request.Context(), store, engine, services); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		auditLog(c, audit.Record{Action: "config.rollback", Target: "running"})
		c.JSON(http.StatusOK, gin.H{"status": "rolled back"})
	}
}

func applyRunningConfig(ctx context.Context, store config.Store, engine EngineClient, services ServicesApplier) error {
	cfg, err := store.Load(ctx)
	if err != nil {
		if errors.Is(err, config.ErrNotFound) {
			return nil
		}
		return err
	}
	if services != nil {
		if err := services.Apply(ctx, cfg.Services); err != nil {
			return err
		}
	}
	if engine != nil {
		if err := engine.ConfigureInterfaces(ctx, cfg.Interfaces); err != nil {
			return err
		}
		if err := engine.ConfigureRouting(ctx, cfg.Routing); err != nil {
			return err
		}
		if err := engine.ConfigureServices(ctx, cfg.Services); err != nil {
			return err
		}
		if err := engine.Configure(ctx, cfg.DataPlane); err != nil {
			return err
		}
		snap, err := compile.CompileSnapshot(cfg)
		if err != nil {
			return err
		}
		if err := engine.ApplyRules(ctx, snap); err != nil {
			return err
		}
	}
	return nil
}

func diffConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		running, err := store.Load(c.Request.Context())
		if err != nil && !errors.Is(err, config.ErrNotFound) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		candidate, err := store.LoadCandidate(c.Request.Context())
		if err != nil && !errors.Is(err, config.ErrNotFound) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"running":   running,
			"candidate": candidate,
		})
	}
}

func getSyslogHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.Services.Syslog)
	}
}

func setSyslogHandler(store config.Store, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var syslogCfg config.SyslogConfig
		if err := c.ShouldBindJSON(&syslogCfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		cfg.Services.Syslog = syslogCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if services != nil {
			if err := services.Apply(c.Request.Context(), cfg.Services); err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
				return
			}
		}
		c.JSON(http.StatusOK, cfg.Services.Syslog)
	}
}

func getDNSHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.Services.DNS)
	}
}

func setDNSHandler(store config.Store, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var dnsCfg config.DNSConfig
		if err := c.ShouldBindJSON(&dnsCfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		cfg.Services.DNS = dnsCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if services != nil {
			if err := services.Apply(c.Request.Context(), cfg.Services); err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
				return
			}
		}
		auditLog(c, audit.Record{Action: "services.dns.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.Services.DNS)
	}
}

func getNTPHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.Services.NTP)
	}
}

func setNTPHandler(store config.Store, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var ntpCfg config.NTPConfig
		if err := c.ShouldBindJSON(&ntpCfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		cfg.Services.NTP = ntpCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if services != nil {
			if err := services.Apply(c.Request.Context(), cfg.Services); err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
				return
			}
		}
		auditLog(c, audit.Record{Action: "services.ntp.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.Services.NTP)
	}
}

func getDHCPHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.Services.DHCP)
	}
}

func setDHCPHandler(store config.Store, services ServicesApplier, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		var dhcpCfg config.DHCPConfig
		if err := c.ShouldBindJSON(&dhcpCfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		cfg.Services.DHCP = dhcpCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if services != nil {
			if err := services.Apply(c.Request.Context(), cfg.Services); err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
				return
			}
		}
		if engine != nil {
			if err := engine.ConfigureServices(c.Request.Context(), cfg.Services); err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
				return
			}
		}
		auditLog(c, audit.Record{Action: "services.dhcp.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.Services.DHCP)
	}
}

func getVPNHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.Services.VPN)
	}
}

func setVPNHandler(store config.Store, services ServicesApplier, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		var vpnCfg config.VPNConfig
		if err := c.ShouldBindJSON(&vpnCfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		cfg.Services.VPN = vpnCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if services != nil {
			if err := services.Apply(c.Request.Context(), cfg.Services); err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
				return
			}
		}
		if engine != nil {
			if err := engine.ConfigureServices(c.Request.Context(), cfg.Services); err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
				return
			}
		}
		auditLog(c, audit.Record{Action: "services.vpn.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.Services.VPN)
	}
}

func getForwardProxyHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.Services.Proxy.Forward)
	}
}

func setForwardProxyHandler(store config.Store, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var forwardCfg config.ForwardProxyConfig
		if err := c.ShouldBindJSON(&forwardCfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		cfg.Services.Proxy.Forward = forwardCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if services != nil {
			if err := services.Apply(c.Request.Context(), cfg.Services); err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
				return
			}
		}
		auditLog(c, audit.Record{Action: "services.proxy.forward.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.Services.Proxy.Forward)
	}
}

func getReverseProxyHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.Services.Proxy.Reverse)
	}
}

func setReverseProxyHandler(store config.Store, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var reverseCfg config.ReverseProxyConfig
		if err := c.ShouldBindJSON(&reverseCfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		cfg.Services.Proxy.Reverse = reverseCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if services != nil {
			if err := services.Apply(c.Request.Context(), cfg.Services); err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
				return
			}
		}
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

func listEventsHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		tc, ok := engine.(TelemetryClient)
		if !ok || tc == nil {
			c.JSON(http.StatusOK, []dpevents.Event{})
			return
		}
		limit := 500
		if q := c.Query("limit"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v > 0 {
				limit = v
			}
		}
		evs, err := tc.ListEvents(c.Request.Context(), limit)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, evs)
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
			if v, err := strconv.Atoi(q); err == nil && v > 0 {
				limit = v
			}
		}
		flows, err := tc.ListFlows(c.Request.Context(), limit)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, flows)
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
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, ents)
	}
}

func killConntrackHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		ck, ok := engine.(ConntrackKiller)
		if !ok || ck == nil {
			c.JSON(http.StatusNotImplemented, gin.H{"error": "conntrack delete not supported"})
			return
		}
		var req conntrack.DeleteRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		if err := ck.DeleteConntrack(c.Request.Context(), req); err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.DataPlane)
	}
}

func getIDSHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.IDS)
	}
}

func setIDSHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var idsCfg config.IDSConfig
		if err := c.ShouldBindJSON(&idsCfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		cfg.IDS = idsCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		auditLog(c, audit.Record{Action: "ids.rules.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.IDS)
	}
}

func convertSigmaHandler() gin.HandlerFunc {
	type req struct {
		SigmaYAML string `json:"sigmaYAML"`
	}
	return func(c *gin.Context) {
		var r req
		if err := c.ShouldBindJSON(&r); err != nil || r.SigmaYAML == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing sigmaYAML"})
			return
		}
		rule, err := cpids.ConvertSigmaYAML([]byte(r.SigmaYAML))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, rule)
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
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
			return
		}
		// Treat blank input as a no-op; the UI console may send empty lines.
		if strings.TrimSpace(r.Line) == "" {
			c.JSON(http.StatusOK, resp{Output: ""})
			return
		}
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
		if h := c.GetHeader("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
			apiClient.Token = strings.TrimSpace(h[len("bearer "):])
		} else if ck, err := c.Cookie("containd_token"); err == nil && strings.TrimSpace(ck) != "" {
			apiClient.Token = strings.TrimSpace(ck)
		}
		ctx := cli.WithRole(c.Request.Context(), c.GetString(ctxRoleKey))
		reg := cli.NewRegistry(store, apiClient)
		var buf bytes.Buffer
		if err := reg.ParseAndExecute(ctx, r.Line, &buf); err != nil {
			c.JSON(http.StatusOK, resp{Output: buf.String(), Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, resp{Output: buf.String()})
	}
}

func getFirewallNATHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.Firewall.NAT)
	}
}

func setFirewallNATHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var nat config.NATConfig
		if err := c.ShouldBindJSON(&nat); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid NAT payload"})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		cfg.Firewall.NAT = nat
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		cfg.DataPlane = dp
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Apply runtime dataplane changes immediately (including DPI mock).
		if engine != nil {
			if err := engine.Configure(c.Request.Context(), cfg.DataPlane); err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
				return
			}
		}
		auditLog(c, audit.Record{Action: "dataplane.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.DataPlane)
	}
}

func listAssetsHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.Assets)
	}
}

func createAssetHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var a config.Asset
		if err := c.ShouldBindJSON(&a); err != nil || a.ID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid asset payload"})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		for _, existing := range cfg.Assets {
			if existing.ID == a.ID {
				c.JSON(http.StatusBadRequest, gin.H{"error": "asset already exists"})
				return
			}
			if existing.Name != "" && existing.Name == a.Name {
				c.JSON(http.StatusBadRequest, gin.H{"error": "asset name already exists"})
				return
			}
		}
		cfg.Assets = append(cfg.Assets, a)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid asset payload"})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusNotFound, gin.H{"error": "asset not found"})
			return
		}
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusNotFound, gin.H{"error": "asset not found"})
			return
		}
		cfg.Assets = filtered
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		auditLog(c, audit.Record{Action: "assets.delete", Target: id})
		c.Status(http.StatusNoContent)
	}
}

func listZonesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.Zones)
	}
}

func createZoneHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var z config.Zone
		if err := c.ShouldBindJSON(&z); err != nil || z.Name == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid zone payload"})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		for _, existing := range cfg.Zones {
			if existing.Name == z.Name {
				c.JSON(http.StatusBadRequest, gin.H{"error": "zone already exists"})
				return
			}
		}
		cfg.Zones = append(cfg.Zones, z)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		for _, iface := range cfg.Interfaces {
			if iface.Zone == name {
				c.JSON(http.StatusBadRequest, gin.H{"error": "zone in use by interface"})
				return
			}
		}
		for _, rule := range cfg.Firewall.Rules {
			for _, z := range append(rule.SourceZones, rule.DestZones...) {
				if z == name {
					c.JSON(http.StatusBadRequest, gin.H{"error": "zone in use by firewall rule"})
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
			c.JSON(http.StatusNotFound, gin.H{"error": "zone not found"})
			return
		}
		cfg.Zones = filtered
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func updateZoneHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		var z config.Zone
		if err := c.ShouldBindJSON(&z); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid zone payload"})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		updated := false
		for i, existing := range cfg.Zones {
			if existing.Name == name {
				if z.Name == "" {
					z.Name = existing.Name
				}
				cfg.Zones[i] = z
				updated = true
				break
			}
		}
		if !updated {
			c.JSON(http.StatusNotFound, gin.H{"error": "zone not found"})
			return
		}
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, z)
	}
}

func listInterfacesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.Interfaces)
	}
}

func interfaceStateHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Ensure config exists (so default interfaces are seeded).
		if _, err := loadOrInitConfig(c.Request.Context(), store); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if engine == nil {
			c.JSON(http.StatusOK, []config.InterfaceState{})
			return
		}
		st, err := engine.ListInterfaceState(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, st)
	}
}

func interfacesAssignHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "engine unavailable"})
			return
		}
		var req struct {
			Mode     string            `json:"mode"`
			Mappings map[string]string `json:"mappings"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		state, err := engine.ListInterfaceState(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
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
				c.JSON(http.StatusBadRequest, gin.H{"error": "no default interfaces present"})
				return
			}
				if len(candidates) < needed {
					c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("not enough eligible kernel interfaces (%d) for defaults (%d)", len(candidates), needed)})
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

				// Prefer the kernel's default-route egress device for WAN when available.
				// This avoids confusing assignments in container labs where extra virtual/tunnel
				// interfaces may exist but are not the actual "uplink".
				if wanIface, ok := ifaceByName["wan"]; ok && wanIface != nil {
					defDev := strings.TrimSpace(detectKernelDefaultRouteIface())
					if defDev != "" && !usedDev[defDev] {
						if st, ok := stateByName[defDev]; ok && isAutoAssignableDevice(defDev, st.MAC) {
							assignments["wan"] = defDev
							usedDev[defDev] = true
						}
					}
				}

				// If Docker Compose provides stable interface names (e.g. "wan", "dmz", "lan1"...),
				// prefer those exact/prefix matches next.
				for _, logical := range order {
					if _, ok := ifaceByName[logical]; !ok {
						continue
					}
					if _, already := assignments[logical]; already {
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
						c.JSON(http.StatusBadRequest, gin.H{"error": "not enough eligible kernel interfaces to complete auto-assign"})
						return
					}
					assignments[logical] = remaining[idx].name
					idx++
				}
			case "explicit":
				if len(req.Mappings) == 0 {
					c.JSON(http.StatusBadRequest, gin.H{"error": "mappings required"})
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
			c.JSON(http.StatusBadRequest, gin.H{"error": "mode must be auto or explicit"})
			return
		}

		used := map[string]string{} // device -> logical
		for logical, dev := range assignments {
			if _, ok := ifaceByName[logical]; !ok {
				c.JSON(http.StatusBadRequest, gin.H{"error": "unknown interface: " + logical})
				return
			}
			if dev == "" {
				continue
			}
			if _, ok := deviceSet[dev]; !ok {
				c.JSON(http.StatusBadRequest, gin.H{"error": "unknown kernel device: " + dev})
				return
			}
			if prev, ok := used[dev]; ok && prev != logical {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("device %s already assigned to %s", dev, prev)})
				return
			}
			used[dev] = logical
		}

		for logical, dev := range assignments {
			ifaceByName[logical].Device = dev
		}

		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := applyRunningConfig(c.Request.Context(), store, engine, services); err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
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
			c.JSON(http.StatusBadRequest, gin.H{"error": "engine unavailable"})
			return
		}
		var req struct {
			Confirm string `json:"confirm"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Confirm) != "REPLACE" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "confirm required: set {\"confirm\":\"REPLACE\"}"})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err := engine.ConfigureInterfacesReplace(c.Request.Context(), cfg.Interfaces); err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid interface payload"})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		for _, existing := range cfg.Interfaces {
			if existing.Name == iface.Name {
				c.JSON(http.StatusBadRequest, gin.H{"error": "interface already exists"})
				return
			}
		}
		cfg.Interfaces = append(cfg.Interfaces, iface)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if engine != nil {
			if err := applyRunningConfig(c.Request.Context(), store, engine, services); err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
				return
			}
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusNotFound, gin.H{"error": "interface not found"})
			return
		}
		cfg.Interfaces = filtered
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if engine != nil {
			if err := applyRunningConfig(c.Request.Context(), store, engine, services); err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
				return
			}
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
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid interface payload"})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusNotFound, gin.H{"error": "interface not found"})
			return
		}
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if engine != nil {
			if err := applyRunningConfig(c.Request.Context(), store, engine, services); err != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
				return
			}
		}
		auditLog(c, audit.Record{Action: "interfaces.update", Target: name})
		c.JSON(http.StatusOK, iface)
	}
}

func getRoutingHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.Routing)
	}
}

func setRoutingHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var routingCfg config.RoutingConfig
		if err := c.ShouldBindJSON(&routingCfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		cfg.Routing = routingCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := applyRunningConfig(c.Request.Context(), store, engine, services); err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		auditLog(c, audit.Record{Action: "routing.set", Target: "config"})
		c.JSON(http.StatusOK, cfg.Routing)
	}
}

func routingReconcileHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "engine unavailable"})
			return
		}
		var req struct {
			Confirm string `json:"confirm"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Confirm) != "REPLACE" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "confirm required: set {\"confirm\":\"REPLACE\"}"})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err := engine.ConfigureRoutingReplace(c.Request.Context(), cfg.Routing); err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.Firewall.Rules)
	}
}

func createFirewallRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var r config.Rule
		if err := c.ShouldBindJSON(&r); err != nil || r.ID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule payload"})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		for _, existing := range cfg.Firewall.Rules {
			if existing.ID == r.ID {
				c.JSON(http.StatusBadRequest, gin.H{"error": "rule already exists"})
				return
			}
		}
		if cfg.Firewall.DefaultAction == "" {
			cfg.Firewall.DefaultAction = config.ActionDeny
		}
		cfg.Firewall.Rules = append(cfg.Firewall.Rules, r)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
			return
		}
		cfg.Firewall.Rules = filtered
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func updateFirewallRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var rule config.Rule
		if err := c.ShouldBindJSON(&rule); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule payload"})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		updated := false
		for i, existing := range cfg.Firewall.Rules {
			if existing.ID == id {
				if rule.ID == "" {
					rule.ID = existing.ID
				}
				cfg.Firewall.Rules[i] = rule
				updated = true
				break
			}
		}
		if !updated {
			c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
			return
		}
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
