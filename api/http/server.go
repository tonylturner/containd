package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
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
	ApplyRules(ctx context.Context, snap rules.Snapshot) error
}

type TelemetryClient interface {
	ListEvents(ctx context.Context, limit int) ([]dpevents.Event, error)
	ListFlows(ctx context.Context, limit int) ([]dpevents.FlowSummary, error)
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
		protected.POST("/services/syslog", requireAdmin(), setSyslogHandler(store))
		protected.GET("/services/dns", getDNSHandler(store))
		protected.POST("/services/dns", requireAdmin(), setDNSHandler(store))
		protected.GET("/services/ntp", getNTPHandler(store))
		protected.POST("/services/ntp", requireAdmin(), setNTPHandler(store))
		protected.GET("/services/proxy/forward", getForwardProxyHandler(store))
		protected.POST("/services/proxy/forward", requireAdmin(), setForwardProxyHandler(store))
		protected.GET("/services/proxy/reverse", getReverseProxyHandler(store))
		protected.POST("/services/proxy/reverse", requireAdmin(), setReverseProxyHandler(store))
		protected.GET("/services/status", getServicesStatusHandler(services))
		protected.GET("/events", listEventsHandler(engine))
		protected.GET("/flows", listFlowsHandler(engine))
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
		protected.POST("/interfaces", requireAdmin(), createInterfaceHandler(store))
		protected.PATCH("/interfaces/:name", requireAdmin(), updateInterfaceHandler(store))
		protected.DELETE("/interfaces/:name", requireAdmin(), deleteInterfaceHandler(store))
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
		cfg, err := store.Load(c.Request.Context())
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
				// NOTE: password auth is controlled by runtime bootstrap logic; don't force it in config here.
				_ = store.Save(c.Request.Context(), def)
				c.JSON(http.StatusOK, def)
				return
			}
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

func setSyslogHandler(store config.Store) gin.HandlerFunc {
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

func setDNSHandler(store config.Store) gin.HandlerFunc {
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

func setNTPHandler(store config.Store) gin.HandlerFunc {
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
		auditLog(c, audit.Record{Action: "services.ntp.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.Services.NTP)
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

func setForwardProxyHandler(store config.Store) gin.HandlerFunc {
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

func setReverseProxyHandler(store config.Store) gin.HandlerFunc {
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
		if err := c.ShouldBindJSON(&r); err != nil || r.Line == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing line"})
			return
		}
		baseURL := "http://" + c.Request.Host
		if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
			baseURL = proto + "://" + c.Request.Host
		}
		apiClient := &cli.API{BaseURL: baseURL}
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

func createInterfaceHandler(store config.Store) gin.HandlerFunc {
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
		c.JSON(http.StatusOK, iface)
	}
}

func deleteInterfaceHandler(store config.Store) gin.HandlerFunc {
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
		c.Status(http.StatusNoContent)
	}
}

func updateInterfaceHandler(store config.Store) gin.HandlerFunc {
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
		auditLog(c, audit.Record{Action: "interfaces.update", Target: name})
		c.JSON(http.StatusOK, iface)
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
			return def, nil
		}
		return nil, err
	}
	if cfg.Firewall.DefaultAction == "" {
		cfg.Firewall.DefaultAction = config.ActionDeny
	}
	return cfg, nil
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
