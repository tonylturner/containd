// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	engineapi "github.com/tonylturner/containd/api/engine"
	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/identity"
	"github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/cp/users"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/mp/sshserver"
	"github.com/gin-gonic/gin"
)

type Options struct{}

func Run(ctx context.Context, _ Options) error {
	logger := logging.NewService("mgmt")
	jwtSecret := strings.TrimSpace(os.Getenv("CONTAIND_JWT_SECRET"))
	labMode := os.Getenv("CONTAIND_LAB_MODE") == "1" || strings.EqualFold(os.Getenv("CONTAIND_LAB_MODE"), "true")
	switch {
	case jwtSecret == "containd-dev-secret-change-me":
		if !labMode {
			return fmt.Errorf("CONTAIND_JWT_SECRET is set to the default example value; " +
				"set a unique secret (e.g. openssl rand -hex 32) or enable CONTAIND_LAB_MODE=1 for development")
		}
		logger.Warn("WARNING: CONTAIND_JWT_SECRET is default (lab mode active)")
	case jwtSecret == "":
		if !labMode {
			return fmt.Errorf("CONTAIND_JWT_SECRET is empty; set a unique secret or enable CONTAIND_LAB_MODE=1 for development")
		}
		logger.Warn("WARNING: CONTAIND_JWT_SECRET is empty (lab mode active)")
	}
	store := mustInitStore()
	defer store.Close()
	ensureDefaultConfig(logger, store)
	auditStore := mustInitAuditStore()
	defer auditStore.Close()
	userStore := mustInitUsersStore()
	defer userStore.Close()
	_ = userStore.EnsureDefaultAdmin(context.Background())

	cfg, err := store.Load(context.Background())
	if err != nil && !errors.Is(err, config.ErrNotFound) {
		logger.Warnf("failed to load config on startup: %v", err)
	}

	httpAddr := common.EnvTrimmed("CONTAIND_MGMT_ADDR", "")
	if httpAddr == "" && cfg != nil {
		httpAddr = firstNonEmpty(cfg.System.Mgmt.HTTPListenAddr, cfg.System.Mgmt.ListenAddr)
	}
	if httpAddr == "" {
		httpAddr = ":8080"
	}
	httpsAddr := ""
	if v := common.EnvTrimmed("CONTAIND_MGMT_HTTPS_ADDR", ""); v != "" {
		httpsAddr = v
	}
	if cfg != nil {
		httpsAddr = cfg.System.Mgmt.HTTPSListenAddr
	}
	if httpsAddr == "" {
		httpsAddr = ":8443"
	}

	enableHTTP := boolDefault(cfgGetBool(cfg, func(c *config.Config) *bool { return c.System.Mgmt.EnableHTTP }), true)
	enableHTTPS := boolDefault(cfgGetBool(cfg, func(c *config.Config) *bool { return c.System.Mgmt.EnableHTTPS }), true)

	var engineClient httpapi.EngineClient
	if engineURL := common.EnvTrimmed("CONTAIND_ENGINE_URL", ""); engineURL != "" {
		if !strings.Contains(engineURL, "://") {
			engineURL = "http://" + engineURL
			logger.Warnf("CONTAIND_ENGINE_URL missing scheme; using %q", engineURL)
		}
		engineClient = engineapi.NewHTTPClient(engineURL)
	}
	startDHCPLeaseAuditIngestor(ctx, logger, engineClient, auditStore)
	serviceManager := services.NewManager(services.ManagerOptions{})
	identityResolver := identity.NewResolver()
	router := httpapi.NewServerWithEngineAndServices(store, auditStore, engineClient, serviceManager, userStore, identityResolver)
	// Best-effort initial service render on startup.
	if cfg, err := store.Load(context.Background()); err == nil {
		if applyErr := serviceManager.Apply(context.Background(), cfg.Services); applyErr != nil {
			logger.Warnf("failed to apply initial service config: %v", applyErr)
		}
	}
	if serviceManager != nil {
		serviceManager.SetEventLister(func(limit int) []dpevents.Event {
			var out []dpevents.Event
			type eventLister interface {
				ListEvents(ctx context.Context, limit int) ([]dpevents.Event, error)
			}
			if ec, ok := engineClient.(eventLister); ok && ec != nil {
				if evs, err := ec.ListEvents(context.Background(), limit); err == nil {
					out = append(out, evs...)
				}
			}
			out = append(out, serviceManager.ListTelemetryEvents(limit)...)
			return out
		})
		serviceManager.StartAVWorker(context.Background())
	}
	serveStaticUI(router)

	httpLoopbackAddr := ensureLoopbackHTTPAddr(httpAddr)
	httpsLoopbackAddr := ensureLoopbackHTTPAddr(httpsAddr)

	// Enforce per-interface access toggles based on the destination IP.
	ipIndex := newIPInterfaceIndex()
	handler := mgmtAccessHandler(store, ipIndex, router)

	// Start SSH server (admin-only) for interactive CLI.
	sshAddr, sshEnabled := startSSH(logger, store, userStore, auditStore, httpAddr, httpLoopbackAddr, ipIndex)

	redirectHTTPToHTTPS := boolDefault(cfgGetBool(cfg, func(c *config.Config) *bool { return c.System.Mgmt.RedirectHTTPToHTTPS }), false)
	enableHSTS := boolDefault(cfgGetBool(cfg, func(c *config.Config) *bool { return c.System.Mgmt.EnableHSTS }), true)
	hstsMaxAge := cfgGetInt(cfg, func(c *config.Config) int { return c.System.Mgmt.HSTSMaxAgeSeconds }, 31536000)
	if hstsMaxAge <= 0 {
		hstsMaxAge = 31536000
	}

	handler = hstsHandler(enableHSTS, hstsMaxAge, handler)

	// Add CORS and frame-embedding support for external applications (e.g., RangerDanger)
	allowedOrigins := getAllowedOrigins()
	if len(allowedOrigins) > 0 {
		logger.Infof("CORS/frame-embedding enabled for origins: %v", allowedOrigins)
		handler = corsHandler(handler, allowedOrigins)
		handler = frameOptionsHandler(handler, allowedOrigins)
	}

	// Note: redirect is applied only for the plain HTTP listeners.

	tlsCert, tlsKey := resolveTLSFiles(cfg)
	if enableHTTPS {
		var err error
		tlsCert, tlsKey, err = ensureSelfSignedTLSFiles(tlsCert, tlsKey, detectIPs())
		if err != nil {
			logger.Warnf("https disabled: failed to ensure TLS cert: %v", err)
			enableHTTPS = false
		}
	}

	printStartupHints(logger, httpAddr, httpLoopbackAddr, httpsAddr, httpsLoopbackAddr, enableHTTP, enableHTTPS, sshAddr, sshEnabled)

	errCh := make(chan error, 8)
	var servers []*http.Server
	var listeners []net.Listener

	if enableHTTP {
		httpHandler := handler
		if redirectHTTPToHTTPS {
			httpHandler = redirectToHTTPSHandler(httpsAddr, httpHandler)
		}
		srv, lns, err := buildHTTPServers(httpHandler, httpAddr, httpLoopbackAddr)
		if err != nil {
			return fmt.Errorf("http disabled: %w", err)
		}
		servers = append(servers, srv...)
		listeners = append(listeners, lns...)
	}
	if enableHTTPS {
		reloader := newCertReloader(tlsCert, tlsKey)
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			GetCertificate: reloader.GetCertificate,
		}
		srv, lns, err := buildHTTPSServers(handler, httpsAddr, httpsLoopbackAddr, tlsCfg)
		if err != nil {
			return fmt.Errorf("https disabled: %w", err)
		}
		servers = append(servers, srv...)
		listeners = append(listeners, lns...)
	}

	if len(servers) == 0 {
		return fmt.Errorf("no management listeners enabled")
	}

	for i := range servers {
		s := servers[i]
		ln := listeners[i]
		go func() {
			if s.TLSConfig != nil {
				errCh <- s.Serve(tls.NewListener(ln, s.TLSConfig))
				return
			}
			errCh <- s.Serve(ln)
		}()
	}

	select {
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		for _, s := range servers {
			_ = s.Shutdown(shutdownCtx)
		}
		return ctx.Err()
	case err := <-errCh:
		for _, s := range servers {
			_ = s.Close()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("containd mgmt server exited: %w", err)
		}
		return nil
	}
}

func startDHCPLeaseAuditIngestor(ctx context.Context, logger *zap.SugaredLogger, engineClient any, auditStore audit.Store) {
	if logger == nil || auditStore == nil || engineClient == nil {
		return
	}
	type eventLister interface {
		ListEvents(ctx context.Context, limit int) ([]dpevents.Event, error)
	}
	ec, ok := engineClient.(eventLister)
	if !ok {
		return
	}

	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		var lastID uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			evs, err := ec.ListEvents(ctx, 1000)
			cancel()
			if err != nil || len(evs) == 0 {
				continue
			}

			var maxID uint64
			for _, ev := range evs {
				if ev.ID > maxID {
					maxID = ev.ID
				}
			}
			// If the engine restarted, its event IDs may reset back near zero. In that case,
			// reset our cursor so we don't silently stop recording lease churn.
			if maxID != 0 && maxID < lastID {
				lastID = 0
			}

			// Engine events are returned newest-first; iterate oldest-first to preserve order.
			for i := len(evs) - 1; i >= 0; i-- {
				ev := evs[i]
				if ev.ID == 0 || ev.ID <= lastID {
					continue
				}
				if ev.Proto != "dhcp" || !strings.HasPrefix(ev.Kind, "service.dhcp.lease.") {
					continue
				}

				dev, _ := ev.Attributes["dev"].(string)
				mac, _ := ev.Attributes["mac"].(string)
				ip, _ := ev.Attributes["ip"].(string)
				host, _ := ev.Attributes["hostname"].(string)
				exp, _ := ev.Attributes["expires_at"].(string)

				target := strings.TrimSpace(strings.Join([]string{dev, ip, mac}, " "))
				detailParts := []string{}
				if host != "" {
					detailParts = append(detailParts, "hostname="+host)
				}
				if exp != "" {
					detailParts = append(detailParts, "expires_at="+exp)
				}
				detailParts = append(detailParts, fmt.Sprintf("event_id=%d", ev.ID))

				_ = auditStore.Add(context.Background(), audit.Record{
					Timestamp: ev.Timestamp,
					Actor:     "system",
					Source:    "dhcp",
					Action:    ev.Kind,
					Target:    target,
					Result:    "ok",
					Detail:    strings.Join(detailParts, " "),
				})
				lastID = ev.ID
			}
		}
	}()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func serveStaticUI(router *gin.Engine) {
	uiDir := pickUIDir()
	if uiDir != "" {
		indexPath := filepath.Join(uiDir, "index.html")
		// Serve index at root.
		router.GET("/", func(c *gin.Context) {
			c.Header("Cache-Control", "no-store")
			c.File(indexPath)
		})
		// For all other non-API paths, try to serve a static file or fall back to index.
		router.NoRoute(func(c *gin.Context) {
			reqPath := c.Request.URL.Path
			if reqPath == "/api" || strings.HasPrefix(reqPath, "/api/") {
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}

			clean := filepath.Clean(reqPath)
			candidate := filepath.Join(uiDir, clean)
			if info, err := os.Stat(candidate); err == nil {
				if info.IsDir() {
					dirIndex := filepath.Join(candidate, "index.html")
					if _, err := os.Stat(dirIndex); err == nil {
						// Never cache HTML shells; they reference hashed asset filenames and must
						// update immediately after upgrades.
						c.Header("Cache-Control", "no-store")
						c.File(dirIndex)
						return
					}
				} else {
					// Appliance UX: always serve fresh assets so upgrades don't get stuck behind
					// browser caches (especially important for auth/session flows).
					c.Header("Cache-Control", "no-store")
					c.File(candidate)
					return
				}
			}

			c.Header("Cache-Control", "no-store")
			c.File(indexPath)
		})
		return
	}

	// Fallback simple response until the Next.js build pipeline lands.
	router.NoRoute(func(c *gin.Context) {
		c.String(http.StatusOK, "containd management API is running. UI build not found.")
	})
}

func pickUIDir() string {
	// Allow override for packaged builds.
	if override := common.Env("CONTAIND_UI_DIR", ""); override != "" {
		if dirExists(override) {
			return override
		}
	}

	// Prefer Next.js static export if present.
	candidates := []string{
		filepath.Join(".", "ui", "out"),
		filepath.Join(".", "ui", "public"),
		"/var/lib/ngfw/ui",
	}

	for _, c := range candidates {
		if dirExists(c) {
			return c
		}
	}
	return ""
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func ensureDefaultConfig(logger *zap.SugaredLogger, store config.Store) {
	if store == nil {
		return
	}
	cfg, err := store.Load(context.Background())
	if err == nil && cfg != nil {
		changed := false
		if strings.TrimSpace(cfg.System.Hostname) == "" {
			cfg.System.Hostname = "containd"
			changed = true
		}
		if strings.TrimSpace(cfg.System.Mgmt.ListenAddr) == "" {
			cfg.System.Mgmt.ListenAddr = ":8080"
			changed = true
		}
		if strings.TrimSpace(cfg.System.Mgmt.HTTPListenAddr) == "" {
			cfg.System.Mgmt.HTTPListenAddr = ":8080"
			changed = true
		}
		if strings.TrimSpace(cfg.System.Mgmt.HTTPSListenAddr) == "" {
			cfg.System.Mgmt.HTTPSListenAddr = ":8443"
			changed = true
		}
		if cfg.System.Mgmt.EnableHTTP == nil {
			cfg.System.Mgmt.EnableHTTP = boolPtr(true)
			changed = true
		}
		if cfg.System.Mgmt.EnableHTTPS == nil {
			cfg.System.Mgmt.EnableHTTPS = boolPtr(true)
			changed = true
		}
		if strings.TrimSpace(cfg.System.Mgmt.TLSCertFile) == "" {
			cfg.System.Mgmt.TLSCertFile = "/data/tls/server.crt"
			changed = true
		}
		if strings.TrimSpace(cfg.System.Mgmt.TLSKeyFile) == "" {
			cfg.System.Mgmt.TLSKeyFile = "/data/tls/server.key"
			changed = true
		}
		if changed {
			if err := store.Save(context.Background(), cfg); err != nil {
				logger.Errorf("failed to backfill default config values: %v", err)
			}
		}
		return
	}
	if !errors.Is(err, config.ErrNotFound) {
		logger.Warnf("failed to load config (continuing): %v", err)
		return
	}
	def := config.DefaultConfig()
	def.System.Hostname = "containd"
	def.System.Mgmt.ListenAddr = ":8080"
	def.System.Mgmt.HTTPListenAddr = ":8080"
	def.System.Mgmt.HTTPSListenAddr = ":8443"
	def.System.Mgmt.EnableHTTP = boolPtr(true)
	def.System.Mgmt.EnableHTTPS = boolPtr(true)
	def.System.Mgmt.TLSCertFile = "/data/tls/server.crt"
	def.System.Mgmt.TLSKeyFile = "/data/tls/server.key"
	if err := store.Save(context.Background(), def); err != nil {
		logger.Errorf("failed to initialize default config: %v", err)
		return
	}
	logger.Info("initialized default config")
}

func ensureLoopbackHTTPAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// If addr is malformed, don't attempt a loopback listener.
		return ""
	}
	h := strings.ToLower(strings.TrimSpace(host))
	switch h {
	case "", "0.0.0.0", "::", "[::]", "127.0.0.1", "localhost":
		return addr
	default:
		return net.JoinHostPort("127.0.0.1", port)
	}
}

type ctxKey int

const localIPKey ctxKey = 1

func connContextWithLocalIP(ctx context.Context, c net.Conn) context.Context {
	if c == nil {
		return ctx
	}
	host, _, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return ctx
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ctx
	}
	return context.WithValue(ctx, localIPKey, ip)
}

func localIPFromRequest(r *http.Request) net.IP {
	if r == nil {
		return nil
	}
	if v := r.Context().Value(localIPKey); v != nil {
		if ip, ok := v.(net.IP); ok {
			return ip
		}
	}
	return nil
}

func buildHTTPServers(handler http.Handler, addr string, loopbackAddr string) ([]*http.Server, []net.Listener, error) {
	var servers []*http.Server
	var listeners []net.Listener
	addrs := []string{addr}
	if loopbackAddr != "" && loopbackAddr != addr {
		addrs = append(addrs, loopbackAddr)
	}
	for _, a := range addrs {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			return nil, nil, err
		}
		srv := &http.Server{Handler: handler, ConnContext: connContextWithLocalIP}
		servers = append(servers, srv)
		listeners = append(listeners, ln)
	}
	return servers, listeners, nil
}

func buildHTTPSServers(handler http.Handler, addr string, loopbackAddr string, tlsCfg *tls.Config) ([]*http.Server, []net.Listener, error) {
	var servers []*http.Server
	var listeners []net.Listener
	addrs := []string{addr}
	if loopbackAddr != "" && loopbackAddr != addr {
		addrs = append(addrs, loopbackAddr)
	}
	for _, a := range addrs {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			return nil, nil, err
		}
		srv := &http.Server{Handler: handler, ConnContext: connContextWithLocalIP, TLSConfig: tlsCfg}
		servers = append(servers, srv)
		listeners = append(listeners, ln)
	}
	return servers, listeners, nil
}

type ipInterfaceIndex struct {
	mu         sync.RWMutex
	lastLoaded time.Time
	byIP       map[string]string
}

func newIPInterfaceIndex() *ipInterfaceIndex {
	return &ipInterfaceIndex{byIP: map[string]string{}}
}

func (idx *ipInterfaceIndex) lookup(ip net.IP) string {
	if ip == nil {
		return ""
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	key := ip4.String()

	idx.mu.RLock()
	if time.Since(idx.lastLoaded) < 30*time.Second {
		if v := idx.byIP[key]; v != "" {
			idx.mu.RUnlock()
			return v
		}
	}
	idx.mu.RUnlock()

	idx.refresh()

	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.byIP[key]
}

func (idx *ipInterfaceIndex) refresh() {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	if time.Since(idx.lastLoaded) < 30*time.Second {
		return
	}
	m := map[string]string{}
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ip := ipFromAddr(a)
				if ip == nil {
					continue
				}
				if ip4 := ip.To4(); ip4 != nil {
					m[ip4.String()] = iface.Name
				}
			}
		}
	}
	idx.byIP = m
	idx.lastLoaded = time.Now()
}

func boolPtr(v bool) *bool { return &v }

func boolDefault(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

func cfgGetBool(cfg *config.Config, f func(*config.Config) *bool) *bool {
	if cfg == nil {
		return nil
	}
	return f(cfg)
}

func cfgGetInt(cfg *config.Config, f func(*config.Config) int, def int) int {
	if cfg == nil {
		return def
	}
	return f(cfg)
}

func resolveTLSFiles(cfg *config.Config) (certFile, keyFile string) {
	certFile = strings.TrimSpace(os.Getenv("CONTAIND_TLS_CERT_FILE"))
	keyFile = strings.TrimSpace(os.Getenv("CONTAIND_TLS_KEY_FILE"))
	if certFile == "" && cfg != nil {
		certFile = cfg.System.Mgmt.TLSCertFile
	}
	if keyFile == "" && cfg != nil {
		keyFile = cfg.System.Mgmt.TLSKeyFile
	}
	if certFile == "" {
		certFile = "/data/tls/server.crt"
	}
	if keyFile == "" {
		keyFile = "/data/tls/server.key"
	}
	return certFile, keyFile
}

func hstsHandler(enabled bool, maxAgeSeconds int, next http.Handler) http.Handler {
	if !enabled {
		return next
	}
	if maxAgeSeconds <= 0 {
		maxAgeSeconds = 31536000
	}
	value := "max-age=" + strconv.Itoa(maxAgeSeconds)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r != nil && r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", value)
		}
		next.ServeHTTP(w, r)
	})
}

// corsHandler adds CORS headers to allow cross-origin requests from specified origins.
// This enables embedding the containd UI in iframes from other applications (e.g., RangerDanger).
func corsHandler(next http.Handler, allowedOrigins []string) http.Handler {
	if len(allowedOrigins) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Check if origin is allowed
		allowed := false
		for _, o := range allowedOrigins {
			o = strings.TrimSpace(o)
			if o != "" && o == origin {
				allowed = true
				break
			}
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS, PUT")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-CSRF-Token")
			w.Header().Set("Access-Control-Max-Age", "3600")
		}

		// Handle preflight OPTIONS requests
		if r.Method == http.MethodOptions {
			if allowed {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusForbidden)
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

// frameOptionsHandler sets Content-Security-Policy frame-ancestors to allow embedding in iframes
// from the specified origins.
func frameOptionsHandler(next http.Handler, allowedOrigins []string) http.Handler {
	if len(allowedOrigins) == 0 {
		return next
	}
	// Build CSP frame-ancestors directive
	cspValue := "'self'"
	for _, o := range allowedOrigins {
		o = strings.TrimSpace(o)
		if o != "" {
			cspValue += " " + o
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "frame-ancestors "+cspValue)
		next.ServeHTTP(w, r)
	})
}

// getAllowedOrigins returns the list of allowed origins for CORS and frame embedding.
// Reads from CONTAIND_ALLOWED_ORIGINS environment variable (comma-separated).
func getAllowedOrigins() []string {
	val := os.Getenv("CONTAIND_ALLOWED_ORIGINS")
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	var origins []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if p == "*" {
			// Reject wildcard origins to prevent CORS misconfiguration.
			continue
		}
		origins = append(origins, p)
	}
	return origins
}

func redirectToHTTPSHandler(httpsAddr string, next http.Handler) http.Handler {
	httpsPort := portOf(httpsAddr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil || r.TLS != nil {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		host := r.Host
		if host == "" {
			host = "localhost"
		}
		if strings.Contains(host, "@") {
			// Don't try to be clever; pass through.
			next.ServeHTTP(w, r)
			return
		}
		h, _, err := net.SplitHostPort(host)
		if err == nil && h != "" {
			host = h
		}
		if httpsPort != "" {
			host = net.JoinHostPort(host, httpsPort)
		}
		target := "https://" + host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusFound)
	})
}

type certReloader struct {
	certFile string
	keyFile  string

	mu      sync.Mutex
	cert    *tls.Certificate
	certM   time.Time
	keyM    time.Time
	lastErr error
}

func newCertReloader(certFile, keyFile string) *certReloader {
	return &certReloader{certFile: certFile, keyFile: keyFile}
}

func (r *certReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cm := modTime(r.certFile)
	km := modTime(r.keyFile)

	// Load on first use, or when files change.
	if r.cert == nil || !cm.Equal(r.certM) || !km.Equal(r.keyM) {
		c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
		if err != nil {
			r.lastErr = err
			return nil, err
		}
		r.cert = &c
		r.certM = cm
		r.keyM = km
		r.lastErr = nil
	}
	return r.cert, nil
}

func modTime(path string) time.Time {
	if path == "" {
		return time.Time{}
	}
	if st, err := os.Stat(path); err == nil {
		return st.ModTime()
	}
	return time.Time{}
}

func ensureSelfSignedTLSFiles(certFile, keyFile string, extraIPs []string) (string, string, error) {
	if certFile == "" || keyFile == "" {
		return "", "", errors.New("tls cert/key file required")
	}
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			return certFile, keyFile, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0o755); err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o755); err != nil {
		return "", "", err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", err
	}

	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "containd",
		},
		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  now.Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
	}
	for _, s := range extraIPs {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			if ip.To4() != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			}
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certFile, certOut, 0o644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyFile, keyOut, 0o600); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}

func mgmtAccessHandler(store config.Store, idx *ipInterfaceIndex, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := localIPFromRequest(r)
		if ip == nil || ip.IsLoopback() {
			next.ServeHTTP(w, r)
			return
		}
		if store == nil {
			next.ServeHTTP(w, r)
			return
		}
		cfg, err := store.Load(r.Context())
		if err != nil || cfg == nil {
			next.ServeHTTP(w, r)
			return
		}
		ifaceName := ""
		if idx != nil {
			ifaceName = idx.lookup(ip)
		}
		allowed := mgmtAllowedOnInterface(cfg, ifaceName, r.TLS != nil)
		if !allowed {
			http.Error(w, "management access disabled on this interface", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func mgmtAllowedOnInterface(cfg *config.Config, ifaceName string, isTLS bool) bool {
	if cfg == nil {
		return true
	}
	// Always allow loopback/unknown; operators must always be able to reach localhost.
	if ifaceName == "" {
		return true
	}
	for _, iface := range cfg.Interfaces {
		effectiveDev := strings.TrimSpace(iface.Device)
		if effectiveDev == "" {
			effectiveDev = iface.Name
		}
		if effectiveDev != ifaceName && iface.Name != ifaceName {
			continue
		}
		mgmt := boolDefault(iface.Access.Mgmt, true)
		if !mgmt {
			return false
		}
		if isTLS {
			return boolDefault(iface.Access.HTTPS, true)
		}
		return boolDefault(iface.Access.HTTP, true)
	}
	// If we can't map the interface, default allow (backward compatible).
	return true
}

func sshAllowedOnInterface(cfg *config.Config, ifaceName string) bool {
	if cfg == nil {
		return true
	}
	if ifaceName == "" {
		return true
	}
	for _, iface := range cfg.Interfaces {
		effectiveDev := strings.TrimSpace(iface.Device)
		if effectiveDev == "" {
			effectiveDev = iface.Name
		}
		if effectiveDev != ifaceName && iface.Name != ifaceName {
			continue
		}
		return boolDefault(iface.Access.SSH, true)
	}
	return true
}

// MgmtAllowedOnInterface exposes the access check for tests and wrappers.
func MgmtAllowedOnInterface(cfg *config.Config, ifaceName string, isTLS bool) bool {
	return mgmtAllowedOnInterface(cfg, ifaceName, isTLS)
}

// SSHAllowedOnInterface exposes the SSH access check for tests and wrappers.
func SSHAllowedOnInterface(cfg *config.Config, ifaceName string) bool {
	return sshAllowedOnInterface(cfg, ifaceName)
}

func startSSH(logger *zap.SugaredLogger, store config.Store, userStore users.Store, auditStore audit.Store, httpAddr string, loopbackAddr string, idx *ipInterfaceIndex) (string, bool) {
	ctx := context.Background()
	sshAddr := common.EnvTrimmed("CONTAIND_SSH_ADDR", "")
	authKeysDir := common.Env("CONTAIND_SSH_AUTH_KEYS_DIR", "")
	hostKeyPath := common.Env("CONTAIND_SSH_HOST_KEY", "")
	bootstrapKey := common.EnvTrimmed("CONTAIND_SSH_BOOTSTRAP_ADMIN_KEY", "")
	bootstrapUser := common.EnvTrimmed("CONTAIND_SSH_BOOTSTRAP_ADMIN_USER", "")
	allowPasswordEnv := common.EnvTrimmed("CONTAIND_SSH_ALLOW_PASSWORD", "")

	cfg, _ := store.Load(ctx)
	if sshAddr == "" && cfg != nil && cfg.System.SSH.ListenAddr != "" {
		sshAddr = cfg.System.SSH.ListenAddr
	}
	if sshAddr == "" {
		sshAddr = ":2222"
	}
	if authKeysDir == "" && cfg != nil && cfg.System.SSH.AuthorizedKeysDir != "" {
		authKeysDir = cfg.System.SSH.AuthorizedKeysDir
	}
	if authKeysDir == "" {
		authKeysDir = "/data/ssh/authorized_keys.d"
	}
	if hostKeyPath == "" {
		hostKeyPath = "/data/ssh/host_key"
	}

	lab := os.Getenv("CONTAIND_LAB_MODE") == "1" || strings.EqualFold(os.Getenv("CONTAIND_LAB_MODE"), "true")
	allowPassword := lab
	if cfg != nil && cfg.System.SSH.AllowPassword {
		allowPassword = true
	}
	// Bootstrap: if no authorized keys exist yet, allow password auth so an admin can get in.
	if !allowPassword && !lab {
		if entries, err := os.ReadDir(authKeysDir); err == nil {
			if len(entries) == 0 {
				allowPassword = true
			}
		} else {
			allowPassword = true
		}
	}
	if allowPasswordEnv != "" {
		allowPassword = allowPasswordEnv == "1" || strings.EqualFold(allowPasswordEnv, "true") || strings.EqualFold(allowPasswordEnv, "yes")
	}

	baseURL := "http://127.0.0.1:8080"
	if loopbackAddr != "" && loopbackAddr != httpAddr {
		baseURL = "http://" + loopbackAddr
	} else if httpAddr != "" {
		// If mgmt listens on all interfaces, localhost should still work.
		_, port, err := net.SplitHostPort(httpAddr)
		if err == nil && port != "" {
			baseURL = "http://127.0.0.1:" + port
		}
	}

	opts := sshserver.Options{
		ListenAddr:        sshAddr,
		BaseURL:           baseURL,
		HostKeyPath:       hostKeyPath,
		AuthorizedKeysDir: authKeysDir,
		AllowPassword:       allowPassword,
		Banner:              func() string { if cfg != nil { return cfg.System.SSH.Banner }; return "" }(),
		HostKeyRotationDays: func() int { if cfg != nil { return cfg.System.SSH.HostKeyRotationDays }; return 0 }(),
		LabMode:             lab,
		JWTSecret:         []byte(strings.TrimSpace(os.Getenv("CONTAIND_JWT_SECRET"))),
		UserStore:         userStore,
		AuditStore:        auditStore,
		AllowLocalIP: func(ip net.IP) bool {
			if ip == nil || ip.IsLoopback() {
				return true
			}
			cfg, _ := store.Load(context.Background())
			ifaceName := ""
			if idx != nil {
				ifaceName = idx.lookup(ip)
			}
			return sshAllowedOnInterface(cfg, ifaceName)
		},
	}
	srv, err := sshserver.New(opts)
	if err != nil {
		logger.Warnf("ssh disabled: %v", err)
		return "", false
	}
	srv.EnsureAuthorizedKeysDir()

	// Optional one-time bootstrap: seed the admin's authorized key file from an env var.
	// This avoids a chicken/egg problem in production container deployments.
	if bootstrapKey != "" {
		if bootstrapUser == "" {
			bootstrapUser = "containd"
		}
		if err := srv.SeedAuthorizedKey(bootstrapUser, bootstrapKey); err != nil {
			logger.Errorf("ssh bootstrap key seed failed: %v", err)
		}
	}

	go func() {
		if err := srv.ListenAndServe(context.Background()); err != nil {
			logger.Errorf("ssh server exited: %v", err)
		}
	}()
	logger.Infof("ssh enabled on %s (admin only)", sshAddr)
	return sshAddr, true
}

func printStartupHints(logger *zap.SugaredLogger, httpAddr string, httpLoopbackAddr string, httpsAddr string, httpsLoopbackAddr string, enableHTTP bool, enableHTTPS bool, sshAddr string, sshEnabled bool) {
	httpPort := portOf(httpAddr)
	httpsPort := portOf(httpsAddr)
	sshPort := portOf(sshAddr)

	logger.Info("------------------------------------------------------------")
	logger.Info("containd access")

	if enableHTTP && httpPort != "" {
		logger.Infof("UI/API (HTTP):  http://localhost:%s", httpPort)
	}
	if enableHTTPS && httpsPort != "" {
		logger.Infof("UI/API (HTTPS): https://localhost:%s (self-signed by default)", httpsPort)
	}

	if sshEnabled && sshPort != "" {
		logger.Infof("SSH CLI: ssh -p %s containd@localhost", sshPort)
		logger.Info("         then type: wizard or menu")
	}

	ips := detectIPs()
	if len(ips) > 0 && httpPort != "" {
		logger.Infof("Container IPs: %s", strings.Join(ips, ", "))
		if enableHTTP && bindsAll(httpAddr) {
			for _, ip := range ips {
				logger.Infof("UI/API via IP (HTTP):  http://%s:%s", ip, httpPort)
				if sshEnabled && sshPort != "" {
					logger.Infof("SSH via IP:    ssh -p %s containd@%s", sshPort, ip)
				}
			}
		} else if enableHTTP && hostOnly(httpAddr) {
			logger.Infof("UI/API bind is restricted to %s; use localhost or reconfigure.", httpAddr)
		}
	}

	logger.Info("Initial login: username=containd password=containd (change immediately)")
	logger.Info("Production note: add SSH key and disable password auth after provisioning.")
	logger.Info("  - CONTAIND_SSH_BOOTSTRAP_ADMIN_KEY=\"ssh-ed25519 AAAA...\"")
	logger.Info("Tip: docker compose logs -f containd")
	logger.Info("------------------------------------------------------------")
}

func portOf(addr string) string {
	if strings.TrimSpace(addr) == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		_ = host
		return port
	}
	// tolerate ":8080" without host (SplitHostPort already handles it),
	// but keep this fallback for odd values.
	if i := strings.LastIndex(addr, ":"); i != -1 && i+1 < len(addr) {
		return strings.TrimSpace(addr[i+1:])
	}
	return ""
}

func bindsAll(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "" || h == "0.0.0.0" || h == "::" || h == "[::]"
}

func hostOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "127.0.0.1" || h == "localhost"
}

func detectIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip := ipFromAddr(a)
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				if isRFC1918(ip4) {
					out = append(out, ip4.String())
				}
			}
		}
	}
	return out
}

func ipFromAddr(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		_, ipnet, err := net.ParseCIDR(a.String())
		if err == nil && ipnet != nil {
			return ipnet.IP
		}
	}
	return nil
}

func isRFC1918(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	switch {
	case ip4[0] == 10:
		return true
	case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
		return true
	case ip4[0] == 192 && ip4[1] == 168:
		return true
	default:
		return false
	}
}

func mustInitStore() config.Store {
	dbPath := common.Env("CONTAIND_CONFIG_DB", filepath.Join("data", "config.db"))
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		logging.NewService("mgmt").Fatalf("failed to create config dir: %v", err)
	}
	store, err := config.NewSQLiteStore(dbPath)
	if err != nil {
		logging.NewService("mgmt").Fatalf("failed to open config store: %v", err)
	}
	return store
}

func mustInitAuditStore() audit.Store {
	dbPath := common.Env("CONTAIND_AUDIT_DB", filepath.Join("data", "audit.db"))
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		logging.NewService("mgmt").Fatalf("failed to create audit dir: %v", err)
	}
	store, err := audit.NewSQLiteStore(dbPath)
	if err != nil {
		logging.NewService("mgmt").Fatalf("failed to open audit store: %v", err)
	}
	return store
}

func mustInitUsersStore() users.Store {
	dbPath := common.Env("CONTAIND_USERS_DB", filepath.Join("data", "users.db"))
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		// If the requested path isn't writable (common in distroless/nonroot),
		// fall back to a local data dir that should be writable in dev images.
		fallback := filepath.Join("data", "users.db")
		if fallback != dbPath {
			_ = os.MkdirAll(filepath.Dir(fallback), 0o755)
			logging.NewService("mgmt").Warnf("users db path %s not writable (%v); falling back to %s", dbPath, err, fallback)
			dbPath = fallback
		} else {
			logging.NewService("mgmt").Fatalf("failed to create users dir: %v", err)
		}
	}
	store, err := users.NewSQLiteStore(dbPath)
	if err != nil {
		logging.NewService("mgmt").Fatalf("failed to open users store: %v", err)
	}
	return store
}
