// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

func resolveEngineURL(logger *zap.SugaredLogger, opts Options) string {
	engineURL := common.EnvTrimmed("CONTAIND_ENGINE_URL", "")
	if engineURL == "" && opts.Combined {
		engineAddr := common.EnvTrimmed("CONTAIND_ENGINE_ADDR", "")
		if engineAddr == "" {
			engineAddr = ":8081"
		}
		if derived, ok := localEngineURL(engineAddr); ok {
			engineURL = derived
			logger.Infof("CONTAIND_ENGINE_URL not set; using local engine URL %q for combined mode", engineURL)
		}
	}
	if engineURL == "" {
		return ""
	}
	if !strings.Contains(engineURL, "://") {
		engineURL = "http://" + engineURL
		logger.Warnf("CONTAIND_ENGINE_URL missing scheme; using %q", engineURL)
	}
	return engineURL
}

func localEngineURL(addr string) (string, bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", false
	}
	if strings.Count(addr, ":") == 0 {
		return "http://" + net.JoinHostPort("127.0.0.1", addr), true
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", false
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port), true
}

func startDHCPLeaseAuditIngestor(ctx context.Context, logger *zap.SugaredLogger, engineClient any, auditStore audit.Store) {
	ec, ok := dhcpLeaseEventLister(logger, engineClient, auditStore)
	if !ok {
		return
	}

	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		var lastID uint64
		for {
			if !waitDHCPLeaseAuditTick(ctx, ticker) {
				return
			}
			evs, err := fetchDHCPLeaseEvents(ec)
			if err != nil || len(evs) == 0 {
				continue
			}
			lastID = ingestDHCPLeaseAuditEvents(auditStore, evs, lastID)
		}
	}()
}

type dhcpLeaseEventListClient interface {
	ListEvents(ctx context.Context, limit int) ([]dpevents.Event, error)
}

func dhcpLeaseEventLister(logger *zap.SugaredLogger, engineClient any, auditStore audit.Store) (dhcpLeaseEventListClient, bool) {
	if logger == nil || auditStore == nil || engineClient == nil {
		return nil, false
	}
	ec, ok := engineClient.(dhcpLeaseEventListClient)
	if !ok {
		return nil, false
	}
	return ec, true
}

func waitDHCPLeaseAuditTick(ctx context.Context, ticker *time.Ticker) bool {
	select {
	case <-ctx.Done():
		return false
	case <-ticker.C:
		return true
	}
}

func fetchDHCPLeaseEvents(ec dhcpLeaseEventListClient) ([]dpevents.Event, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return ec.ListEvents(ctx, 1000)
}

func ingestDHCPLeaseAuditEvents(auditStore audit.Store, evs []dpevents.Event, lastID uint64) uint64 {
	if maxID := highestDHCPLeaseEventID(evs); maxID != 0 && maxID < lastID {
		lastID = 0
	}

	for i := len(evs) - 1; i >= 0; i-- {
		ev := evs[i]
		if !shouldAuditDHCPLeaseEvent(ev, lastID) {
			continue
		}
		_ = auditStore.Add(context.Background(), dhcpLeaseAuditRecord(ev))
		lastID = ev.ID
	}
	return lastID
}

func highestDHCPLeaseEventID(evs []dpevents.Event) uint64 {
	var maxID uint64
	for _, ev := range evs {
		if ev.ID > maxID {
			maxID = ev.ID
		}
	}
	return maxID
}

func shouldAuditDHCPLeaseEvent(ev dpevents.Event, lastID uint64) bool {
	if ev.ID == 0 || ev.ID <= lastID {
		return false
	}
	return ev.Proto == "dhcp" && strings.HasPrefix(ev.Kind, "service.dhcp.lease.")
}

func dhcpLeaseAuditRecord(ev dpevents.Event) audit.Record {
	dev, _ := ev.Attributes["dev"].(string)
	mac, _ := ev.Attributes["mac"].(string)
	ip, _ := ev.Attributes["ip"].(string)
	host, _ := ev.Attributes["hostname"].(string)
	exp, _ := ev.Attributes["expires_at"].(string)

	detailParts := []string{}
	if host != "" {
		detailParts = append(detailParts, "hostname="+host)
	}
	if exp != "" {
		detailParts = append(detailParts, "expires_at="+exp)
	}
	detailParts = append(detailParts, fmt.Sprintf("event_id=%d", ev.ID))

	return audit.Record{
		Timestamp: ev.Timestamp,
		Actor:     "system",
		Source:    "dhcp",
		Action:    ev.Kind,
		Target:    strings.TrimSpace(strings.Join([]string{dev, ip, mac}, " ")),
		Result:    "ok",
		Detail:    strings.Join(detailParts, " "),
	}
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

	for _, candidate := range candidates {
		if dirExists(candidate) {
			return candidate
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
	config.ApplyBootstrapEnvDefaults(def)
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
	host = strings.ToLower(strings.TrimSpace(host))
	switch host {
	case "", "0.0.0.0", "::", "[::]", "127.0.0.1", "localhost":
		return addr
	default:
		return net.JoinHostPort("127.0.0.1", port)
	}
}
