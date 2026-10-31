// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	engineapi "github.com/tonylturner/containd/api/engine"
	httpapi "github.com/tonylturner/containd/api/http"
	engineapp "github.com/tonylturner/containd/pkg/app/engine"
	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/common/enginetransport"
	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/common/mgmttls"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"go.uber.org/zap"
)

func resolveEngineURL(logger *zap.SugaredLogger, opts Options) (*enginetransport.Target, error) {
	raw := common.EnvTrimmed("CONTAIND_ENGINE_URL", "")
	inProcess := opts.Combined || opts.Reservation != nil
	addr := engineapp.ListenAddr(opts.Combined)
	if inProcess {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid CONTAIND_ENGINE_ADDR for CONTAIND_ENGINE_URL")
		}
		if !enginetransport.LocalHost(host) && strings.HasPrefix(strings.ToLower(raw), "http://") {
			return nil, fmt.Errorf("CONTAIND_ENGINE_URL must use HTTPS when CONTAIND_ENGINE_ADDR is non-loopback")
		}
	}
	if raw == "" && inProcess {
		derived, ok := localEngineURL(addr)
		if !ok {
			return nil, fmt.Errorf("invalid CONTAIND_ENGINE_ADDR for deriving CONTAIND_ENGINE_URL")
		}
		raw = derived
	}
	if raw == "" {
		return nil, nil
	}
	target, err := enginetransport.Resolve(raw)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	if inProcess && !enginetransport.LocalHost(host) && strings.HasPrefix(target.URL(), "http://") {
		return nil, fmt.Errorf("CONTAIND_ENGINE_URL must use HTTPS when CONTAIND_ENGINE_ADDR is non-loopback")
	}
	logger.Debug("engine transport target validated")
	return target, nil
}

func localEngineURL(addr string) (string, bool) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", false
	}
	scheme := "https"
	if enginetransport.LocalHost(host) {
		scheme = "http"
	}
	if host == "" {
		host = "127.0.0.1"
	} else if a, err := netip.ParseAddr(host); err == nil && a.Unmap().IsUnspecified() {
		host = "127.0.0.1"
		if a.Unmap().Is6() {
			host = "::1"
		}
	}
	return scheme + "://" + net.JoinHostPort(host, port), true
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
		if err := auditStore.Add(context.Background(), dhcpLeaseAuditRecord(ev)); err != nil {
			return lastID
		}
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

func ensureDefaultConfig(logger *zap.SugaredLogger, store config.Store) error {
	if store == nil {
		return nil
	}
	cfg, err := store.Load(context.Background())
	if err == nil && cfg != nil {
		_, repairErr := config.Repair(context.Background(), store, func(next *config.Config) error {
			if strings.TrimSpace(next.System.Hostname) == "" {
				next.System.Hostname = "containd"
			}
			if strings.TrimSpace(next.System.Mgmt.ListenAddr) == "" {
				next.System.Mgmt.ListenAddr = config.DefaultManagementHTTPAddr
			}
			if strings.TrimSpace(next.System.Mgmt.HTTPListenAddr) == "" {
				next.System.Mgmt.HTTPListenAddr = config.DefaultManagementHTTPAddr
			}
			if strings.TrimSpace(next.System.Mgmt.HTTPSListenAddr) == "" {
				next.System.Mgmt.HTTPSListenAddr = config.DefaultManagementHTTPSAddr
			}
			if next.System.Mgmt.EnableHTTP == nil {
				next.System.Mgmt.EnableHTTP = boolPtr(true)
			}
			if next.System.Mgmt.EnableHTTPS == nil {
				next.System.Mgmt.EnableHTTPS = boolPtr(true)
			}
			if strings.TrimSpace(next.System.Mgmt.TLSCertFile) == "" {
				next.System.Mgmt.TLSCertFile = mgmttls.DefaultCertFile
			}
			if strings.TrimSpace(next.System.Mgmt.TLSKeyFile) == "" {
				next.System.Mgmt.TLSKeyFile = mgmttls.DefaultKeyFile
			}
			return nil
		})
		if repairErr != nil {
			logger.Warnf("backfill default config: %v", repairErr)
		}
		return nil
	}
	if !errors.Is(err, config.ErrNotFound) {
		return fmt.Errorf("load default config: %w", err)
	}
	def := httpapi.ApplianceDefaults(config.ReservationForStore(store))
	if err := store.Save(context.Background(), def); err != nil {
		return fmt.Errorf("initialize default config: %w", err)
	}
	logger.Info("initialized default config")
	return nil
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

// validateReservedStartup checks effective environment-resolved listeners as well
// as the pure configured aliases checked by ValidateManagementReservation.
func validateReservedStartup(cfg *config.Config, r *mgmtpath.Reservation) error {
	if r == nil {
		return nil
	}
	l := config.EffectiveManagementListeners(cfg)
	if err := r.ValidateListen(l.HTTP.Addr); err != nil {
		return err
	}
	if l.HTTPS.Enabled && config.ManagementListenerConflictsHTTP(l.HTTPS.Addr, l.HTTP.Addr, true, r) {
		return fmt.Errorf("effective HTTPS listener conflicts with reserved management path")
	}
	if config.ManagementListenerConflictsHTTP(l.SSH.Addr, l.HTTP.Addr, false, r) {
		return fmt.Errorf("effective SSH listener conflicts with reserved management path")
	}
	return nil
}

// No management-owned service may start until the engine has subscribed and
// completed its initial guard scan. This also orders split-process startup.
func waitForReservedEngine(ctx context.Context, client *engineapi.HTTPClient, r *mgmtpath.Reservation) error {
	if r == nil {
		return nil
	}
	if client == nil {
		return fmt.Errorf("reserved management path requires an engine target")
	}
	u, err := url.Parse(client.BaseURL)
	if err != nil || u.Scheme != "http" || r.ValidateEngineBind(u.Host) != nil {
		return fmt.Errorf("reserved management path requires a loopback HTTP engine URL")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	health := managementGuardHealth(client)
	var last error
	for {
		h, err := health(ctx)
		if err == nil {
			same := len(h.Sources) == len(r.Sources)
			for _, source := range r.Sources {
				found := false
				for _, s := range h.Sources {
					if s == source.String() {
						found = true
					}
				}
				same = same && found
			}
			if h.Active && h.Error == "" && h.Device == r.Device && h.Local == r.Local.String() && h.Port == r.Port && same {
				return nil
			}
			last = fmt.Errorf("engine reservation guard is not ready or does not match startup authority")
		} else {
			last = err
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("reserved management path engine guard: %w: %v", ctx.Err(), last)
		case <-time.After(100 * time.Millisecond):
		}
	}
}
