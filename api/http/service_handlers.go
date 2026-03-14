// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	cpservices "github.com/tonylturner/containd/pkg/cp/services"
)

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
		if name == "." || name == ".." || strings.ContainsAny(name, `/\\`) {
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
