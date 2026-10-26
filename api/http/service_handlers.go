// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
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
func patchSyslogHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var patch syslogPatch
		if err := c.ShouldBindJSON(&patch); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		if patch.Forwarder != nil {
			if err := cpservices.ValidateSyslogForwarder(*patch.Forwarder); err != nil {
				apiError(c, http.StatusBadRequest, err.Error())
				return
			}
		}
		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
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
			return true
		})
		if !ok {
			return
		}

		auditLog(c, audit.Record{Action: "services.syslog.patch", Target: "candidate", Detail: "candidate"})
		c.JSON(http.StatusOK, cfg.Services.Syslog)
	}
}

func getSyslogHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.LoadCandidate(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Services.Syslog)
	}
}

func setSyslogHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var syslogCfg config.SyslogConfig
		if err := c.ShouldBindJSON(&syslogCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			cfg.Services.Syslog = syslogCfg
			return true
		})
		if !ok {
			return
		}

		auditLog(c, audit.Record{Action: "services.syslog.set", Target: "candidate", Detail: "candidate"})
		c.JSON(http.StatusOK, cfg.Services.Syslog)
	}
}

func getDNSHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.LoadCandidate(c.Request.Context())
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
		if v, ok := services.(ServicesValidator); ok && v != nil {
			current, err := store.LoadCandidate(c.Request.Context())
			if err != nil {
				internalError(c, err)
				return
			}
			next := current.Services
			next.DNS = dnsCfg
			if err := v.Validate(c.Request.Context(), next); err != nil {
				apiError(c, http.StatusBadRequest, err.Error())
				return
			}
		}
		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			cfg.Services.DNS = dnsCfg
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "services.dns.set", Target: "candidate", Detail: "candidate"})
		c.JSON(http.StatusOK, cfg.Services.DNS)
	}
}

func getNTPHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.LoadCandidate(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Services.NTP)
	}
}

func setNTPHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var ntpCfg config.NTPConfig
		if err := c.ShouldBindJSON(&ntpCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			cfg.Services.NTP = ntpCfg
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "services.ntp.set", Target: "candidate", Detail: "candidate"})
		c.JSON(http.StatusOK, cfg.Services.NTP)
	}
}

func getAVHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.LoadCandidate(c.Request.Context())
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
		if v, ok := services.(ServicesValidator); ok && v != nil {
			current, err := store.LoadCandidate(c.Request.Context())
			if err != nil {
				internalError(c, err)
				return
			}
			next := current.Services
			next.AV = avCfg
			if err := v.Validate(c.Request.Context(), next); err != nil {
				apiError(c, http.StatusBadRequest, err.Error())
				return
			}
		}
		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			cfg.Services.AV = avCfg
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "services.av.set", Target: "candidate", Detail: "candidate"})
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
		cfg, err := store.LoadCandidate(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Services.DHCP)
	}
}

func setDHCPHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var dhcpCfg config.DHCPConfig
		if err := c.ShouldBindJSON(&dhcpCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			cfg.Services.DHCP = dhcpCfg
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "services.dhcp.set", Target: "candidate", Detail: "candidate"})
		c.JSON(http.StatusOK, cfg.Services.DHCP)
	}
}

func getForwardProxyHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.LoadCandidate(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Services.Proxy.Forward)
	}
}

func setForwardProxyHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var forwardCfg config.ForwardProxyConfig
		if err := c.ShouldBindJSON(&forwardCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			cfg.Services.Proxy.Forward = forwardCfg
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "services.proxy.forward.set", Target: "candidate", Detail: "candidate"})
		c.JSON(http.StatusOK, cfg.Services.Proxy.Forward)
	}
}

func getReverseProxyHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.LoadCandidate(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Services.Proxy.Reverse)
	}
}

func setReverseProxyHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var reverseCfg config.ReverseProxyConfig
		if err := c.ShouldBindJSON(&reverseCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			cfg.Services.Proxy.Reverse = reverseCfg
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "services.proxy.reverse.set", Target: "candidate", Detail: "candidate"})
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
