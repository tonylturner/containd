// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	engineclient "github.com/tonylturner/containd/api/engine"
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
		cfg, err := readCandidate(c, store)
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
		cfg, err := readCandidate(c, store)
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
			current, err := loadCandidateDocument(c.Request.Context(), store)
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
		cfg, err := readCandidate(c, store)
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
		cfg, err := readCandidate(c, store)
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
			current, err := loadCandidateDocument(c.Request.Context(), store)
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

// engineAVError passes engine request errors through and reports any other
// failure as the engine antivirus being unavailable. Management never
// substitutes local state for the engine's.
func engineAVError(c *gin.Context, err error) {
	var se *engineclient.StatusError
	if errors.As(err, &se) && se.Code >= 400 && se.Code < 500 {
		apiError(c, se.Code, se.Detail)
		return
	}
	apiErrorDetail(c, http.StatusServiceUnavailable, "engine antivirus unavailable", err.Error())
}

func engineUnavailable(c *gin.Context) {
	apiError(c, http.StatusServiceUnavailable, "engine unavailable")
}

func triggerAVUpdateHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			engineUnavailable(c)
			return
		}
		if err := engine.TriggerAVUpdate(c.Request.Context()); err != nil {
			engineAVError(c, err)
			return
		}
		auditLog(c, audit.Record{Action: "services.av.update", Target: "engine"})
		c.JSON(http.StatusAccepted, gin.H{"status": "freshclam started"})
	}
}

func listAVDefsHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			engineUnavailable(c)
			return
		}
		list, err := engine.ListAVDefs(c.Request.Context())
		if err != nil {
			engineAVError(c, err)
			return
		}
		c.JSON(http.StatusOK, list)
	}
}

// uploadAVDefHandler streams the multipart "file" part to the engine without
// storing it on management.
func uploadAVDefHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			engineUnavailable(c)
			return
		}
		mr, err := c.Request.MultipartReader()
		if err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "file is required", err.Error())
			return
		}
		for {
			part, err := mr.NextPart()
			if err != nil {
				apiErrorDetail(c, http.StatusBadRequest, "file is required", err.Error())
				return
			}
			if part.FormName() != "file" {
				_ = part.Close()
				continue
			}
			name := filepath.Base(part.FileName())
			if err := cpservices.ValidateDefinitionName(name); err != nil {
				apiError(c, http.StatusBadRequest, err.Error())
				return
			}
			def, err := engine.UploadAVDef(c.Request.Context(), name, part)
			if err != nil {
				engineAVError(c, err)
				return
			}
			auditLog(c, audit.Record{Action: "services.av.defs.upload", Target: name})
			c.JSON(http.StatusOK, gin.H{"status": "uploaded", "file": def.Name, "active": def.Active})
			return
		}
	}
}

func deleteAVDefHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		file := strings.TrimSpace(c.Query("file"))
		if file == "" {
			apiError(c, http.StatusBadRequest, "file query parameter required")
			return
		}
		if engine == nil {
			engineUnavailable(c)
			return
		}
		if err := engine.DeleteAVDef(c.Request.Context(), file); err != nil {
			engineAVError(c, err)
			return
		}
		auditLog(c, audit.Record{Action: "services.av.defs.delete", Target: file})
		c.JSON(http.StatusOK, gin.H{"status": "deleted", "file": file})
	}
}

func getDHCPHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := readCandidate(c, store)
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
		cfg, err := readCandidate(c, store)
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
		cfg, err := readCandidate(c, store)
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

// getServicesStatusHandler reports management-run services and the engine's
// antivirus status. An unreachable engine is reported in the av entry, never
// replaced with management state.
func getServicesStatusHandler(services ServicesApplier, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		out := map[string]any{}
		if s, ok := services.(interface{ Status() any }); ok && s != nil {
			if m, ok := s.Status().(map[string]any); ok {
				out = m
			}
		}
		out["av"] = engineAVStatus(c.Request.Context(), engine)
		c.JSON(http.StatusOK, out)
	}
}

func engineAVStatus(ctx context.Context, engine EngineClient) map[string]any {
	if engine == nil {
		return map[string]any{"available": false, "error": "engine unavailable"}
	}
	status, err := engine.AVStatus(ctx)
	if err != nil {
		return map[string]any{"available": false, "error": err.Error()}
	}
	if status == nil {
		status = map[string]any{}
	}
	status["available"] = true
	return status
}
