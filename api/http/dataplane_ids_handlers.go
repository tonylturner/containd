// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	cpids "github.com/tonylturner/containd/pkg/cp/ids"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
)

func getDataPlaneHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.LoadCandidate(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.DataPlane)
	}
}

func getRulesetPreviewHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.LoadCandidate(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		if err := cfg.Validate(); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		type rulesetPreviewClient interface {
			PreviewRuleset(context.Context, *config.Config) (dpengine.RulesetPreview, error)
		}
		ec, ok := engine.(rulesetPreviewClient)
		if !ok || ec == nil {
			apiError(c, http.StatusServiceUnavailable, "engine unavailable: ruleset preview requires a live engine")
			return
		}
		preview, err := ec.PreviewRuleset(c.Request.Context(), cfg)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}

		resp := gin.H{
			"snapshot": preview.Snapshot,
			"runtime":  preview.Runtime,
		}
		if preview.Ruleset != "" {
			resp["ruleset"] = preview.Ruleset
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
		cfg, err := store.LoadCandidate(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		resp := cfg.IDS
		c.JSON(http.StatusOK, resp)
	}
}

func setIDSHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var idsCfg config.IDSConfig
		if err := c.ShouldBindJSON(&idsCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, ok := stageCandidateIDS(c, store, func(cfg *config.Config) bool {
			cfg.IDS.Enabled = idsCfg.Enabled
			cfg.IDS.RuleGroups = idsCfg.RuleGroups
			if idsCfg.Rules != nil {
				cfg.IDS.Rules = idsCfg.Rules
			}
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "ids.rules.set", Target: "candidate", Detail: "candidate"})
		idsCfg = cfg.IDS
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

func idsImportHandler(store config.Store) gin.HandlerFunc {
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

		added, skipped := 0, 0
		cfg, ok := stageCandidateIDS(c, store, func(cfg *config.Config) bool {
			existing := make(map[string]bool, len(cfg.IDS.Rules))
			for _, r := range cfg.IDS.Rules {
				existing[r.ID] = true
			}
			for _, r := range rules {
				if existing[r.ID] {
					skipped++
					continue
				}
				cfg.IDS.Rules = append(cfg.IDS.Rules, r)
				existing[r.ID] = true
				added++
			}
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "ids.rules.import", Target: format, Detail: "candidate"})

		c.JSON(http.StatusOK, gin.H{
			"imported": added,
			"skipped":  skipped,
			"total":    len(cfg.IDS.Rules),
			"format":   format,
		})
	}
}

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

func idsSourcesHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, cpids.BuiltinSources)
	}
}

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

func idsRestoreHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		const maxSize = 50 << 20
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
		if _, ok := stageCandidateIDS(c, store, func(cfg *config.Config) bool {
			cfg.IDS.Rules = rules
			return true
		}); !ok {
			return
		}
		auditLog(c, audit.Record{Action: "ids.rules.restore", Target: "candidate", Detail: "candidate"})

		c.JSON(http.StatusOK, gin.H{"status": "staged", "count": len(rules)})
	}
}

func getFirewallNATHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.LoadCandidate(c.Request.Context())
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
		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			cfg.Firewall.NAT = nat
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "firewall.nat.set", Target: "candidate", Detail: "candidate"})
		c.JSON(http.StatusOK, cfg.Firewall.NAT)
	}
}

func setDataPlaneHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var dp config.DataPlaneConfig
		if err := c.ShouldBindJSON(&dp); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			cfg.DataPlane = dp
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "dataplane.set", Target: "candidate", Detail: "candidate"})
		c.JSON(http.StatusOK, cfg.DataPlane)
	}
}
