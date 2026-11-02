// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/common/labmode"
	"github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	history "github.com/tonylturner/containd/pkg/cp/telemetry"
	"github.com/tonylturner/containd/pkg/cp/users"
)

type dashboardResponse struct {
	Health          dashboardHealth      `json:"health"`
	Counts          dashboardCounts      `json:"counts"`
	EventStats      *dashboardEventStats `json:"eventStats"`
	EventStatsError string               `json:"eventStatsError,omitempty"`
	Services        any                  `json:"services"`
	User            any                  `json:"user"`
	LastActivity    *audit.Record        `json:"lastActivity"`
}

type dashboardHealth struct {
	Status    string `json:"status"`
	Component string `json:"component"`
	Build     string `json:"build"`
	Commit    string `json:"commit"`
	Hostname  string `json:"hostname"`
	Time      string `json:"time"`
	LabMode   bool   `json:"labMode,omitempty"`
}

type dashboardCounts struct {
	Assets     int `json:"assets"`
	Zones      int `json:"zones"`
	Interfaces int `json:"interfaces"`
	Rules      int `json:"rules"`
	ICSRules   int `json:"icsRules"`
}

type dashboardEventStats struct {
	WindowSeconds int    `json:"windowSeconds"`
	Complete      bool   `json:"complete"`
	Total         uint64 `json:"total"`
	IDSAlerts     uint64 `json:"idsAlerts"`
	ModbusWrites  uint64 `json:"modbusWrites"`
	AVDetections  uint64 `json:"avDetections"`
	AVBlocks      uint64 `json:"avBlocks"`
}

func dashboardHandler(store config.Store, services ServicesApplier, userStore users.Store, auditStore audit.Store, telemetryStore TelemetryStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		resp := dashboardResponse{
			Health: buildDashboardHealth(),
		}
		cfg, err := readRunningOrDefault(c, store)
		if err == nil {
			resp.Counts = loadDashboardCounts(cfg)
		}
		resp.EventStats, err = collectDashboardEventStats(c.Request.Context(), telemetryStore)
		if err != nil {
			resp.EventStatsError = err.Error()
		}
		resp.Services = dashboardServicesStatus(services)
		resp.User = dashboardCurrentUser(c, userStore)
		resp.LastActivity = dashboardLastActivity(c.Request.Context(), auditStore)
		c.JSON(http.StatusOK, resp)
	}
}

func buildDashboardHealth() dashboardHealth {
	hostname, _ := os.Hostname()
	lab := labmode.Enabled()
	return dashboardHealth{
		Status:    "ok",
		Component: "mgmt",
		Build:     config.BuildVersion,
		Commit:    config.BuildCommit,
		Hostname:  hostname,
		Time:      time.Now().UTC().Format(time.RFC3339Nano),
		LabMode:   lab,
	}
}

func loadDashboardCounts(cfg *config.Config) dashboardCounts {
	return dashboardCounts{
		Assets:     len(cfg.Assets),
		Zones:      len(cfg.Zones),
		Interfaces: len(cfg.Interfaces),
		Rules:      len(cfg.Firewall.Rules),
		ICSRules:   countICSRules(cfg.Firewall.Rules),
	}
}

func countICSRules(rules []config.Rule) int {
	count := 0
	for _, r := range rules {
		if !r.ICS.Empty() {
			count++
		}
	}
	return count
}

func collectDashboardEventStats(ctx context.Context, store TelemetryStore) (*dashboardEventStats, error) {
	if store == nil {
		return nil, history.ErrUnavailable
	}
	stats := &dashboardEventStats{WindowSeconds: 86400, Complete: true}
	now := time.Now()
	for _, counter := range []struct {
		metric telemetry.Metric
		class  telemetry.EventClass
		target *uint64
	}{
		{telemetry.EventsTotal, "", &stats.Total},
		{telemetry.EventsClass, telemetry.ClassIDSAlert, &stats.IDSAlerts},
		{telemetry.EventsClass, telemetry.ClassModbusWrite, &stats.ModbusWrites},
		{telemetry.EventsClass, telemetry.ClassAVDetection, &stats.AVDetections},
		{telemetry.EventsClass, telemetry.ClassAVBlock, &stats.AVBlocks},
	} {
		filters := map[string]string{}
		if counter.class != "" {
			filters["class"] = string(counter.class)
		}
		resp, err := store.Query(ctx, history.Query{Metric: counter.metric, Range: telemetry.Range24h, Origin: telemetry.OriginReal, Filters: filters}, now)
		if err != nil {
			return nil, err
		}
		value, complete, err := history.Total(resp)
		if err != nil {
			return nil, err
		}
		*counter.target = value
		sources := map[string]bool{}
		for _, series := range resp.Series {
			sources[series.Dims["source"]] = true
		}
		stats.Complete = stats.Complete && complete && sources["engine"] && sources["services"]
	}
	return stats, nil
}

func dashboardServicesStatus(services ServicesApplier) any {
	if ss, ok := services.(interface{ Status() any }); ok && ss != nil {
		return ss.Status()
	}
	return nil
}

func dashboardCurrentUser(c *gin.Context, userStore users.Store) any {
	if userStore == nil {
		return nil
	}
	uid := c.GetString(ctxUserKey)
	if uid == "" {
		return nil
	}
	if u, err := userStore.GetByID(c.Request.Context(), uid); err == nil {
		return callerProfile(c, u.User)
	}
	return nil
}

func dashboardLastActivity(ctx context.Context, auditStore audit.Store) *audit.Record {
	if auditStore == nil {
		return nil
	}
	records, err := auditStore.List(ctx, 20)
	if err != nil {
		return nil
	}
	for i := range records {
		if records[i].Actor != "" && records[i].Actor != "system" {
			return &records[i]
		}
	}
	return nil
}
