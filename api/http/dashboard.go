// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

type dashboardResponse struct {
	Health       dashboardHealth     `json:"health"`
	Counts       dashboardCounts     `json:"counts"`
	EventStats   dashboardEventStats `json:"eventStats"`
	Services     any                 `json:"services"`
	User         any                 `json:"user"`
	LastActivity *audit.Record       `json:"lastActivity"`
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
	Total        int `json:"total"`
	IDSAlerts    int `json:"idsAlerts"`
	ModbusWrites int `json:"modbusWrites"`
	AVDetections int `json:"avDetections"`
	AVBlocks     int `json:"avBlocks"`
}

func dashboardHandler(store config.Store, engine EngineClient, services ServicesApplier, userStore users.Store, auditStore audit.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		resp := dashboardResponse{
			Health: buildDashboardHealth(),
		}
		resp.Counts = loadDashboardCounts(c.Request.Context(), store)
		resp.EventStats = collectDashboardEventStats(c.Request.Context(), engine, services)
		resp.Services = dashboardServicesStatus(services)
		resp.User = dashboardCurrentUser(c, userStore)
		resp.LastActivity = dashboardLastActivity(c.Request.Context(), auditStore)
		c.JSON(http.StatusOK, resp)
	}
}

func buildDashboardHealth() dashboardHealth {
	hostname, _ := os.Hostname()
	lab := os.Getenv("CONTAIND_LAB_MODE") == "1" || strings.EqualFold(os.Getenv("CONTAIND_LAB_MODE"), "true")
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

func loadDashboardCounts(ctx context.Context, store config.Store) dashboardCounts {
	cfg, err := loadOrInitConfig(ctx, store)
	if err != nil {
		return dashboardCounts{}
	}
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
		if hasICSPredicate(r) {
			count++
		}
	}
	return count
}

func collectDashboardEventStats(ctx context.Context, engine EngineClient, services ServicesApplier) dashboardEventStats {
	stats := dashboardEventStats{}
	for _, e := range dashboardEvents(ctx, engine, services) {
		stats.Total++
		accumulateDashboardEventStats(&stats, e)
	}
	return stats
}

func dashboardEvents(ctx context.Context, engine EngineClient, services ServicesApplier) []dpevents.Event {
	var events []dpevents.Event
	if tc, ok := engine.(TelemetryClient); ok && tc != nil {
		events, _ = tc.ListEvents(ctx, 500)
	}
	if ss, ok := services.(interface{ RecentEvents(int) []dpevents.Event }); ok && ss != nil {
		events = append(events, ss.RecentEvents(500)...)
	}
	return events
}

func accumulateDashboardEventStats(stats *dashboardEventStats, e dpevents.Event) {
	if e.Proto == "ids" && e.Kind == "alert" {
		stats.IDSAlerts++
	}
	if e.Kind == "service.av.detected" {
		stats.AVDetections++
	}
	if e.Kind == "service.av.block_flow" {
		stats.AVBlocks++
	}
	if e.Proto == "modbus" && e.Kind == "request" && modbusWriteEvent(e) {
		stats.ModbusWrites++
	}
}

func modbusWriteEvent(e dpevents.Event) bool {
	if e.Attributes == nil {
		return false
	}
	isWrite, ok := e.Attributes["is_write"].(bool)
	return ok && isWrite
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
		return u.User
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
