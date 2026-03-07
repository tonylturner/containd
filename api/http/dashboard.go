package httpapi

import (
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/containd/containd/pkg/cp/audit"
	"github.com/containd/containd/pkg/cp/config"
	"github.com/containd/containd/pkg/cp/users"
	dpevents "github.com/containd/containd/pkg/dp/events"
)

type dashboardResponse struct {
	Health       dashboardHealth       `json:"health"`
	Counts       dashboardCounts       `json:"counts"`
	EventStats   dashboardEventStats   `json:"eventStats"`
	Services     any                   `json:"services"`
	User         any                   `json:"user"`
	LastActivity *audit.Record         `json:"lastActivity"`
}

type dashboardHealth struct {
	Status    string `json:"status"`
	Component string `json:"component"`
	Build     string `json:"build"`
	Commit    string `json:"commit"`
	Hostname  string `json:"hostname"`
	Time      string `json:"time"`
}

type dashboardCounts struct {
	Assets     int `json:"assets"`
	Zones      int `json:"zones"`
	Interfaces int `json:"interfaces"`
	Rules      int `json:"rules"`
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
		resp := dashboardResponse{}

		// Health
		hostname, _ := os.Hostname()
		resp.Health = dashboardHealth{
			Status:    "ok",
			Component: "mgmt",
			Build:     config.BuildVersion,
			Commit:    config.BuildCommit,
			Hostname:  hostname,
			Time:      time.Now().UTC().Format(time.RFC3339Nano),
		}

		// Config counts
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err == nil {
			resp.Counts = dashboardCounts{
				Assets:     len(cfg.Assets),
				Zones:      len(cfg.Zones),
				Interfaces: len(cfg.Interfaces),
				Rules:      len(cfg.Firewall.Rules),
			}
		}

		// Event stats (from engine telemetry + services)
		var events []dpevents.Event
		if tc, ok := engine.(TelemetryClient); ok && tc != nil {
			events, _ = tc.ListEvents(c.Request.Context(), 500)
		}
		if ss, ok := services.(interface{ RecentEvents(int) []dpevents.Event }); ok && ss != nil {
			events = append(events, ss.RecentEvents(500)...)
		}
		for _, e := range events {
			resp.EventStats.Total++
			if e.Proto == "ids" && e.Kind == "alert" {
				resp.EventStats.IDSAlerts++
			}
			if e.Kind == "service.av.detected" {
				resp.EventStats.AVDetections++
			}
			if e.Kind == "service.av.block_flow" {
				resp.EventStats.AVBlocks++
			}
			if e.Proto == "modbus" && e.Kind == "request" && e.Attributes != nil {
				if isWrite, ok := e.Attributes["is_write"].(bool); ok && isWrite {
					resp.EventStats.ModbusWrites++
				}
			}
		}

		// Services status
		if ss, ok := services.(interface{ Status() any }); ok && ss != nil {
			resp.Services = ss.Status()
		}

		// Current user
		if userStore != nil {
			uid := c.GetString(ctxUserKey)
			if u, err := userStore.GetByID(c.Request.Context(), uid); err == nil {
				resp.User = u.User
			}
		}

		// Last admin activity
		if auditStore != nil {
			if records, err := auditStore.List(c.Request.Context(), 20); err == nil {
				for i := range records {
					if records[i].Actor != "" && records[i].Actor != "system" {
						resp.LastActivity = &records[i]
						break
					}
				}
			}
		}

		c.JSON(http.StatusOK, resp)
	}
}
