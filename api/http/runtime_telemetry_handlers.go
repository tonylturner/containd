// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	engineclient "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/stats"
)

func listEventsHandler(engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := 500
		if q := c.Query("limit"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 5000 {
				limit = v
			}
		}

		out := []dpevents.Event{}
		var engineErr error

		if tc, ok := engine.(TelemetryClient); ok && tc != nil {
			evs, err := tc.ListEvents(c.Request.Context(), limit)
			if err != nil {
				engineErr = err
			} else {
				out = append(out, evs...)
			}
		}

		if s, ok := services.(interface {
			ListTelemetryEvents(limit int) []dpevents.Event
		}); ok && s != nil {
			out = append(out, s.ListTelemetryEvents(limit)...)
		}

		if engineErr != nil && len(out) > 0 {
			out = append(out, dpevents.Event{
				Proto:     "system",
				Kind:      "system.engine.telemetry_error",
				Timestamp: time.Now().UTC(),
				Attributes: map[string]any{
					"error": engineErr.Error(),
				},
			})
		}

		sort.Slice(out, func(i, j int) bool {
			return out[i].Timestamp.After(out[j].Timestamp)
		})
		if limit > 0 && len(out) > limit {
			out = out[:limit]
		}
		c.JSON(http.StatusOK, out)
	}
}

func eventDetailHandler(engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		idStr := c.Param("id")
		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			apiError(c, http.StatusBadRequest, "invalid event ID")
			return
		}

		var all []dpevents.Event
		if tc, ok := engine.(TelemetryClient); ok && tc != nil {
			evs, err := tc.ListEvents(c.Request.Context(), 5000)
			if err == nil {
				all = append(all, evs...)
			}
		}
		if s, ok := services.(interface {
			ListTelemetryEvents(limit int) []dpevents.Event
		}); ok && s != nil {
			all = append(all, s.ListTelemetryEvents(5000)...)
		}

		for _, ev := range all {
			if ev.ID == id {
				c.JSON(http.StatusOK, ev)
				return
			}
		}
		apiError(c, http.StatusNotFound, "event not found")
	}
}

func listFlowsHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		tc, ok := engine.(TelemetryClient)
		if !ok || tc == nil {
			c.JSON(http.StatusOK, []dpevents.FlowSummary{})
			return
		}
		limit := 200
		if q := c.Query("limit"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 5000 {
				limit = v
			}
		}
		flows, err := tc.ListFlows(c.Request.Context(), limit)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		if flows == nil {
			flows = []dpevents.FlowSummary{}
		}
		c.JSON(http.StatusOK, flows)
	}
}

func simulationStatusHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(SimulationClient)
		if !ok || sc == nil {
			c.JSON(http.StatusOK, engineclient.SimulationStatus{Running: false})
			return
		}
		st, err := sc.SimulationStatus(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		c.JSON(http.StatusOK, st)
	}
}

func simulationControlHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(SimulationClient)
		if !ok || sc == nil {
			apiError(c, http.StatusBadRequest, "simulation unavailable")
			return
		}
		var req struct {
			Action string `json:"action"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || (req.Action != "start" && req.Action != "stop") {
			apiError(c, http.StatusBadRequest, `action must be "start" or "stop"`)
			return
		}
		st, err := sc.SimulationControl(c.Request.Context(), req.Action)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "simulation." + req.Action, Target: "synth"})
		c.JSON(http.StatusOK, st)
	}
}

func protoStatsHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(StatsClient)
		if !ok || sc == nil {
			c.JSON(http.StatusOK, []stats.ProtoStats{})
			return
		}
		result, err := sc.ListProtoStats(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		if result == nil {
			result = []stats.ProtoStats{}
		}
		c.JSON(http.StatusOK, result)
	}
}

func topTalkersHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(StatsClient)
		if !ok || sc == nil {
			c.JSON(http.StatusOK, []stats.FlowStats{})
			return
		}
		n := 10
		if q := c.Query("n"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 1000 {
				n = v
			}
		}
		result, err := sc.ListTopTalkers(c.Request.Context(), n)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		if result == nil {
			result = []stats.FlowStats{}
		}
		c.JSON(http.StatusOK, result)
	}
}

func listAnomaliesHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		ac, ok := engine.(AnomalyClient)
		if !ok || ac == nil {
			c.JSON(http.StatusOK, []anomaly.Anomaly{})
			return
		}
		limit := 200
		if q := c.Query("limit"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 5000 {
				limit = v
			}
		}
		anomalies, err := ac.ListAnomalies(c.Request.Context(), limit)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		if anomalies == nil {
			anomalies = []anomaly.Anomaly{}
		}
		c.JSON(http.StatusOK, anomalies)
	}
}

func clearAnomaliesHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		ac, ok := engine.(AnomalyClient)
		if !ok || ac == nil {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
			return
		}
		if err := ac.ClearAnomalies(c.Request.Context()); err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

func listConntrackHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		cc, ok := engine.(ConntrackClient)
		if !ok || cc == nil {
			c.JSON(http.StatusOK, []conntrack.Entry{})
			return
		}
		limit := 200
		if q := c.Query("limit"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v > 0 {
				limit = v
			}
		}
		ents, err := cc.ListConntrack(c.Request.Context(), limit)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		c.JSON(http.StatusOK, ents)
	}
}

func killConntrackHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		ck, ok := engine.(ConntrackKiller)
		if !ok || ck == nil {
			apiError(c, http.StatusNotImplemented, "conntrack delete not supported")
			return
		}
		var req conntrack.DeleteRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		if err := ck.DeleteConntrack(c.Request.Context(), req); err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "conntrack.delete", Target: "dataplane"})
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	}
}
