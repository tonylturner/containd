// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/stats"
)

func listEventsHandler(engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		q, filtered, err := dpevents.ParseQuery(c.Request.URL.Query())
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if filtered {
			queryEvents(c, engine, services, q)
			return
		}
		limit := q.Limit

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

		// An unreachable engine is reported in the stream, never as an
		// empty 200 that reads like "no events".
		if engineErr != nil {
			out = append(out, dpevents.Event{
				Proto:     "system",
				Kind:      "system.engine.telemetry_error",
				Timestamp: time.Now().UTC(),
				Attributes: map[string]any{
					"error": engineErr.Error(),
				},
			})
		}

		out = dpevents.SelectTelemetry(out, limit)
		c.JSON(http.StatusOK, out)
	}
}

// EventQueryClient is the filtered telemetry capability of the engine API.
type EventQueryClient interface {
	QueryEvents(context.Context, dpevents.Query) (dpevents.Page, error)
}

func queryEvents(c *gin.Context, engine EngineClient, services ServicesApplier, q dpevents.Query) {
	tc, ok := engine.(EventQueryClient)
	if !ok {
		apiError(c, http.StatusBadGateway, "engine does not support event queries")
		return
	}
	source, err := tc.QueryEvents(c.Request.Context(), q)
	var candidates []dpevents.Event
	serviceHistoryUnknown := false
	if err == nil {
		candidates = append(candidates, source.Events...)
	}
	if s, ok := services.(interface{ ListTelemetryEvents(int) []dpevents.Event }); ok && s != nil {
		serviceHistoryUnknown = true
		// Zero means all retained rows, avoiding service priority selection before filtering.
		candidates = append(candidates, s.ListTelemetryEvents(0)...)
	}
	page := dpevents.QueryPage(candidates, q, source.HistoryTruncated, source.NextCursor != "")
	// Service stores do not expose overflow metadata. Their completeness cannot
	// be established, so mark the merged history conservatively as truncated.
	if serviceHistoryUnknown {
		page.HistoryTruncated = true
	}
	if err != nil {
		page.EngineError = err.Error()
		page.HistoryTruncated = true
	}
	c.JSON(http.StatusOK, page)
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
		if tc, ok := engine.(EventQueryClient); ok && tc != nil {
			page, err := tc.QueryEvents(c.Request.Context(), dpevents.Query{EventID: id, Limit: 1})
			if err == nil {
				all = append(all, page.Events...)
			}
		}
		if s, ok := services.(interface {
			ListTelemetryEvents(limit int) []dpevents.Event
		}); ok && s != nil {
			all = append(all, s.ListTelemetryEvents(0)...)
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
			apiError(c, http.StatusServiceUnavailable, "engine flows unavailable")
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
			apiError(c, http.StatusServiceUnavailable, "engine flows unavailable")
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
			apiError(c, http.StatusServiceUnavailable, "engine simulation unavailable")
			return
		}
		st, err := sc.SimulationStatus(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusServiceUnavailable, "engine simulation unavailable")
			return
		}
		c.JSON(http.StatusOK, st)
	}
}

func simulationControlHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		sc, ok := engine.(SimulationClient)
		if !ok || sc == nil {
			apiError(c, http.StatusServiceUnavailable, "engine simulation unavailable")
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
			apiError(c, http.StatusServiceUnavailable, "engine simulation unavailable")
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
			apiError(c, http.StatusServiceUnavailable, "engine protocol statistics unavailable")
			return
		}
		result, err := sc.ListProtoStats(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusServiceUnavailable, "engine protocol statistics unavailable")
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
			apiError(c, http.StatusServiceUnavailable, "engine top talkers unavailable")
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
			apiError(c, http.StatusServiceUnavailable, "engine top talkers unavailable")
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
			apiError(c, http.StatusServiceUnavailable, "engine anomalies unavailable")
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
			apiError(c, http.StatusServiceUnavailable, "engine anomalies unavailable")
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
			apiError(c, http.StatusServiceUnavailable, "engine anomalies unavailable")
			return
		}
		if err := ac.ClearAnomalies(c.Request.Context()); err != nil {
			apiError(c, http.StatusServiceUnavailable, "engine anomalies unavailable")
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}

func listConntrackHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		cc, ok := engine.(ConntrackClient)
		if !ok || cc == nil {
			apiError(c, http.StatusServiceUnavailable, "conntrack backend unavailable")
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
		if ents == nil {
			ents = []conntrack.Entry{}
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
		var req conntrack.KillRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		if err := req.Validate(); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		result, err := ck.DeleteConntrack(c.Request.Context(), req)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		outcome := "success"
		if !result.RevocationInstalled || !result.ConntrackDeleted {
			outcome = "failure"
		}
		auditLog(c, audit.Record{Action: "conntrack.kill", Target: fmt.Sprintf("%s [%s]:%d → [%s]:%d", req.Proto, req.Src, req.Sport, req.Dst, req.Dport), Result: outcome, Detail: fmt.Sprintf("scope=%s deleted=%d/%d revocation=%t %s %s", result.Scope, result.Deleted, result.Matched, result.RevocationInstalled, result.DeleteError, result.RevocationError)})
		c.JSON(http.StatusOK, result)
	}
}
