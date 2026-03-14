// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/config"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func listFirewallRulesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Firewall.Rules)
	}
}

func createFirewallRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var r config.Rule
		if err := c.ShouldBindJSON(&r); err != nil || r.ID == "" {
			apiError(c, http.StatusBadRequest, "invalid rule payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		for _, existing := range cfg.Firewall.Rules {
			if existing.ID == r.ID {
				apiError(c, http.StatusBadRequest, "rule already exists")
				return
			}
		}
		if cfg.Firewall.DefaultAction == "" {
			cfg.Firewall.DefaultAction = config.ActionDeny
		}
		cfg.Firewall.Rules = append(cfg.Firewall.Rules, r)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, r)
	}
}

func deleteFirewallRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		original := len(cfg.Firewall.Rules)
		filtered := make([]config.Rule, 0, len(cfg.Firewall.Rules))
		for _, r := range cfg.Firewall.Rules {
			if r.ID != id {
				filtered = append(filtered, r)
			}
		}
		if len(filtered) == original {
			apiError(c, http.StatusNotFound, "rule not found")
			return
		}
		cfg.Firewall.Rules = filtered
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			internalError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func mergeJSONObject(dst, patch map[string]interface{}) map[string]interface{} {
	if dst == nil {
		dst = map[string]interface{}{}
	}
	for key, value := range patch {
		if existing, ok := dst[key].(map[string]interface{}); ok {
			if nested, ok := value.(map[string]interface{}); ok {
				dst[key] = mergeJSONObject(existing, nested)
				continue
			}
		}
		dst[key] = value
	}
	return dst
}

func updateFirewallRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			apiError(c, http.StatusBadRequest, "failed to read request body")
			return
		}
		var patch map[string]interface{}
		if err := json.Unmarshal(body, &patch); err != nil {
			apiError(c, http.StatusBadRequest, "invalid rule payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		updated := false
		for i, existing := range cfg.Firewall.Rules {
			if existing.ID == id {
				currentJSON, err := json.Marshal(existing)
				if err != nil {
					internalError(c, err)
					return
				}
				var merged map[string]interface{}
				if err := json.Unmarshal(currentJSON, &merged); err != nil {
					internalError(c, err)
					return
				}
				merged = mergeJSONObject(merged, patch)
				mergedJSON, err := json.Marshal(merged)
				if err != nil {
					internalError(c, err)
					return
				}
				var rule config.Rule
				if err := json.Unmarshal(mergedJSON, &rule); err != nil {
					apiError(c, http.StatusBadRequest, "invalid rule payload")
					return
				}
				if rule.ID == "" {
					rule.ID = existing.ID
				}
				cfg.Firewall.Rules[i] = rule
				updated = true
				c.Set("updated_rule", rule)
				break
			}
		}
		if !updated {
			apiError(c, http.StatusNotFound, "rule not found")
			return
		}
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if v, ok := c.Get("updated_rule"); ok {
			if rule, ok := v.(config.Rule); ok {
				c.JSON(http.StatusOK, rule)
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"status": "updated"})
	}
}

type previewRuleResponse struct {
	MatchCount    int               `json:"match_count"`
	SampleMatches []dpevents.Event  `json:"sample_matches"`
	TimeRange     *previewTimeRange `json:"time_range"`
	TotalEvents   int               `json:"total_events"`
}

type previewTimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

func previewFirewallRuleHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req config.Rule
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, "invalid rule payload")
			return
		}

		entry := rules.Entry{
			ID:           req.ID,
			SourceZones:  req.SourceZones,
			DestZones:    req.DestZones,
			Sources:      req.Sources,
			Destinations: req.Destinations,
			Action:       rules.Action(req.Action),
			Identities:   req.Identities,
			ICS: rules.ICSPredicate{
				Protocol:     req.ICS.Protocol,
				FunctionCode: req.ICS.FunctionCode,
				UnitID:       req.ICS.UnitID,
				Addresses:    req.ICS.Addresses,
				ReadOnly:     req.ICS.ReadOnly,
				WriteOnly:    req.ICS.WriteOnly,
				Mode:         req.ICS.Mode,
			},
		}
		if req.Schedule != nil {
			entry.Schedule = rules.SchedulePredicate{
				DaysOfWeek: req.Schedule.DaysOfWeek,
				StartTime:  req.Schedule.StartTime,
				EndTime:    req.Schedule.EndTime,
				Timezone:   req.Schedule.Timezone,
			}
		}
		for _, p := range req.Protocols {
			entry.Protocols = append(entry.Protocols, rules.Protocol{Name: p.Name, Port: p.Port})
		}

		tc, ok := engine.(TelemetryClient)
		if !ok || tc == nil {
			c.JSON(http.StatusOK, previewRuleResponse{
				SampleMatches: []dpevents.Event{},
			})
			return
		}

		evs, err := tc.ListEvents(c.Request.Context(), 5000)
		if err != nil {
			apiError(c, http.StatusBadGateway, "failed to fetch events: "+err.Error())
			return
		}

		totalEvents := len(evs)
		var tr *previewTimeRange
		if totalEvents > 0 {
			oldest := evs[0].Timestamp
			newest := evs[0].Timestamp
			for _, ev := range evs[1:] {
				if ev.Timestamp.Before(oldest) {
					oldest = ev.Timestamp
				}
				if ev.Timestamp.After(newest) {
					newest = ev.Timestamp
				}
			}
			tr = &previewTimeRange{Start: oldest, End: newest}
		}

		const maxSamples = 50
		var matchCount int
		var samples []dpevents.Event
		for _, ev := range evs {
			ctx := rules.EvalContext{
				SrcIP: net.ParseIP(ev.SrcIP),
				DstIP: net.ParseIP(ev.DstIP),
				Proto: ev.Transport,
				Port:  strconv.Itoa(int(ev.DstPort)),
				Now:   ev.Timestamp,
			}
			if rules.PreviewMatch(entry, ctx) {
				matchCount++
				if len(samples) < maxSamples {
					samples = append(samples, ev)
				}
			}
		}

		if samples == nil {
			samples = []dpevents.Event{}
		}

		c.JSON(http.StatusOK, previewRuleResponse{
			MatchCount:    matchCount,
			SampleMatches: samples,
			TimeRange:     tr,
			TotalEvents:   totalEvents,
		})
	}
}

func hasICSPredicate(r config.Rule) bool {
	return strings.TrimSpace(r.ICS.Protocol) != "" ||
		len(r.ICS.FunctionCode) > 0 ||
		r.ICS.UnitID != nil ||
		len(r.ICS.Addresses) > 0 ||
		r.ICS.ReadOnly ||
		r.ICS.WriteOnly
}

func listICSRulesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		var icsRules []config.Rule
		for _, r := range cfg.Firewall.Rules {
			if hasICSPredicate(r) {
				icsRules = append(icsRules, r)
			}
		}
		if icsRules == nil {
			icsRules = []config.Rule{}
		}
		c.JSON(http.StatusOK, icsRules)
	}
}

func createICSRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var r config.Rule
		if err := c.ShouldBindJSON(&r); err != nil || r.ID == "" {
			apiError(c, http.StatusBadRequest, "invalid rule payload")
			return
		}
		if !hasICSPredicate(r) {
			apiError(c, http.StatusBadRequest, "rule must include an ICS predicate")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		for _, existing := range cfg.Firewall.Rules {
			if existing.ID == r.ID {
				apiError(c, http.StatusBadRequest, "rule already exists")
				return
			}
		}
		if cfg.Firewall.DefaultAction == "" {
			cfg.Firewall.DefaultAction = config.ActionDeny
		}
		cfg.Firewall.Rules = append(cfg.Firewall.Rules, r)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, r)
	}
}

func updateICSRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var rule config.Rule
		if err := c.ShouldBindJSON(&rule); err != nil {
			apiError(c, http.StatusBadRequest, "invalid rule payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		updated := false
		for i, existing := range cfg.Firewall.Rules {
			if existing.ID == id {
				if !hasICSPredicate(existing) {
					apiError(c, http.StatusBadRequest, "rule is not an ICS rule")
					return
				}
				if rule.ID == "" {
					rule.ID = existing.ID
				}
				cfg.Firewall.Rules[i] = rule
				updated = true
				break
			}
		}
		if !updated {
			apiError(c, http.StatusNotFound, "rule not found")
			return
		}
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, rule)
	}
}
