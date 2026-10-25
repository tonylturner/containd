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

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
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
		if err := c.ShouldBindJSON(&r); err != nil {
			apiError(c, http.StatusBadRequest, "invalid rule payload: "+err.Error())
			return
		}
		if r.ID == "" {
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

// updateFirewallRuleHandler merges a JSON patch into a rule. The "ics"
// object is not deep-merged as generic JSON: config.PatchICSPredicate
// strict-decodes it, and a protocol change replaces the predicate.
func updateFirewallRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			apiError(c, http.StatusBadRequest, "failed to read request body")
			return
		}
		var patch map[string]json.RawMessage
		if err := json.Unmarshal(body, &patch); err != nil {
			apiError(c, http.StatusBadRequest, "invalid rule payload")
			return
		}
		icsPatch, patchesICS := patch["ics"]
		delete(patch, "ics")
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		idx := -1
		for i, existing := range cfg.Firewall.Rules {
			if existing.ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			apiError(c, http.StatusNotFound, "rule not found")
			return
		}
		existing := cfg.Firewall.Rules[idx]
		rule, err := mergeRulePatch(existing, patch)
		if err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid rule payload", err.Error())
			return
		}
		if patchesICS {
			if rule.ICS, err = config.PatchICSPredicate(existing.ICS, icsPatch); err != nil {
				apiErrorDetail(c, http.StatusBadRequest, "invalid rule payload", err.Error())
				return
			}
		}
		if rule.ID == "" {
			rule.ID = existing.ID
		}
		cfg.Firewall.Rules[idx] = rule
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, rule)
	}
}

// mergeRulePatch deep-merges the non-ICS keys of a patch into a rule.
func mergeRulePatch(existing config.Rule, patch map[string]json.RawMessage) (config.Rule, error) {
	currentJSON, err := json.Marshal(existing)
	if err != nil {
		return config.Rule{}, err
	}
	var merged map[string]interface{}
	if err := json.Unmarshal(currentJSON, &merged); err != nil {
		return config.Rule{}, err
	}
	generic := make(map[string]interface{}, len(patch))
	for key, raw := range patch {
		var value interface{}
		if err := json.Unmarshal(raw, &value); err != nil {
			return config.Rule{}, err
		}
		generic[key] = value
	}
	mergedJSON, err := json.Marshal(mergeJSONObject(merged, generic))
	if err != nil {
		return config.Rule{}, err
	}
	var rule config.Rule
	err = json.Unmarshal(mergedJSON, &rule)
	return rule, err
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
			ICS:          compile.ICSPredicate(req.ICS),
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
		iec104 := entry.ICS.Protocol == rules.ProtocolIEC104
		for _, ev := range evs {
			ctx := rules.EvalContext{
				SrcIP: net.ParseIP(ev.SrcIP),
				DstIP: net.ParseIP(ev.DstIP),
				Proto: ev.Transport,
				Port:  strconv.Itoa(int(ev.DstPort)),
				Now:   ev.Timestamp,
			}
			if iec104 {
				ctx = previewIEC104Context(ctx, ev)
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

// iec104WireKinds are the event kinds the IEC104 decoder emits for wire
// objects. Decision and outcome events (ics.*) are evidence about them
// and must not count again.
var iec104WireKinds = map[string]struct{}{
	"request": {}, "response": {}, "apci": {}, "malformed": {}, "unsupported": {},
}

// previewIEC104Context adds the IEC104 object of a decoded IEC104 event to
// ctx and turns the tuple into the session tuple (source = client,
// destination = server, port = server port) that IEC104 rules match
// (spec §6.3, B8). Other events keep ctx unchanged and cannot match an
// IEC104 rule.
//
// SafeRead is classified by the same authority as decoder events.
func previewIEC104Context(ctx rules.EvalContext, ev dpevents.Event) rules.EvalContext {
	if ev.Proto != eventfields.ProtoIEC104 {
		return ctx
	}
	if _, ok := iec104WireKinds[ev.Kind]; !ok {
		return ctx
	}
	attrs := ev.Attributes
	direction, ok := eventfields.String(attrs, eventfields.KeyDirection)
	if !ok {
		direction = "request"
		if ev.SrcPort == iec104Port && ev.DstPort != iec104Port {
			direction = "response"
		}
	}
	if direction == "response" {
		ctx.SrcIP, ctx.DstIP = ctx.DstIP, ctx.SrcIP
		ctx.Port = strconv.Itoa(int(ev.SrcPort))
	}
	obj := &rules.IEC104Context{
		Malformed:   ev.Kind == "malformed",
		Unsupported: ev.Kind == "unsupported",
	}
	obj.APCIType, _ = eventfields.String(attrs, eventfields.KeyAPCIType)
	obj.Class, _ = eventfields.String(attrs, eventfields.KeyClass)
	obj.SafeRead = iec104.SafeRead(attrs)
	if v, ok := eventfields.Uint8(attrs, eventfields.KeyTypeID); ok {
		obj.TypeID = &v
	}
	if v, ok := eventfields.Uint16(attrs, eventfields.KeyCA); ok {
		obj.CA = &v
		obj.Broadcast = obj.APCIType == "I" && v == iec104BroadcastCA
	}
	if v, ok := eventfields.Uint32(attrs, eventfields.KeyIOA); ok {
		obj.IOA = &v
	}
	ctx.ICS = &rules.ICSContext{Protocol: rules.ProtocolIEC104, Direction: direction, IEC104: obj}
	return ctx
}

const (
	iec104Port        = 2404
	iec104BroadcastCA = 65535
)

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
		if err := c.ShouldBindJSON(&r); err != nil {
			apiError(c, http.StatusBadRequest, "invalid rule payload: "+err.Error())
			return
		}
		if r.ID == "" {
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
			apiError(c, http.StatusBadRequest, "invalid rule payload: "+err.Error())
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
