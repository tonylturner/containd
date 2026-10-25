// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
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

		client, ok := engine.(RulePreviewClient)
		if !ok || client == nil {
			apiError(c, http.StatusServiceUnavailable, "engine rule preview unavailable")
			return
		}
		result, err := client.PreviewRule(c.Request.Context(), entry)
		if err != nil {
			apiError(c, http.StatusBadGateway, "failed to preview rule: "+err.Error())
			return
		}
		c.JSON(http.StatusOK, result)
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
