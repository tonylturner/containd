// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func listFirewallRulesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.LoadCandidate(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		configCollectionJSON(c, cfg.Firewall.Rules)
	}
}

func createFirewallRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request positionedRule
		if err := c.ShouldBindJSON(&request); err != nil {
			apiError(c, http.StatusBadRequest, "invalid rule payload: "+err.Error())
			return
		}
		r := request.Rule
		if r.ID == "" {
			apiError(c, http.StatusBadRequest, "invalid rule payload")
			return
		}
		index := 0
		_, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			for _, existing := range cfg.Firewall.Rules {
				if existing.ID == r.ID {
					apiError(c, http.StatusBadRequest, "rule already exists")
					return false
				}
			}
			var err error
			index, err = request.Position.index(cfg.Firewall.Rules, "")
			if err != nil {
				apiError(c, http.StatusBadRequest, err.Error())
				return false
			}
			cfg.Firewall.Rules = insertRule(cfg.Firewall.Rules, index, r)
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "firewall.rules.create", Target: r.ID, Detail: "candidate"})
		c.JSON(http.StatusOK, struct {
			config.Rule
			Index int `json:"index"`
		}{r, index})
	}
}

func deleteFirewallRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		_, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			original := len(cfg.Firewall.Rules)
			filtered := make([]config.Rule, 0, len(cfg.Firewall.Rules))
			for _, r := range cfg.Firewall.Rules {
				if r.ID != id {
					filtered = append(filtered, r)
				}
			}
			if len(filtered) == original {
				apiError(c, http.StatusNotFound, "rule not found")
				return false
			}
			cfg.Firewall.Rules = filtered
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "firewall.rules.delete", Target: id, Detail: "candidate"})
		c.Status(http.StatusNoContent)
	}
}

func mergeJSONObject(dst, patch map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	if dst == nil {
		dst = map[string]json.RawMessage{}
	}
	for key, value := range patch {
		if bytes.HasPrefix(bytes.TrimSpace(dst[key]), []byte("{")) &&
			bytes.HasPrefix(bytes.TrimSpace(value), []byte("{")) {
			var existing, nested map[string]json.RawMessage
			if err := json.Unmarshal(dst[key], &existing); err != nil {
				return nil, err
			}
			if err := json.Unmarshal(value, &nested); err != nil {
				return nil, err
			}
			merged, err := mergeJSONObject(existing, nested)
			if err != nil {
				return nil, err
			}
			value, err = json.Marshal(merged)
			if err != nil {
				return nil, err
			}
		}
		dst[key] = value
	}
	return dst, nil
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
		var rule config.Rule
		icsPatch, patchesICS := patch["ics"]
		delete(patch, "ics")
		_, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			idx := -1
			for i, existing := range cfg.Firewall.Rules {
				if existing.ID == id {
					idx = i
					break
				}
			}
			if idx < 0 {
				apiError(c, http.StatusNotFound, "rule not found")
				return false
			}
			existing := cfg.Firewall.Rules[idx]
			rule, err = mergeRulePatch(existing, patch)
			if err != nil {
				apiErrorDetail(c, http.StatusBadRequest, "invalid rule payload", err.Error())
				return false
			}
			if patchesICS {
				if rule.ICS, err = config.PatchICSPredicate(existing.ICS, icsPatch); err != nil {
					apiErrorDetail(c, http.StatusBadRequest, "invalid rule payload", err.Error())
					return false
				}
			}
			if rule.ID == "" {
				rule.ID = existing.ID
			}
			cfg.Firewall.Rules[idx] = rule
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "firewall.rules.update", Target: id, Detail: "candidate"})
		c.JSON(http.StatusOK, rule)
	}
}

// mergeRulePatch deep-merges the non-ICS keys of a patch into a rule.
func mergeRulePatch(existing config.Rule, patch map[string]json.RawMessage) (config.Rule, error) {
	currentJSON, err := json.Marshal(existing)
	if err != nil {
		return config.Rule{}, err
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(currentJSON, &merged); err != nil {
		return config.Rule{}, err
	}
	// Keep values as JSON until the strict, concrete Rule decode below.
	// In particular, nested schedule patches retain unspecified fields.
	merged, err = mergeJSONObject(merged, patch)
	if err != nil {
		return config.Rule{}, err
	}
	mergedJSON, err := json.Marshal(merged)
	if err != nil {
		return config.Rule{}, err
	}
	var rule config.Rule
	err = json.Unmarshal(mergedJSON, &rule)
	return rule, err
}

func previewFirewallRuleHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req config.Rule
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, "invalid rule payload")
			return
		}
		if err := config.ValidateICSPredicate(req.ICS, req.ID); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid rule payload", err.Error())
			return
		}

		entry := firewallRuleEntry(req)

		client, ok := engine.(RulePreviewClient)
		if !ok || client == nil {
			apiError(c, http.StatusServiceUnavailable, "engine rule preview unavailable")
			return
		}
		cfg, err := store.LoadCandidate(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		result, err := client.PreviewRule(c.Request.Context(), dpengine.PreviewRuleRequest{Entry: entry, ForwardMatches: compile.ResolveForwardMatches(cfg)})
		if err != nil {
			apiError(c, http.StatusBadGateway, "failed to preview rule: "+err.Error())
			return
		}
		c.JSON(http.StatusOK, result)
	}
}

func listICSRulesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.LoadCandidate(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		var icsRules []config.Rule
		for _, r := range cfg.Firewall.Rules {
			if !r.ICS.Empty() {
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
		var request positionedRule
		if err := c.ShouldBindJSON(&request); err != nil {
			apiError(c, http.StatusBadRequest, "invalid rule payload: "+err.Error())
			return
		}
		r := request.Rule
		if r.ID == "" {
			apiError(c, http.StatusBadRequest, "invalid rule payload")
			return
		}
		if r.ICS.Empty() {
			apiError(c, http.StatusBadRequest, "rule must include an ICS predicate")
			return
		}
		index := 0
		_, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			for _, existing := range cfg.Firewall.Rules {
				if existing.ID == r.ID {
					apiError(c, http.StatusBadRequest, "rule already exists")
					return false
				}
			}
			var err error
			index, err = request.Position.index(cfg.Firewall.Rules, "")
			if err != nil {
				apiError(c, http.StatusBadRequest, err.Error())
				return false
			}
			cfg.Firewall.Rules = insertRule(cfg.Firewall.Rules, index, r)
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "firewall.ics_rules.create", Target: r.ID, Detail: "candidate"})
		c.JSON(http.StatusOK, struct {
			config.Rule
			Index int `json:"index"`
		}{r, index})
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
		_, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			updated := false
			for i, existing := range cfg.Firewall.Rules {
				if existing.ID == id {
					if existing.ICS.Empty() {
						apiError(c, http.StatusBadRequest, "rule is not an ICS rule")
						return false
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
				return false
			}
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "firewall.ics_rules.update", Target: id, Detail: "candidate"})
		c.JSON(http.StatusOK, rule)
	}
}

func firewallRuleEntry(req config.Rule) rules.Entry {
	entry := rules.Entry{
		ID:           req.ID,
		ViaForwards:  req.ViaForwards,
		SourceZones:  req.SourceZones,
		DestZones:    req.DestZones,
		Sources:      req.Sources,
		Destinations: req.Destinations,
		Action:       rules.Action(req.Action),
		Tag:          req.Tag,
		Identities:   req.Identities,
		ICS:          compile.ICSPredicate(req.ICS),
	}
	// A zero burst means packetsPerSecond here as in the snapshot.
	if rl := req.RateLimit; rl != nil {
		entry.RateLimit = &rules.RateLimit{PacketsPerSecond: rl.PacketsPerSecond, Burst: rl.Burst}
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

	return entry
}
