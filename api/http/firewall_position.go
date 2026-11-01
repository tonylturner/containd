// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

type rulePosition struct {
	kind, anchor string
}

func (p *rulePosition) UnmarshalJSON(data []byte) error {
	var word string
	if json.Unmarshal(data, &word) == nil && (word == "top" || word == "bottom") {
		p.kind = word
		return nil
	}
	fields, err := uniqueObject(data)
	if err == nil && len(fields) == 1 {
		for key, value := range fields {
			if (key == "before" || key == "after") && json.Unmarshal(value, &word) == nil && word != "" {
				p.kind, p.anchor = key, word
				return nil
			}
		}
	}
	return fmt.Errorf("position must be top, bottom, {before: ruleId}, or {after: ruleId}")
}

// uniqueObject preserves the strict rule decoder's duplicate-key guarantee
// while separating the authoring-only position from the persisted rule.
func uniqueObject(data []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("expected object")
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return nil, err
		}
		key := token.(string)
		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	return fields, nil
}

type positionedRule struct {
	Rule     config.Rule
	Position rulePosition
}

func (r *positionedRule) UnmarshalJSON(data []byte) error {
	fields, err := uniqueObject(data)
	if err != nil {
		return err
	}
	if value, exists := fields["position"]; exists {
		if err := json.Unmarshal(value, &r.Position); err != nil {
			return err
		}
		delete(fields, "position")
	}
	body, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, &r.Rule)
}

func (p rulePosition) index(list []config.Rule, moved string) (int, error) {
	switch p.kind {
	case "top":
		return 0, nil
	case "", "bottom":
		return len(list), nil
	}
	if p.anchor == moved {
		return 0, fmt.Errorf("position anchor cannot be the moved rule")
	}
	for i, rule := range list {
		if rule.ID == p.anchor {
			if p.kind == "after" {
				i++
			}
			return i, nil
		}
	}
	return 0, fmt.Errorf("position anchor %q not found", p.anchor)
}

func insertRule(list []config.Rule, index int, rule config.Rule) []config.Rule {
	return slices.Insert(list, index, rule)
}

func moveFirewallRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Position rulePosition `json:"position" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || req.Position.kind == "" {
			apiError(c, 400, "position is required and must be valid")
			return
		}
		id := c.Param("id")
		index := 0
		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			i := slices.IndexFunc(cfg.Firewall.Rules, func(r config.Rule) bool { return r.ID == id })
			if i < 0 {
				apiError(c, 404, "rule not found")
				return false
			}
			rule := cfg.Firewall.Rules[i]
			list := slices.Delete(cfg.Firewall.Rules, i, i+1)
			var err error
			index, err = req.Position.index(list, id)
			if err != nil {
				apiError(c, 400, err.Error())
				return false
			}
			cfg.Firewall.Rules = insertRule(list, index, rule)
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "firewall.rule.move", Target: id, Detail: "candidate"})
		c.JSON(200, gin.H{"index": index, "rules": cfg.Firewall.Rules})
	}
}
