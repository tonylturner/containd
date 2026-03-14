// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/identity"
	"github.com/tonylturner/containd/pkg/cp/templates"
)

func listIdentitiesHandler(resolver *identity.Resolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"mappings": resolver.All()})
	}
}

func setIdentityHandler(resolver *identity.Resolver) gin.HandlerFunc {
	type req struct {
		IP         string   `json:"ip"`
		Identities []string `json:"identities"`
	}
	return func(c *gin.Context) {
		var body req
		if err := c.ShouldBindJSON(&body); err != nil {
			apiError(c, http.StatusBadRequest, "invalid request body")
			return
		}
		ip := net.ParseIP(strings.TrimSpace(body.IP))
		if ip == nil {
			apiError(c, http.StatusBadRequest, "invalid IP address")
			return
		}
		if len(body.Identities) == 0 {
			apiError(c, http.StatusBadRequest, "identities must not be empty")
			return
		}
		for _, id := range body.Identities {
			if strings.TrimSpace(id) == "" {
				apiError(c, http.StatusBadRequest, "identity must not be empty")
				return
			}
		}
		resolver.Register(ip, body.Identities)
		c.JSON(http.StatusOK, gin.H{"ip": ip.String(), "identities": body.Identities})
	}
}

func deleteIdentityHandler(resolver *identity.Resolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := c.Param("ip")
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			apiError(c, http.StatusBadRequest, "invalid IP address")
			return
		}
		resolver.Remove(ip)
		c.JSON(http.StatusOK, gin.H{"deleted": ip.String()})
	}
}

func listTemplatesHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, templates.List())
	}
}

func applyTemplateHandler(store config.Store) gin.HandlerFunc {
	type req struct {
		Name string `json:"name"`
	}
	return func(c *gin.Context) {
		var r req
		if err := c.ShouldBindJSON(&r); err != nil || r.Name == "" {
			apiError(c, http.StatusBadRequest, "name is required")
			return
		}
		ctx := c.Request.Context()
		cfg, err := loadOrInitConfig(ctx, store)
		if err != nil {
			internalError(c, err)
			return
		}
		if err := templates.Apply(r.Name, cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := store.Save(ctx, cfg); err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"applied": r.Name, "ruleCount": len(cfg.Firewall.Rules)})
	}
}

type icsTemplateInfo struct {
	Name        string                     `json:"name"`
	Description string                     `json:"description"`
	Protocol    string                     `json:"protocol"`
	Parameters  []icsTemplateParameterInfo `json:"parameters,omitempty"`
}

type icsTemplateParameterInfo struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Type        string `json:"type"`
	Required    bool   `json:"required,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
	Help        string `json:"help,omitempty"`
}

type icsTemplateParams struct {
	Ranges []string `json:"ranges,omitempty"`
}

type icsTemplateRequest struct {
	Template          string            `json:"template"`
	SourceZones       []string          `json:"sourceZones,omitempty"`
	SourceZonesLegacy []string          `json:"source_zones,omitempty"`
	DestZones         []string          `json:"destZones,omitempty"`
	DestZonesLegacy   []string          `json:"dest_zones,omitempty"`
	Parameters        map[string]string `json:"parameters,omitempty"`
	Params            icsTemplateParams `json:"params,omitempty"`
	Preview           bool              `json:"preview,omitempty"`
}

func listICSTemplatesHandler() gin.HandlerFunc {
	infos := []icsTemplateInfo{
		{Name: "modbus_read_only", Description: "Allow Modbus read operations only (FC 1-4), deny all writes", Protocol: "modbus"},
		{
			Name:        "modbus_register_guard",
			Description: "Allow Modbus access to specific register address ranges only",
			Protocol:    "modbus",
			Parameters: []icsTemplateParameterInfo{{
				Name:        "ranges",
				Label:       "Register Ranges",
				Type:        "text",
				Required:    true,
				Placeholder: "0-99,400-499",
				Help:        "Comma- or newline-separated Modbus register ranges such as 0-99 or 400-499.",
			}},
		},
		{Name: "dnp3_secure_operations", Description: "Allow normal DNP3 reads, deny dangerous function codes (restart, stop)", Protocol: "dnp3"},
		{Name: "s7comm_read_only", Description: "Allow S7comm read variable, deny write and PLC control", Protocol: "s7comm"},
		{Name: "cip_monitor_only", Description: "Allow CIP read services, deny writes and control commands", Protocol: "cip"},
		{Name: "bacnet_read_only", Description: "Allow BACnet read properties, deny writes and device control", Protocol: "bacnet"},
		{Name: "opcua_monitor_only", Description: "Allow OPC UA browse/read/subscribe, deny writes and node management", Protocol: "opcua"},
	}
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, infos)
	}
}

func applyICSTemplateHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var r icsTemplateRequest
		if err := c.ShouldBindJSON(&r); err != nil || r.Template == "" {
			apiError(c, http.StatusBadRequest, "template name is required")
			return
		}
		sourceZones, destZones, ranges := normalizeICSTemplateRequest(r)
		generated, err := buildICSTemplateRules(r.Template, ranges)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		applyICSTemplateZones(generated, sourceZones, destZones)

		if r.Preview {
			c.JSON(http.StatusOK, gin.H{"template": r.Template, "preview": true, "rules": generated})
			return
		}

		ctx := c.Request.Context()
		cfg, err := loadOrInitConfig(ctx, store)
		if err != nil {
			internalError(c, err)
			return
		}
		created, updated := upsertFirewallRulesByID(cfg.Firewall.Rules, generated)
		cfg.Firewall.Rules = appendFirewallRulesUpsert(cfg.Firewall.Rules, generated)
		if err := store.Save(ctx, cfg); err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"template":  r.Template,
			"applied":   true,
			"created":   created,
			"updated":   updated,
			"ruleCount": len(cfg.Firewall.Rules),
			"rules":     generated,
		})
	}
}

func normalizeICSTemplateRequest(r icsTemplateRequest) ([]string, []string, []string) {
	sourceZones := r.SourceZones
	if len(sourceZones) == 0 {
		sourceZones = r.SourceZonesLegacy
	}
	destZones := r.DestZones
	if len(destZones) == 0 {
		destZones = r.DestZonesLegacy
	}
	ranges := r.Params.Ranges
	if len(ranges) == 0 {
		ranges = parseDelimitedTemplateValues(r.Parameters["ranges"])
	}
	return sourceZones, destZones, ranges
}

func buildICSTemplateRules(template string, ranges []string) ([]config.Rule, error) {
	switch template {
	case "modbus_read_only":
		return templates.ModbusReadOnly(), nil
	case "modbus_register_guard":
		if len(ranges) == 0 {
			return nil, fmt.Errorf("parameters.ranges is required for modbus_register_guard")
		}
		return templates.ModbusRegisterGuard(ranges), nil
	case "dnp3_secure_operations":
		return templates.DNP3SecureOperations(), nil
	case "s7comm_read_only":
		return templates.S7commReadOnly(), nil
	case "cip_monitor_only":
		return templates.CIPMonitorOnly(), nil
	case "bacnet_read_only":
		return templates.BACnetReadOnly(), nil
	case "opcua_monitor_only":
		return templates.OPCUAMonitorOnly(), nil
	default:
		return nil, fmt.Errorf("unknown ICS template %q", template)
	}
}

func applyICSTemplateZones(generated []config.Rule, sourceZones, destZones []string) {
	if len(sourceZones) == 0 && len(destZones) == 0 {
		return
	}
	for i := range generated {
		if len(sourceZones) > 0 {
			generated[i].SourceZones = append([]string(nil), sourceZones...)
		}
		if len(destZones) > 0 {
			generated[i].DestZones = append([]string(nil), destZones...)
		}
	}
}

func parseDelimitedTemplateValues(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func upsertFirewallRulesByID(existing, generated []config.Rule) (created int, updated int) {
	index := make(map[string]struct{}, len(existing))
	for _, rule := range existing {
		index[rule.ID] = struct{}{}
	}
	for _, rule := range generated {
		if _, ok := index[rule.ID]; ok {
			updated++
		} else {
			created++
		}
	}
	return created, updated
}

func appendFirewallRulesUpsert(existing, generated []config.Rule) []config.Rule {
	index := make(map[string]int, len(existing))
	for i, rule := range existing {
		index[rule.ID] = i
	}
	for _, rule := range generated {
		if i, ok := index[rule.ID]; ok {
			existing[i] = rule
			continue
		}
		index[rule.ID] = len(existing)
		existing = append(existing, rule)
	}
	return existing
}
