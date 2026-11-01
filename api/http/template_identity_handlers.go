// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/templates"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// The /identities routes edit firewall.identityBindings in the candidate
// configuration: changes are staged like rules and take effect on commit.

func listIdentitiesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := readCandidate(c, store)
		if err != nil {
			internalError(c, err)
			return
		}
		mappings := cfg.Firewall.IdentityBindings
		if mappings == nil {
			mappings = []config.IdentityBinding{}
		}
		c.JSON(http.StatusOK, gin.H{"mappings": mappings})
	}
}

// setIdentityHandler binds an address to identities, replacing any binding
// it has. Validation is the configuration's.
func setIdentityHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body config.IdentityBinding
		if err := c.ShouldBindJSON(&body); err != nil {
			apiError(c, http.StatusBadRequest, "invalid request body")
			return
		}
		addr, ok := rules.BindingAddr(strings.TrimSpace(body.IP))
		if !ok {
			apiError(c, http.StatusBadRequest, "invalid IP address")
			return
		}
		binding := config.IdentityBinding{IP: addr.String(), Identities: body.Identities}
		_, staged := stageCandidate(c, store, func(cfg *config.Config) bool {
			if i := identityBindingIndex(cfg.Firewall.IdentityBindings, addr); i >= 0 {
				cfg.Firewall.IdentityBindings[i] = binding
			} else {
				cfg.Firewall.IdentityBindings = append(cfg.Firewall.IdentityBindings, binding)
			}
			return true
		})
		if !staged {
			return
		}
		auditLog(c, audit.Record{Action: "identities.set", Target: binding.IP, Detail: "candidate"})
		c.JSON(http.StatusOK, binding)
	}
}

func deleteIdentityHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		addr, ok := rules.BindingAddr(strings.TrimSpace(c.Param("ip")))
		if !ok {
			apiError(c, http.StatusBadRequest, "invalid IP address")
			return
		}
		_, staged := stageCandidate(c, store, func(cfg *config.Config) bool {
			i := identityBindingIndex(cfg.Firewall.IdentityBindings, addr)
			if i < 0 {
				apiError(c, http.StatusNotFound, "no identity binding for "+addr.String())
				return false
			}
			cfg.Firewall.IdentityBindings = append(cfg.Firewall.IdentityBindings[:i], cfg.Firewall.IdentityBindings[i+1:]...)
			return true
		})
		if !staged {
			return
		}
		auditLog(c, audit.Record{Action: "identities.delete", Target: addr.String(), Detail: "candidate"})
		c.JSON(http.StatusOK, gin.H{"deleted": addr.String()})
	}
}

// identityBindingIndex finds the binding of addr, comparing canonical
// addresses; -1 when there is none.
func identityBindingIndex(bindings []config.IdentityBinding, addr netip.Addr) int {
	for i, b := range bindings {
		if got, ok := rules.BindingAddr(b.IP); ok && got == addr {
			return i
		}
	}
	return -1
}

func listTemplatesHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, templates.List())
	}
}

func applyTemplateHandler(store config.Store) gin.HandlerFunc {
	type req struct {
		Name string `json:"name"`
		// Mode, when set ("monitor" or "enforce"), overrides the
		// per-rule ICSPredicate.Mode on every rule the template
		// generates. Default (blank) leaves the field blank so rules
		// inherit the global DPIMode at evaluation time.
		Mode string `json:"mode,omitempty"`
	}
	return func(c *gin.Context) {
		var r req
		if err := c.ShouldBindJSON(&r); err != nil || r.Name == "" {
			apiError(c, http.StatusBadRequest, "name is required")
			return
		}
		if err := validateTemplateApplyMode(r.Mode); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			if err := templates.ApplyWithOpts(r.Name, cfg, templates.ApplyOpts{Mode: r.Mode}); err != nil {
				apiError(c, http.StatusBadRequest, err.Error())
				return false
			}
			return true
		})
		if !ok {
			return
		}

		if !candidateShadowWarnings(c, cfg) {
			return
		}
		auditLog(c, audit.Record{Action: "templates.apply", Target: r.Name, Detail: "candidate"})
		c.JSON(http.StatusOK, gin.H{"applied": r.Name, "ruleCount": len(cfg.Firewall.Rules), "mode": r.Mode})
	}
}

// validateTemplateApplyMode rejects modes outside the documented set.
// Empty is accepted: it means "inherit from global", which is the safe
// production default (monitor-first).
func validateTemplateApplyMode(mode string) error {
	switch mode {
	case "", "monitor", "enforce":
		return nil
	default:
		return fmt.Errorf("mode must be one of: \"\" (inherit), \"monitor\", or \"enforce\"; got %q", mode)
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
	// Mode, when set ("monitor" or "enforce"), overrides each generated
	// rule's ICSPredicate.Mode. Empty means inherit from global DPIMode
	// (which itself defaults to monitor — the operationally-safe default
	// for production deployments).
	Mode string `json:"mode,omitempty"`
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
		{Name: "cip_monitor_only", Description: "Allow CIP read services, deny writes and control commands", Protocol: "cip"},
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
		if err := validateTemplateApplyMode(r.Mode); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		sourceZones, destZones, ranges := normalizeICSTemplateRequest(r)
		generated, err := buildICSTemplateRules(r.Template, ranges)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		applyICSTemplateZones(generated, sourceZones, destZones)
		applyICSTemplateMode(generated, r.Mode)

		if r.Preview {
			c.JSON(http.StatusOK, gin.H{"template": r.Template, "preview": true, "rules": generated, "mode": r.Mode})
			return
		}

		var created, updated int
		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			created, updated = upsertFirewallRulesByID(cfg.Firewall.Rules, generated)
			cfg.Firewall.Rules = appendFirewallRulesUpsert(cfg.Firewall.Rules, generated)
			return true
		})
		if !ok {
			return
		}

		if !candidateShadowWarnings(c, cfg) {
			return
		}
		auditLog(c, audit.Record{Action: "templates.ics.apply", Target: r.Template, Detail: "candidate"})
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
	// Normalize hyphens to underscores so callers can use either form.
	// GET /api/v1/templates returns hyphenated names (the registry's
	// canonical user-facing form, e.g. "modbus-read-only"); the apply
	// switch below was written with underscores. Without this, anyone
	// copy-pasting from the list endpoint into apply gets a 400. Both
	// forms are unambiguous because template names contain at most one
	// separator and that separator is the only divergence point.
	requested := template
	template = strings.ReplaceAll(template, "-", "_")
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
	case "cip_monitor_only":
		return templates.CIPMonitorOnly(), nil
	default:
		return nil, fmt.Errorf("unknown ICS template %q", requested)
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

// applyICSTemplateMode overwrites ICSPredicate.Mode on every generated
// rule when mode is non-empty. Blank mode preserves the template's
// default (also blank, inheriting from global DPIMode at runtime).
func applyICSTemplateMode(generated []config.Rule, mode string) {
	if mode == "" {
		return
	}
	for i := range generated {
		generated[i].ICS.Mode = mode
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
