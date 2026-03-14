// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// Well-known port-to-protocol name mappings.
var portNameMap = map[int]string{
	443:   "HTTPS",
	80:    "HTTP",
	22:    "SSH",
	3389:  "RDP",
	53:    "DNS",
	161:   "SNMP",
	502:   "Modbus",
	20000: "DNP3",
	44818: "EtherNet/IP",
	102:   "S7comm",
	47808: "BACnet",
	4840:  "OPC-UA",
}

// Ports considered encrypted for TLS enforcement check.
var encryptedPorts = map[int]bool{
	443: true, 22: true, 990: true, 989: true,
}

// Ports considered plaintext (unencrypted).
var plaintextPorts = map[int]bool{
	80: true, 23: true, 21: true, 161: true, 162: true,
}

// ICS protocol ports.
var icsPorts = map[int]bool{
	502: true, 20000: true, 44818: true, 102: true, 47808: true, 4840: true,
}

// Admin protocol names for MITRE mapping.
var adminProtos = map[string]bool{
	"SSH": true, "RDP": true,
}

type protoEntry struct {
	N string `json:"n"`
	T string `json:"t"`
}

type conduitResult struct {
	State          string       `json:"state"`
	IDS            string       `json:"ids"`
	Proto          []protoEntry `json:"proto"`
	Traffic        float64      `json:"traffic"`
	Rules          []string     `json:"rules"`
	Gaps           []string     `json:"gaps"`
	Mitre          []string     `json:"mitre"`
	DefaultDeny    bool         `json:"defaultDeny"`
	TLSEnforced    bool         `json:"tlsEnforced"`
	ProtoWhitelist bool         `json:"protoWhitelist"`
	MFARequired    bool         `json:"mfaRequired"`
	AuditLogged    bool         `json:"auditLogged"`
	AVEnabled      bool         `json:"avEnabled"`
}

type conduitGlobalState struct {
	zoneNames     []string
	idsMode       string
	auditLogged   bool
	avEnabled     bool
	defaultAction config.Action
}

func securityConduitsHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		globals := computeConduitGlobals(cfg)
		result := make(map[string]*conduitResult)
		for _, from := range globals.zoneNames {
			for _, to := range globals.zoneNames {
				if from == to {
					continue
				}
				key := from + "\u2192" + to
				result[key] = buildConduitResult(cfg, globals, from, to)
			}
		}
		c.JSON(http.StatusOK, result)
	}
}

func computeConduitGlobals(cfg *config.Config) conduitGlobalState {
	zoneNames := make([]string, len(cfg.Zones))
	for i, z := range cfg.Zones {
		zoneNames[i] = z.Name
	}
	return conduitGlobalState{
		zoneNames:     zoneNames,
		idsMode:       conduitIDSMode(cfg),
		auditLogged:   conduitAuditLogged(cfg),
		avEnabled:     cfg.Services.AV.Enabled,
		defaultAction: cfg.Firewall.DefaultAction,
	}
}

func conduitIDSMode(cfg *config.Config) string {
	if cfg.IDS.Enabled {
		return "full"
	}
	return "none"
}

func conduitAuditLogged(cfg *config.Config) bool {
	for _, fwd := range cfg.Services.Syslog.Forwarders {
		if fwd.Address != "" {
			return true
		}
	}
	return false
}

func buildConduitResult(cfg *config.Config, globals conduitGlobalState, from, to string) *conduitResult {
	matching := matchingConduitRules(cfg.Firewall.Rules, from, to)
	state := computeConduitState(matching, globals.defaultAction)
	protos, allPorts, hasProtoRestrictions, hasICSPredicate := conduitProtocols(matching)
	defaultDeny := globals.defaultAction == config.ActionDeny || hasExplicitDenyAll(cfg.Firewall.Rules, from)
	tlsEnforced := conduitTLSEnforced(allPorts)
	protoWhitelist := hasProtoRestrictions
	ruleDescs := conduitRuleDescriptions(matching, from, to)
	gaps := computeGaps(state, defaultDeny, tlsEnforced, protoWhitelist, globals.auditLogged, globals.avEnabled, allPorts, hasICSPredicate)
	mitre := computeMitre(state, protoWhitelist, from, protos, allPorts)
	return &conduitResult{
		State:          state,
		IDS:            globals.idsMode,
		Proto:          nonNilProtoEntries(protos),
		Traffic:        0.0,
		Rules:          nonNilStrings(ruleDescs),
		Gaps:           nonNilStrings(gaps),
		Mitre:          nonNilStrings(mitre),
		DefaultDeny:    defaultDeny,
		TLSEnforced:    tlsEnforced,
		ProtoWhitelist: protoWhitelist,
		MFARequired:    false,
		AuditLogged:    globals.auditLogged,
		AVEnabled:      globals.avEnabled,
	}
}

func matchingConduitRules(rules []config.Rule, from, to string) []config.Rule {
	var matching []config.Rule
	for _, r := range rules {
		srcMatch := len(r.SourceZones) == 0 || containsStr(r.SourceZones, from)
		dstMatch := len(r.DestZones) == 0 || containsStr(r.DestZones, to)
		if srcMatch && dstMatch {
			matching = append(matching, r)
		}
	}
	return matching
}

func conduitProtocols(matching []config.Rule) ([]protoEntry, map[int]bool, bool, bool) {
	var protos []protoEntry
	allPorts := make(map[int]bool)
	hasProtoRestrictions := false
	hasICSPredicate := false
	for _, r := range matching {
		if r.Action != config.ActionAllow {
			continue
		}
		if r.ICS.Protocol != "" {
			hasICSPredicate = true
		}
		if len(r.Protocols) == 0 {
			continue
		}
		hasProtoRestrictions = true
		protos = append(protos, protocolEntriesForRule(r, hasICSPredicate, allPorts)...)
	}
	return protos, allPorts, hasProtoRestrictions, hasICSPredicate
}

func protocolEntriesForRule(r config.Rule, hasICSPredicate bool, allPorts map[int]bool) []protoEntry {
	var protos []protoEntry
	for _, p := range r.Protocols {
		port := parsePort(p.Port)
		if port <= 0 {
			continue
		}
		allPorts[port] = true
		name := portNameMap[port]
		if name == "" {
			name = fmt.Sprintf("%s/%s", strings.ToUpper(p.Name), p.Port)
		}
		t := "allowed"
		if hasICSPredicate || r.ICS.Protocol != "" {
			t = "inspect"
		}
		protos = append(protos, protoEntry{N: name, T: t})
	}
	return protos
}

func conduitTLSEnforced(allPorts map[int]bool) bool {
	if len(allPorts) == 0 {
		return false
	}
	for port := range allPorts {
		if !encryptedPorts[port] {
			return false
		}
	}
	return true
}

func conduitRuleDescriptions(matching []config.Rule, from, to string) []string {
	var ruleDescs []string
	for _, r := range matching {
		ruleDescs = append(ruleDescs, describeRule(r, from, to))
	}
	return ruleDescs
}

func nonNilProtoEntries(in []protoEntry) []protoEntry {
	if in == nil {
		return []protoEntry{}
	}
	return in
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func computeConduitState(rules []config.Rule, defaultAction config.Action) string {
	if len(rules) == 0 {
		if defaultAction == config.ActionDeny {
			return "block"
		}
		return "unmodeled"
	}

	hasAllow := false
	hasDeny := false
	allAllowUnrestricted := true

	for _, r := range rules {
		if r.Action == config.ActionAllow {
			hasAllow = true
			if len(r.Protocols) > 0 || r.ICS.Protocol != "" {
				allAllowUnrestricted = false
			}
		} else if r.Action == config.ActionDeny {
			hasDeny = true
		}
	}

	if !hasAllow && hasDeny {
		return "block"
	}
	if hasAllow && allAllowUnrestricted {
		return "allow"
	}
	if hasAllow {
		return "partial"
	}
	return "block"
}

func hasExplicitDenyAll(rules []config.Rule, srcZone string) bool {
	for _, r := range rules {
		if r.Action != config.ActionDeny {
			continue
		}
		srcMatch := len(r.SourceZones) == 0 || containsStr(r.SourceZones, srcZone)
		dstMatch := len(r.DestZones) == 0
		noProto := len(r.Protocols) == 0
		if srcMatch && dstMatch && noProto {
			return true
		}
	}
	return false
}

func describeRule(r config.Rule, from, to string) string {
	action := string(r.Action)
	var protoStr string
	if len(r.Protocols) > 0 {
		var names []string
		for _, p := range r.Protocols {
			name := portNameMap[parsePort(p.Port)]
			if name == "" {
				if p.Port != "" {
					name = strings.ToUpper(p.Name) + "/" + p.Port
				} else {
					name = strings.ToUpper(p.Name)
				}
			}
			names = append(names, name)
		}
		protoStr = strings.Join(names, "/")
	} else {
		protoStr = "ALL"
	}
	return fmt.Sprintf("%s %s from %s to %s", action, protoStr, strings.ToUpper(from), strings.ToUpper(to))
}

func computeGaps(state string, defaultDeny, tlsEnforced, protoWhitelist, auditLogged, avEnabled bool, ports map[int]bool, hasICS bool) []string {
	var gaps []string

	if !defaultDeny {
		gaps = append(gaps, "No default-deny policy")
	}
	if state == "allow" && !protoWhitelist {
		gaps = append(gaps, "No protocol whitelist - all protocols permitted")
	}
	if !tlsEnforced && len(ports) > 0 {
		gaps = append(gaps, "Unencrypted protocols permitted")
	}
	if !auditLogged {
		gaps = append(gaps, "No audit logging configured")
	}
	if !avEnabled {
		gaps = append(gaps, "Antivirus scanning not enabled")
	}
	if hasICS {
		hasPlaintext := false
		for port := range ports {
			if plaintextPorts[port] {
				hasPlaintext = true
				break
			}
		}
		if hasPlaintext {
			gaps = append(gaps, "ICS traffic mixed with plaintext IT protocols")
		}
	}
	if state == "unmodeled" {
		gaps = append(gaps, "No explicit rules defined for this conduit")
	}

	return gaps
}

func computeMitre(state string, protoWhitelist bool, fromZone string, protos []protoEntry, ports map[int]bool) []string {
	var mitre []string

	hasICSPort := false
	for port := range ports {
		if icsPorts[port] {
			hasICSPort = true
			break
		}
	}

	if state != "block" && hasICSPort {
		mitre = append(mitre, "T0886 Remote Services OT", "T0843 Program Download")
	}
	if state == "allow" && !protoWhitelist {
		mitre = append(mitre, "T1048 Exfiltration Over Alt Protocol")
	}

	fromLower := strings.ToLower(fromZone)
	if fromLower == "internet" || fromLower == "wan" {
		mitre = append(mitre, "T1190 Exploit Public App", "T1595 Active Scanning")
	}

	for _, p := range protos {
		if adminProtos[p.N] {
			mitre = append(mitre, "T1021 Remote Services")
			break
		}
	}

	return mitre
}

func parsePort(s string) int {
	if s == "" {
		return 0
	}
	// Handle ranges by taking the first port.
	if idx := strings.Index(s, "-"); idx >= 0 {
		s = s[:idx]
	}
	n, _ := strconv.Atoi(s)
	return n
}

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
