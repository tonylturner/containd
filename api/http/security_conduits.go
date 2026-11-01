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
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Non-industrial port names remain independent of transport.
var portNameMap = map[int]string{
	443:  "HTTPS",
	80:   "HTTP",
	22:   "SSH",
	3389: "RDP",
	53:   "DNS",
	161:  "SNMP",
}

// Industrial names apply only to registered decoder transports.
var icsPortNames = map[int]string{
	ics.ModbusPort:      "Modbus",
	ics.DNP3Port:        "DNP3",
	ics.CIPPort:         "EtherNet/IP",
	ics.IEC104Port:      "IEC 104",
	ics.CIPImplicitPort: "EtherNet/IP",
}

// Ports considered encrypted for TLS enforcement check.
var encryptedPorts = map[int]bool{
	443: true, 22: true, 990: true, 989: true,
}

// Ports considered plaintext (unencrypted).
var plaintextPorts = map[int]bool{
	80: true, 23: true, 21: true, 161: true, 162: true,
}

// Admin protocol names for MITRE mapping.
var adminProtos = map[string]bool{
	"SSH": true, "RDP": true,
}

type protoEntry struct {
	N string `json:"n"`
	T string `json:"t"`

	industrial bool
}

type conduitResult struct {
	From           string       `json:"from"`
	To             string       `json:"to"`
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
		cfg, err := readRunningOrDefault(c, store)
		if err != nil {
			internalError(c, err)
			return
		}
		globals := computeConduitGlobals(cfg)
		result := make([]*conduitResult, 0)
		for _, from := range globals.zoneNames {
			for _, to := range globals.zoneNames {
				if from == to {
					continue
				}
				result = append(result, buildConduitResult(cfg, globals, from, to))
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
		defaultAction: cfg.Firewall.EffectiveDefaultAction(),
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
	effective := reachableConduitRules(matching, cfg.DataPlane.DPIMode)
	state := computeConduitState(effective, globals.defaultAction, from, to, cfg.DataPlane.DPIMode)
	protos, allPorts, hasProtoRestrictions, hasICSPredicate := conduitProtocols(effective)
	defaultDeny := globals.defaultAction == config.ActionDeny || hasExplicitDenyAll(effective, from)
	tlsEnforced := conduitTLSEnforced(allPorts)
	protoWhitelist := hasProtoRestrictions
	if state == "allow" {
		// An unrestricted winning grant or ALLOW default is not a service whitelist.
		tlsEnforced, protoWhitelist = false, false
	}
	ruleDescs := conduitRuleDescriptions(matching, from, to)
	gaps := computeGaps(state, defaultDeny, tlsEnforced, protoWhitelist, globals.auditLogged, globals.avEnabled, allPorts, hasICSPredicate)
	mitre := computeMitre(state, protoWhitelist, from, protos)
	return &conduitResult{
		From:           from,
		To:             to,
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
		name, industrial := conduitProtocolInfo(p)
		t := "allowed"
		if hasICSPredicate || r.ICS.Protocol != "" {
			t = "inspect"
		}
		protos = append(protos, protoEntry{N: name, T: t, industrial: industrial})
	}
	return protos
}

func conduitProtocolInfo(p config.Protocol) (string, bool) {
	port := parsePort(p.Port)
	var transport uint8
	switch strings.ToLower(p.Name) {
	case "tcp":
		transport = ics.TCP
	case "udp":
		transport = ics.UDP
	}
	industrial := port > 0 && port <= 65535 && ics.IsDecoderPortOn(transport, uint16(port))
	name := portNameMap[port]
	if industrial {
		name = icsPortNames[port]
	}
	if name == "" {
		name = strings.ToUpper(p.Name)
		if p.Port != "" {
			name += "/" + p.Port
		}
	}
	return name, industrial
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

// reachableConduitRules uses the same ordered coverage warnings as enforcement.
// Hidden grants must not advertise services, TLS or protocol whitelisting.
func reachableConduitRules(list []config.Rule, mode string) []config.Rule {
	snap := &rules.Snapshot{DPIMode: mode}
	for _, r := range list {
		snap.Firewall = append(snap.Firewall, firewallRuleEntry(r))
	}
	hidden := map[string]bool{}
	for _, w := range enforce.NewCompiler().RuleWarnings(snap) {
		if w.ShadowedBy != "" {
			hidden[w.RuleID] = true
		}
	}
	out := make([]config.Rule, 0, len(list))
	for _, r := range list {
		if !hidden[r.ID] {
			out = append(out, r)
		}
	}
	return out
}

// A conduit is a static zone summary, not a proof about every address,
// identity, schedule or decoded operation. The ordered evaluator determines
// the unconditional terminal/default; earlier conditional exceptions make
// the result partial rather than asserting universal permission or refusal.
func computeConduitState(list []config.Rule, defaultAction config.Action, from, to, mode string) string {
	snap := &rules.Snapshot{Default: rules.Action(defaultAction), DPIMode: mode}
	for _, r := range list {
		entry := firewallRuleEntry(r)
		if entry.Action.Decides() && !rules.MonitorICS(entry, mode) {
			snap.Firewall = append(snap.Firewall, entry)
		}
	}
	if len(snap.Firewall) == 0 {
		if defaultAction == config.ActionAllow {
			return "unmodeled"
		}
		return "block"
	}
	action, winner := rules.NewEvaluator(snap).EvaluateMatch(rules.EvalContext{SrcZone: from, DstZone: to})
	for _, entry := range snap.Firewall {
		if winner != nil && entry.ID == winner.ID {
			break
		}
		if (entry.Action == rules.ActionAllow) != (action == rules.ActionAllow) {
			return "partial"
		}
	}
	if action == rules.ActionAllow {
		return "allow"
	}
	return "block"
}

func hasExplicitDenyAll(rules []config.Rule, srcZone string) bool {
	for _, r := range rules {
		if !denies(r.Action) {
			continue
		}
		srcMatch := len(r.SourceZones) == 0 || containsStr(r.SourceZones, srcZone)
		dstMatch := len(r.DestZones) == 0
		noProto := len(r.Protocols) == 0 && len(r.Sources) == 0 && len(r.Destinations) == 0 && len(r.ViaForwards) == 0 && len(r.Identities) == 0 && r.Schedule == nil && r.ICS.Empty()
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
			name, _ := conduitProtocolInfo(p)
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

func computeMitre(state string, protoWhitelist bool, fromZone string, protos []protoEntry) []string {
	var mitre []string

	hasICSPort := false
	for _, p := range protos {
		if p.industrial {
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

// denies reports a rule action that refuses traffic: DENY drops it and
// RESET rejects it.
func denies(a config.Action) bool {
	return a == config.ActionDeny || a == config.ActionReset
}
