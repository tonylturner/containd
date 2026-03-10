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

func securityConduitsHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}

		// Collect zone names.
		zoneNames := make([]string, len(cfg.Zones))
		for i, z := range cfg.Zones {
			zoneNames[i] = z.Name
		}

		// Global flags derived from config.
		idsMode := "none"
		if cfg.IDS.Enabled {
			idsMode = "full"
		}

		auditLogged := false
		for _, fwd := range cfg.Services.Syslog.Forwarders {
			if fwd.Address != "" {
				auditLogged = true
				break
			}
		}

		avEnabled := cfg.Services.AV.Enabled

		result := make(map[string]*conduitResult)

		for _, from := range zoneNames {
			for _, to := range zoneNames {
				if from == to {
					continue
				}

				// Find matching rules.
				var matching []config.Rule
				for _, r := range cfg.Firewall.Rules {
					srcMatch := len(r.SourceZones) == 0 || containsStr(r.SourceZones, from)
					dstMatch := len(r.DestZones) == 0 || containsStr(r.DestZones, to)
					if srcMatch && dstMatch {
						matching = append(matching, r)
					}
				}

				// Compute state.
				state := computeConduitState(matching, cfg.Firewall.DefaultAction)

				// Compute proto entries from ALLOW rules.
				var protos []protoEntry
				hasProtoRestrictions := false
				allPorts := make(map[int]bool)
				hasICSPredicate := false

				for _, r := range matching {
					if r.Action != config.ActionAllow {
						continue
					}
					if r.ICS.Protocol != "" {
						hasICSPredicate = true
					}
					if len(r.Protocols) > 0 {
						hasProtoRestrictions = true
						for _, p := range r.Protocols {
							port := parsePort(p.Port)
							if port > 0 {
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
						}
					}
				}

				// Compute boolean flags.
				defaultDeny := cfg.Firewall.DefaultAction == config.ActionDeny || hasExplicitDenyAll(cfg.Firewall.Rules, from)

				tlsEnforced := false
				if len(allPorts) > 0 {
					tlsEnforced = true
					for port := range allPorts {
						if !encryptedPorts[port] {
							tlsEnforced = false
							break
						}
					}
				}

				protoWhitelist := hasProtoRestrictions

				// Compute rule descriptions.
				var ruleDescs []string
				for _, r := range matching {
					ruleDescs = append(ruleDescs, describeRule(r, from, to))
				}

				// Compute gaps.
				gaps := computeGaps(state, defaultDeny, tlsEnforced, protoWhitelist, auditLogged, avEnabled, allPorts, hasICSPredicate)

				// Compute MITRE ATT&CK tags.
				mitre := computeMitre(state, protoWhitelist, from, protos, allPorts)

				// Ensure non-nil slices so JSON encodes [] not null.
				if protos == nil {
					protos = []protoEntry{}
				}
				if ruleDescs == nil {
					ruleDescs = []string{}
				}
				if gaps == nil {
					gaps = []string{}
				}
				if mitre == nil {
					mitre = []string{}
				}

				key := from + "\u2192" + to
				result[key] = &conduitResult{
					State:          state,
					IDS:            idsMode,
					Proto:          protos,
					Traffic:        0.0,
					Rules:          ruleDescs,
					Gaps:           gaps,
					Mitre:          mitre,
					DefaultDeny:    defaultDeny,
					TLSEnforced:    tlsEnforced,
					ProtoWhitelist: protoWhitelist,
					MFARequired:    false,
					AuditLogged:    auditLogged,
					AVEnabled:      avEnabled,
				}
			}
		}

		c.JSON(http.StatusOK, result)
	}
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
