// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"slices"
	"strconv"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/ics"
)

func TestProtocolScopeConduits(t *testing.T) {
	for _, tc := range []struct {
		transport  string
		port       string
		name       string
		industrial bool
	}{
		{"tcp", "2404", "IEC 104", true},
		{"udp", "2404", "UDP/2404", false},
		{"tcp", "2222", "TCP/2222", false},
		{"udp", "2222", "EtherNet/IP", true},
		{"sctp", "2222", "SCTP/2222", false},
		{"tcp", "502", "Modbus", true},
		{"udp", "502", "UDP/502", false},
		{"tcp", "20000", "DNP3", true},
		{"udp", "20000", "UDP/20000", false},
		{"tcp", "44818", "EtherNet/IP", true},
		{"udp", "44818", "EtherNet/IP", true},
		{"TCP", "44818", "EtherNet/IP", true},
		{"udp", "67758", "UDP/67758", false},
		{"tcp", "443", "HTTPS", false},
		{"udp", "443", "HTTPS", false},
		{"tcp", "22", "SSH", false},
		{"udp", "22", "SSH", false},
		{"udp", "80", "HTTP", false},
		{"udp", "161", "SNMP", false},
		{"tcp", "102", "TCP/102", false},
		{"tcp", "4840", "TCP/4840", false},
		{"udp", "47808", "UDP/47808", false},
		{"udp", "18245", "UDP/18245", false},
	} {
		t.Run(tc.transport+"/"+tc.port, func(t *testing.T) {
			ports := map[int]bool{}
			rule := config.Rule{Action: config.ActionAllow, Protocols: []config.Protocol{{Name: tc.transport, Port: tc.port}}}
			entries := protocolEntriesForRule(rule, false, ports)
			if len(entries) != 1 || entries[0].N != tc.name {
				t.Fatalf("protocol label=%+v want=%s", entries, tc.name)
			}
			if got, want := describeRule(rule, "lan", "wan"), "ALLOW "+tc.name+" from LAN to WAN"; got != want {
				t.Errorf("rule description=%q want=%q", got, want)
			}
			mitre := computeMitre("allow", true, "lan", entries)
			for _, technique := range []string{"T0886 Remote Services OT", "T0843 Program Download"} {
				if got := slices.Contains(mitre, technique); got != tc.industrial {
					t.Errorf("%s classification=%t want=%t (%v)", technique, got, tc.industrial, mitre)
				}
			}
		})
	}
}

func TestConduitICSRegistryMembership(t *testing.T) {
	names := map[string]string{
		"modbus": "Modbus",
		"cip":    "EtherNet/IP",
		"iec104": "IEC 104",
		"dnp3":   "DNP3",
	}
	for _, port := range ics.DecoderPorts() {
		transport := "tcp"
		if port.Transport == ics.UDP {
			transport = "udp"
		}
		name, industrial := conduitProtocolInfo(config.Protocol{Name: transport, Port: strconv.Itoa(int(port.Port))})
		if !industrial || name != names[port.Protocol] || name == "" {
			t.Errorf("decoder %s/%d missing industrial label: %q (industrial=%t)", transport, port.Port, name, industrial)
		}
	}
}

func TestConduitProtocolPortChecks(t *testing.T) {
	for _, tc := range []struct {
		name       string
		protocols  []config.Protocol
		encrypted  bool
		plaintext  bool
		industrial bool
	}{
		{"ssh-service", []config.Protocol{{Name: "tcp", Port: "2222"}}, false, false, false},
		{"mixed-transports", []config.Protocol{{Name: "tcp", Port: "2222"}, {Name: "udp", Port: "2222"}}, false, false, true},
		{"https", []config.Protocol{{Name: "udp", Port: "443"}}, true, false, false},
		{"ssh", []config.Protocol{{Name: "udp", Port: "22"}}, true, false, false},
		{"http", []config.Protocol{{Name: "udp", Port: "80"}}, false, true, false},
		{"snmp", []config.Protocol{{Name: "udp", Port: "161"}}, false, true, false},
		{"industrial-and-http", []config.Protocol{{Name: "tcp", Port: "502"}, {Name: "tcp", Port: "80"}}, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Firewall.Rules = []config.Rule{{
				Action:    config.ActionAllow,
				Protocols: tc.protocols,
			}}
			// The plaintext-mixing check remains driven by an explicit ICS predicate.
			cfg.Firewall.Rules[0].ICS.Protocol = "modbus"
			result := buildConduitResult(cfg, computeConduitGlobals(cfg), "lan", "wan")
			if result.TLSEnforced != tc.encrypted {
				t.Errorf("TLS enforced=%t want=%t", result.TLSEnforced, tc.encrypted)
			}
			if got := slices.Contains(result.Gaps, "ICS traffic mixed with plaintext IT protocols"); got != tc.plaintext {
				t.Errorf("plaintext gap=%t want=%t (%v)", got, tc.plaintext, result.Gaps)
			}
			if got := slices.Contains(result.Mitre, "T0886 Remote Services OT"); got != tc.industrial {
				t.Errorf("industrial classification=%t want=%t (%v)", got, tc.industrial, result.Mitre)
			}
		})
	}
}
