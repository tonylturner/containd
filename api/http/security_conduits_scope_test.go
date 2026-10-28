// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestProtocolScopeConduits(t *testing.T) {
	for _, tc := range []struct {
		transport  string
		port       string
		name       string
		industrial bool
	}{
		{"tcp", "2404", "IEC 104", true},
		{"udp", "2222", "EtherNet/IP", true},
		{"tcp", "502", "Modbus", true},
		{"tcp", "20000", "DNP3", true},
		{"tcp", "44818", "EtherNet/IP", true},
		{"tcp", "102", "TCP/102", false},
		{"tcp", "4840", "TCP/4840", false},
		{"udp", "47808", "UDP/47808", false},
		{"udp", "18245", "UDP/18245", false},
	} {
		t.Run(tc.transport+"/"+tc.port, func(t *testing.T) {
			ports := map[int]bool{}
			entries := protocolEntriesForRule(config.Rule{Protocols: []config.Protocol{{Name: tc.transport, Port: tc.port}}}, false, ports)
			if len(entries) != 1 || entries[0].N != tc.name {
				t.Fatalf("protocol label=%+v want=%s", entries, tc.name)
			}
			mitre := computeMitre("allow", true, "lan", entries, ports)
			if got := slices.Contains(mitre, "T0886 Remote Services OT"); got != tc.industrial {
				t.Fatalf("industrial classification=%t want=%t (%v)", got, tc.industrial, mitre)
			}
		})
	}
}
