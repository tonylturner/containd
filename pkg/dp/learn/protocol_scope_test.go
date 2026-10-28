// SPDX-License-Identifier: Apache-2.0
package learn

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func TestRecordEventIndustrialScope(t *testing.T) {
	learner := New()
	for _, protocol := range []string{"http", "dns", "tls", "ssh", "smb", "ntp", "snmp", "rdp", "ics", "tcp", "udp",
		"iec104", "s7comm", "s7", "mms", "iec61850", "goose", "bacnet", "opcua", ""} {
		learner.RecordEvent("192.0.2.1", "192.0.2.2", dpi.Event{Proto: protocol, Kind: "request"})
	}
	if len(learner.Profiles()) != 0 || len(learner.GenerateRules()) != 0 {
		t.Fatal("non-learnable protocols created profiles or rules")
	}
	for _, protocol := range []string{"modbus", "dnp3", "cip"} {
		learner.RecordEvent("192.0.2.1", "192.0.2.2", dpi.Event{Proto: protocol, Kind: "request"})
	}
	if len(learner.Profiles()) != 3 || len(learner.GenerateRules()) != 3 {
		t.Fatal("kept learnable protocols were excluded")
	}
}
