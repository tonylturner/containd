// SPDX-License-Identifier: Apache-2.0
package synth

import (
	"math/rand"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/ics"
)

func TestRemovedProtocolScenarios(t *testing.T) {
	for _, scenario := range scenarios {
		if ics.Removed(scenario.proto) {
			t.Fatalf("retired synthetic scenario: %s", scenario.proto)
		}
	}
}

func TestCIPScenarioLayers(t *testing.T) {
	found := false
	for _, scenario := range scenarios {
		if scenario.proto != "cip" {
			continue
		}
		found = true
		attrs := scenario.attrFn(rand.New(rand.NewSource(1)))
		for key, want := range map[string]any{
			"enip_command": "SendRRData", "enip_command_code": uint16(0x6f),
			"enip_session_handle": uint32(1), "cpf_item_types": "0x0000,0x00b2",
		} {
			if attrs[key] != want {
				t.Errorf("%s=%v, want %v", key, attrs[key], want)
			}
		}
		for _, old := range []string{"command", "command_code", "session_handle"} {
			if _, ok := attrs[old]; ok {
				t.Errorf("obsolete alias %s", old)
			}
		}
	}
	if !found {
		t.Fatal("no CIP scenario")
	}
}
