// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// icsAddressConfig returns a valid config whose one rule names the ICS
// protocol proto and the address entries specs.
func icsAddressConfig(proto string, specs ...string) *Config {
	cfg := genericICSConfig(proto, "learn", "", 0)
	cfg.Firewall.Rules[0].ICS.Addresses = specs
	return cfg
}

func TestValidateAcceptsICSAddressForms(t *testing.T) {
	for _, proto := range []string{"modbus", "dnp3", "cip", "s7comm", "mms", "bacnet", "opcua"} {
		for _, spec := range []string{"0", "256", "0x0100", "0X01ff", "100-511", "0x0100-0x01FF", "0x0100-511", "7-7", " 1 - 2 ", "65535", "0-0xFFFF"} {
			if err := icsAddressConfig(proto, spec).Validate(); err != nil {
				t.Errorf("%s address %q: %v", proto, spec, err)
			}
		}
	}
	// Protocols other than Modbus carry 32-bit addresses.
	for _, proto := range []string{"dnp3", "opcua"} {
		for _, spec := range []string{"65536", "4294967295", "0-0xFFFFFFFF"} {
			if err := icsAddressConfig(proto, spec).Validate(); err != nil {
				t.Errorf("%s address %q: %v", proto, spec, err)
			}
		}
	}
}

func TestValidateRefusesICSAddressForms(t *testing.T) {
	for _, tc := range []struct{ proto, spec, reason string }{
		{"modbus", "", "not a decimal or 0x hex value"},
		{"modbus", "0x01G0", "not a decimal or 0x hex value"},
		{"modbus", "junk", "not a decimal or 0x hex value"},
		{"modbus", "+5", "not a decimal or 0x hex value"},
		{"modbus", "5-", "not a decimal or 0x hex value"},
		{"modbus", "1-2-3", "not a decimal or 0x hex value"},
		{"modbus", "-5", "negative"},
		{"dnp3", "-0x10", "negative"},
		{"modbus", "0x200-0x100", "range starts at 512 after its end 256"},
		{"opcua", "10-9", "range starts at 10 after its end 9"},
		{"modbus", "65536", "modbus addresses end at 65535"},
		{"modbus", "0-0x10000", "modbus addresses end at 65535"},
		{"dnp3", "4294967296", "exceeds the largest address 4294967295"},
	} {
		// The bad entry is refused even next to a valid one.
		err := icsAddressConfig(tc.proto, "1", tc.spec).Validate()
		if err == nil {
			t.Errorf("%s address %q: accepted", tc.proto, tc.spec)
			continue
		}
		for _, want := range []string{"rule ics-1", "addresses entry \"" + tc.spec + "\"", tc.reason, "low-high range"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s address %q: error %q lacks %q", tc.proto, tc.spec, err, want)
			}
		}
	}
}
