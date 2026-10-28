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
	for _, spec := range []string{"0", "256", "0x0100", "0X01ff", "100-511", "0x0100-0x01FF", "0x0100-511", "7-7", " 1 - 2 ", "65535", "0-0xFFFF"} {
		if err := icsAddressConfig("modbus", spec).Validate(); err != nil {
			t.Errorf("modbus address %q: %v", spec, err)
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
		{"modbus", "-0x10", "negative"},
		{"modbus", "0x200-0x100", "range starts at 512 after its end 256"},
		{"modbus", "10-9", "range starts at 10 after its end 9"},
		{"modbus", "65536", "modbus addresses end at 65535"},
		{"modbus", "0-0x10000", "modbus addresses end at 65535"},
		{"modbus", "4294967296", "exceeds the largest address 4294967295"},
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

func TestValidateRefusesUnsupportedICSAddresses(t *testing.T) {
	const message = "rule ics-1: Address filters are not supported for DNP3 or CIP. Remove this filter before saving; protocol-specific station, point and CIP path selectors are not available yet."
	for _, proto := range []string{"dnp3", "cip"} {
		for _, action := range []Action{ActionAllow, ActionDeny} {
			for _, mode := range []string{"", "learn", "enforce"} {
				t.Run(proto+"/"+string(action)+"/"+mode, func(t *testing.T) {
					for _, addresses := range [][]string{{"1"}, {"0-10"}, {"0x0100"}, {""}, {"0x02/1/1"}} {
						cfg := genericICSConfig(proto, mode, "enforce", 100)
						cfg.Firewall.Rules[0].Action = action
						cfg.Firewall.Rules[0].ICS.Addresses = addresses
						if err := cfg.Validate(); err == nil || err.Error() != message {
							t.Fatalf("addresses %q: got %v, want %q", addresses, err, message)
						}
					}
					for _, addresses := range [][]string{nil, {}} {
						cfg := genericICSConfig(proto, mode, "enforce", 100)
						cfg.Firewall.Rules[0].Action = action
						cfg.Firewall.Rules[0].ICS.Addresses = addresses
						if err := cfg.Validate(); err != nil {
							t.Fatalf("empty addresses: %v", err)
						}
					}
				})
			}
		}
	}
}

func TestUnsupportedAddressesCannotBypassActionValidation(t *testing.T) {
	for _, proto := range []string{"dnp3", "cip"} {
		for _, action := range []Action{ActionReset, ActionRateLimit, ActionTag} {
			cfg := icsAddressConfig(proto, "1")
			cfg.Firewall.Rules[0].Action = action
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "cannot take an ics protocol") {
				t.Fatalf("%s/%s: %v", proto, action, err)
			}
		}
	}
}

func TestUnsupportedAddressesPatchRequiresExplicitRemoval(t *testing.T) {
	for _, proto := range []string{"dnp3", "cip"} {
		cfg := icsAddressConfig(proto, "10-20")
		original := cfg.Firewall.Rules[0].ICS
		unchanged, err := PatchICSPredicate(original, []byte(`{"readOnly":true}`))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Firewall.Rules[0].ICS = unchanged
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s: omitting addresses silently cleared the filter", proto)
		}
		corrected, err := PatchICSPredicate(original, []byte(`{"addresses":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Firewall.Rules[0].ICS = corrected
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s: explicit removal did not repair the rule: %v", proto, err)
		}
	}
}
