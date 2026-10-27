// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/enforce"
)

// Zone names are refused at commit when enforcement could not declare
// their interface set (zone_<hex name>, at most 255 bytes) or when rule and
// set lookups would disagree on surrounding whitespace.
func TestValidateZoneNames(t *testing.T) {
	longest := strings.Repeat("z", enforce.MaxZoneNameBytes)
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"ot", true},
		{"ot cell 1", true},
		{longest, true},
		{strings.Repeat("é", enforce.MaxZoneNameBytes/2), true},
		{longest + "z", false},
		{strings.Repeat("é", enforce.MaxZoneNameBytes/2+1), false},
		{" lan", false},
		{"lan ", false},
		{"\tlan", false},
		{"lan\n", false},
		{"", false},
		{"  ", false},
	} {
		cfg := DefaultConfig()
		cfg.Zones = append(cfg.Zones, Zone{Name: tc.name})
		err := cfg.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("zone %q: err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}
