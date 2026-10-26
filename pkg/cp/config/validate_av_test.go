// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidateAV(t *testing.T) {
	clamav := func(mut func(*AVConfig)) AVConfig {
		cfg := AVConfig{Enabled: true, Mode: "clamav"}
		mut(&cfg)
		return cfg
	}
	icap := func(mut func(*AVConfig)) AVConfig {
		cfg := AVConfig{Enabled: true, Mode: "icap", ICAP: ICAPConfig{Servers: []ICAPServer{{Address: "127.0.0.1:1344"}}}}
		mut(&cfg)
		return cfg
	}
	for _, tc := range []struct {
		name string
		cfg  AVConfig
		err  string // empty: valid
	}{
		{"disabled ignores settings", AVConfig{TimeoutSec: -1, BlockTTL: -1, ClamAV: ClamAVConfig{UpdateSchedule: "0 */6 * * *"}}, ""},
		{"clamav default socket", clamav(func(*AVConfig) {}), ""},
		{"clamav explicit socket", clamav(func(c *AVConfig) { c.ClamAV.SocketPath = "/run/clamav/clamd.sock" }), ""},
		{"clamav duration schedule", clamav(func(c *AVConfig) { c.ClamAV.UpdateSchedule = " 4h " }), ""},
		{"clamav cron schedule", clamav(func(c *AVConfig) { c.ClamAV.UpdateSchedule = "0 */6 * * *" }), "updateSchedule"},
		{"clamav bare number schedule", clamav(func(c *AVConfig) { c.ClamAV.UpdateSchedule = "6" }), "updateSchedule"},
		{"clamav zero schedule", clamav(func(c *AVConfig) { c.ClamAV.UpdateSchedule = "0s" }), "updateSchedule"},
		{"clamav negative schedule", clamav(func(c *AVConfig) { c.ClamAV.UpdateSchedule = "-1h" }), "updateSchedule"},
		{"icap does not run freshclam", icap(func(c *AVConfig) { c.ClamAV.UpdateSchedule = "daily" }), ""},
		{"default timeout", icap(func(c *AVConfig) { c.TimeoutSec = 0 }), ""},
		{"maximum timeout", icap(func(c *AVConfig) { c.TimeoutSec = maxAVTimeoutSec }), ""},
		{"negative timeout", icap(func(c *AVConfig) { c.TimeoutSec = -1 }), "timeoutSec"},
		{"excessive timeout", clamav(func(c *AVConfig) { c.TimeoutSec = maxAVTimeoutSec + 1 }), "timeoutSec"},
		{"unlimited size", clamav(func(c *AVConfig) { c.MaxSizeBytes = 0 }), ""},
		{"maximum size", clamav(func(c *AVConfig) { c.MaxSizeBytes = maxAVScanBytes }), ""},
		{"negative size", clamav(func(c *AVConfig) { c.MaxSizeBytes = -1 }), "maxSizeBytes"},
		{"excessive size", icap(func(c *AVConfig) { c.MaxSizeBytes = maxAVScanBytes + 1 }), "maxSizeBytes"},
		{"default block ttl", icap(func(c *AVConfig) { c.BlockTTL = 0 }), ""},
		{"block ttl", clamav(func(c *AVConfig) { c.BlockTTL = 3600 }), ""},
		{"negative block ttl", icap(func(c *AVConfig) { c.BlockTTL = -1 }), "blockTtlSeconds"},
		{"default cache ttl", clamav(func(c *AVConfig) { c.CacheTTL = 0 }), ""},
		{"cache ttl", icap(func(c *AVConfig) { c.CacheTTL = time.Minute }), ""},
		{"negative cache ttl", clamav(func(c *AVConfig) { c.CacheTTL = -time.Nanosecond }), "cacheTtl"},
		{"icap needs servers", icap(func(c *AVConfig) { c.ICAP.Servers = nil }), "icap.servers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAV(tc.cfg)
			if tc.err == "" && err != nil {
				t.Fatalf("validateAV = %v, want valid", err)
			}
			if tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
				t.Fatalf("validateAV = %v, want error mentioning %q", err, tc.err)
			}
		})
	}
}
