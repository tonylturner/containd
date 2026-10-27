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
		{"disabled ignores settings", AVConfig{TimeoutSec: -1, ClamAV: ClamAVConfig{UpdateSchedule: "0 */6 * * *"}}, ""},
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
		{"default cache ttl", clamav(func(c *AVConfig) { c.CacheTTL = 0 }), ""},
		{"cache ttl", icap(func(c *AVConfig) { c.CacheTTL = time.Minute }), ""},
		{"negative cache ttl", clamav(func(c *AVConfig) { c.CacheTTL = -time.Nanosecond }), "cacheTtl"},
		{"empty mode is clamav", clamav(func(c *AVConfig) { c.Mode = "" }), ""},
		{"empty mode ignores icap servers", clamav(func(c *AVConfig) { c.Mode = " "; c.ICAP.Servers = nil }), ""},
		{"unknown mode", clamav(func(c *AVConfig) { c.Mode = "remote" }), "services.av.mode"},
		{"icap needs servers", icap(func(c *AVConfig) { c.ICAP.Servers = nil }), "icap.servers"},
		{"icap rejects a second server", icap(func(c *AVConfig) {
			c.ICAP.Servers = append(c.ICAP.Servers, ICAPServer{Address: "127.0.0.2:1344"})
		}), "exactly one server"},
		{"icap needs an address", icap(func(c *AVConfig) { c.ICAP.Servers[0].Address = " " }), "address required"},
		{"icap address needs a port", icap(func(c *AVConfig) { c.ICAP.Servers[0].Address = "icap.example" }), "host:port"},
		{"icap tls service", icap(func(c *AVConfig) {
			c.ICAP.Servers[0] = ICAPServer{Address: "icap.example:11344", UseTLS: true, Service: "avscan"}
		}), ""},
		{"clamav ignores icap servers", clamav(func(c *AVConfig) {
			c.ICAP.Servers = []ICAPServer{{Address: "a:1"}, {Address: "b:2"}}
		}), ""},
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

func TestClamAVUpdateInterval(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 0, " \t": 0, "90m": 90 * time.Minute, " 4h ": 4 * time.Hour} {
		if got, err := (ClamAVConfig{UpdateSchedule: in}).UpdateInterval(); err != nil || got != want {
			t.Fatalf("UpdateInterval(%q) = %s, %v; want %s", in, got, err, want)
		}
	}
	for _, in := range []string{"0 */6 * * *", "6", "0s", "-1h", "daily"} {
		if _, err := (ClamAVConfig{UpdateSchedule: in}).UpdateInterval(); err == nil || !strings.Contains(err.Error(), "updateSchedule") {
			t.Fatalf("UpdateInterval(%q) = %v, want an updateSchedule error", in, err)
		}
	}
}
