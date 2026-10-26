// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"testing"
	"time"
)

// A daemon that never started or rendered reports empty timestamps rather
// than the zero time, and recorded times render as RFC 3339 strings.
func TestStatusTimestampsOmitZeroTime(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	when := time.Date(2026, 3, 13, 10, 0, 0, 0, time.FixedZone("x", 3600))
	want := "2026-03-13T09:00:00Z"

	ntp := NewNTPManager(dir)
	proxy := NewProxyManager(ProxyOptions{BaseDir: dir})
	dhcp := NewDHCPManager(dir)
	vpn := NewVPNManager(dir)
	dns := NewDNSManager(dir)

	statuses := map[string]func() map[string]any{
		"ntp":   ntp.Status,
		"proxy": proxy.Status,
		"dhcp":  dhcp.Status,
		"vpn":   vpn.Status,
		"dns":   dns.Status,
	}
	keys := map[string][]string{
		"ntp":   {"last_render", "last_start", "last_stop"},
		"proxy": {"last_render", "envoy_last_start", "nginx_last_start", "envoy_last_stop", "nginx_last_stop"},
		"dhcp":  {"last_render"},
		"vpn":   {"last_render"},
		"dns":   {"last_render"},
	}
	for svc, status := range statuses {
		got := status()
		for _, key := range keys[svc] {
			if got[key] != "" {
				t.Errorf("%s %s before any run = %#v, want empty string", svc, key, got[key])
			}
		}
	}

	ntp.lastRender, ntp.lastStart, ntp.lastStop = when, when, when
	proxy.lastRender = when
	proxy.lastEnvoyStart, proxy.lastNginxStart = when, when
	proxy.lastEnvoyStop, proxy.lastNginxStop = when, when
	dhcp.lastRender = when
	vpn.lastRender = when
	dns.lastRender = when
	for svc, status := range statuses {
		got := status()
		for _, key := range keys[svc] {
			if got[key] != want {
				t.Errorf("%s %s = %#v, want %q", svc, key, got[key], want)
			}
		}
	}
}
