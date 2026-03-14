// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

func TestManagerTelemetryStatusAndValidation(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(ManagerOptions{BaseDir: dir, SuperviseProxies: false})
	if mgr == nil || mgr.Syslog == nil || mgr.DNS == nil || mgr.Proxy == nil || mgr.DHCP == nil || mgr.VPN == nil || mgr.AV == nil {
		t.Fatalf("unexpected manager wiring: %#v", mgr)
	}

	mgr.recordServiceEvent("service.envoy.requests", map[string]any{"count": 2})
	mgr.recordServiceEvent("service.envoy.error", map[string]any{"error_count": 1})
	mgr.recordServiceEvent("service.openvpn.applied", map[string]any{"count": 3})
	mgr.IncrementServiceMetric("dns", 4)

	events := mgr.ListTelemetryEvents(10)
	if len(events) != 3 {
		t.Fatalf("ListTelemetryEvents len = %d, want 3", len(events))
	}
	if !mgr.hasMetrics("proxy") || !mgr.hasMetrics("envoy") || !mgr.hasMetrics("vpn") || !mgr.hasMetrics("dns") {
		t.Fatal("expected telemetry metrics for proxy/envoy/vpn/dns")
	}

	proxyStatus, ok := mgr.decorateStatus("proxy", map[string]any{"enabled": true}).(map[string]any)
	if !ok {
		t.Fatal("decorateStatus did not return map")
	}
	if count, ok := proxyStatus["count"].(int); !ok || count != 3 {
		t.Fatalf("proxy count = %#v", proxyStatus["count"])
	}
	if errCount, ok := proxyStatus["errors_count"].(int); !ok || errCount != 1 {
		t.Fatalf("proxy errors_count = %#v", proxyStatus["errors_count"])
	}

	status, ok := mgr.Status().(map[string]any)
	if !ok {
		t.Fatal("manager Status did not return a map")
	}
	if _, ok := status["proxy"]; !ok {
		t.Fatalf("manager status missing proxy: %#v", status)
	}
	if _, ok := status["envoy"]; !ok {
		t.Fatalf("manager status missing envoy telemetry: %#v", status)
	}
	if _, ok := status["vpn"]; !ok {
		t.Fatalf("manager status missing vpn: %#v", status)
	}

	mgr.SetEventLister(func(limit int) []dpevents.Event { return nil })
	if mgr.Syslog.listEvents == nil {
		t.Fatal("SetEventLister did not install list function on Syslog manager")
	}

	if err := mgr.Validate(context.Background(), config.ServicesConfig{
		DNS: config.DNSConfig{Enabled: true, ListenPort: -1},
	}); err == nil {
		t.Fatal("expected invalid DNS validation error")
	}

	if err := (*Manager)(nil).TriggerAVUpdate(context.Background()); err == nil {
		t.Fatal("expected nil manager TriggerAVUpdate error")
	}
}

func TestCanonicalServicesFromKind(t *testing.T) {
	t.Parallel()

	cases := []struct {
		kind    string
		services []string
		isErr   bool
	}{
		{kind: "service.envoy.requests", services: []string{"proxy", "envoy"}, isErr: false},
		{kind: "service.envoy.error", services: []string{"proxy", "envoy"}, isErr: true},
		{kind: "service.nginx.fail", services: []string{"proxy", "nginx"}, isErr: true},
		{kind: "service.openvpn.applied", services: []string{"vpn"}, isErr: false},
		{kind: "invalid", services: nil, isErr: false},
	}
	for _, tc := range cases {
		got, isErr := canonicalServicesFromKind(tc.kind)
		if len(got) != len(tc.services) {
			t.Fatalf("%s services len = %d, want %d", tc.kind, len(got), len(tc.services))
		}
		for i := range got {
			if got[i] != tc.services[i] {
				t.Fatalf("%s services[%d] = %q, want %q", tc.kind, i, got[i], tc.services[i])
			}
		}
		if isErr != tc.isErr {
			t.Fatalf("%s isErr = %v, want %v", tc.kind, isErr, tc.isErr)
		}
	}
}

func TestServiceCurrentAndStatusHelpers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)

	dnsMgr := NewDNSManager(dir)
	dnsMgr.lastCfg = config.DNSConfig{Enabled: true, UpstreamServers: []string{"1.1.1.1"}}
	dnsMgr.lastRender = now
	dnsMgr.lastError = "dns-error"
	dnsStatus := dnsMgr.Status()
	if !dnsMgr.Current().Enabled || dnsStatus["configured_upstreams"] != 1 {
		t.Fatalf("unexpected dns status: %#v", dnsStatus)
	}

	ntpMgr := NewNTPManager(dir)
	ntpMgr.lastCfg = config.NTPConfig{Enabled: true, Servers: []string{"time.example"}, IntervalSeconds: 60}
	ntpMgr.lastRender = now
	ntpMgr.lastError = "ntp-error"
	ntpStatus := ntpMgr.Status()
	if !ntpMgr.Current().Enabled || ntpStatus["servers_count"] != 1 {
		t.Fatalf("unexpected ntp status: %#v", ntpStatus)
	}

	dhcpMgr := NewDHCPManager(dir)
	dhcpMgr.lastCfg = config.DHCPConfig{
		Enabled:      true,
		ListenIfaces: []string{"lan1"},
		Pools:        []config.DHCPPool{{Iface: "lan1", Start: "192.168.1.10", End: "192.168.1.20"}},
	}
	dhcpMgr.lastRender = now
	dhcpMgr.lastError = "dhcp-error"
	dhcpStatus := dhcpMgr.Status()
	if !dhcpMgr.Current().Enabled || dhcpStatus["listen_ifaces"] != 1 || dhcpStatus["pools"] != 1 {
		t.Fatalf("unexpected dhcp status: %#v", dhcpStatus)
	}
	metricsSeen := map[string]int{}
	dhcpMgr.SetMetricEmitter(func(service string, delta int) { metricsSeen[service] += delta })
	dhcpMgr.IncrementLeaseMetric(2, false)
	dhcpMgr.IncrementLeaseMetric(1, true)
	if metricsSeen["dhcp"] != 2 || metricsSeen["dhcp_error"] != 1 {
		t.Fatalf("unexpected dhcp metrics: %#v", metricsSeen)
	}

	syslogMgr := NewSyslogManager()
	syslogMgr.config = config.SyslogConfig{Forwarders: []config.SyslogForwarder{{Address: "192.0.2.1", Port: 514, Proto: "tcp"}}}
	syslogMgr.sentTotal = 4
	syslogMgr.failTotal = 1
	syslogMgr.lastFlush = now
	syslogMgr.batchSize = 50
	syslogMgr.flushEvery = 2 * time.Second
	syslogStatus := syslogMgr.Status()
	if syslogMgr.Current().Forwarders[0].Proto != "tcp" || syslogStatus["configured_forwarders"] != 1 {
		t.Fatalf("unexpected syslog status: %#v", syslogStatus)
	}
	if err := ValidateSyslogForwarder(config.SyslogForwarder{Address: "", Port: 514}); err == nil {
		t.Fatal("expected missing address validation error")
	}
	if err := ValidateSyslogForwarder(config.SyslogForwarder{Address: "host.example", Port: 514, Proto: "tcp"}); err != nil {
		t.Fatalf("unexpected syslog forwarder validation error: %v", err)
	}

	proxyMgr := NewProxyManager(ProxyOptions{BaseDir: dir, Supervise: false})
	proxyMgr.lastCfg = config.ProxyConfig{
		Forward: config.ForwardProxyConfig{Enabled: true},
		Reverse: config.ReverseProxyConfig{Enabled: true},
	}
	proxyMgr.lastRender = now
	proxyStatus := proxyMgr.Status()
	if proxyStatus["forward_enabled"] != true {
		t.Fatalf("unexpected proxy status: %#v", proxyStatus)
	}
	rendered, ok := proxyStatus["rendered_files"].([]string)
	if !ok || len(rendered) != 2 {
		t.Fatalf("unexpected rendered_files: %#v", proxyStatus["rendered_files"])
	}
	proxyMgr.RecordForwardRequests(2, 1)
	proxyMgr.RecordReverseRequests(3, 0)

	vpnMgr := NewVPNManager(dir)
	vpnMgr.lastCfg = config.VPNConfig{
		WireGuard: config.WireGuardConfig{Enabled: true, Peers: []config.WGPeer{{PublicKey: "key"}}},
		OpenVPN:   config.OpenVPNConfig{Enabled: true, ConfigPath: filepath.Join(dir, "client.ovpn")},
	}
	vpnMgr.lastRender = now
	vpnStatus := vpnMgr.Status()
	if !vpnMgr.Current().WireGuard.Enabled || vpnStatus["wg_peers"] != 1 {
		t.Fatalf("unexpected vpn status: %#v", vpnStatus)
	}
}
