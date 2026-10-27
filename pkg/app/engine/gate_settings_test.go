// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/httpgate"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestGateSettingsDefaults(t *testing.T) {
	set := gateSettings(rules.GateSelection{}, config.AVConfig{})
	if set.FailPolicy != avscan.FailOpen || set.DownloadMode != httpgate.DownloadHold {
		t.Fatalf("defaults: policy %q mode %q", set.FailPolicy, set.DownloadMode)
	}
	if set.ScanUploads || set.ScanDownloads {
		t.Fatal("directions selected without configuration")
	}
	if set.MaxObjectBytes != gateDefaultMaxObjectBytes || set.MemoryThreshold != gateMemoryThreshold {
		t.Fatalf("size bounds %d/%d", set.MaxObjectBytes, set.MemoryThreshold)
	}
	if set.ScanTimeout != max(gateScanTimeoutPerUnit*gateDefaultBackendTimeout, gateMinScanTimeout) {
		t.Fatalf("scan timeout %s", set.ScanTimeout)
	}
	if !set.ICSBypass || set.IsICS != nil {
		t.Fatal("ICS bypass must be on with no ICS endpoints marked")
	}
	srv := &httpgate.Server{}
	if err := srv.Update(set); err != nil {
		t.Fatalf("default settings rejected: %v", err)
	}
}

func TestGateSettingsFromConfiguration(t *testing.T) {
	av := config.AVConfig{
		Enabled: true, FailPolicy: "Closed", MaxSizeBytes: 1 << 20, TimeoutSec: 30,
		HTTPDownload: true, HTTPUpload: true,
		Scan: config.ScanSelection{DownloadMode: "stream_tail"},
	}
	gate := rules.GateSelection{Enabled: true, ICSCIDRs: []string{"10.10.0.0/16", "fd00:1::/64", "not a cidr"}}
	set := gateSettings(gate, av)
	if set.FailPolicy != avscan.FailClosed || set.DownloadMode != httpgate.DownloadStreamTail {
		t.Fatalf("policy %q mode %q", set.FailPolicy, set.DownloadMode)
	}
	if !set.ScanUploads || !set.ScanDownloads {
		t.Fatal("directions not taken from the configuration")
	}
	if set.MaxObjectBytes != 1<<20 || set.MemoryThreshold != 1<<20 {
		t.Fatalf("size bounds %d/%d", set.MaxObjectBytes, set.MemoryThreshold)
	}
	if set.ScanTimeout != 300*time.Second {
		t.Fatalf("scan timeout %s", set.ScanTimeout)
	}
	ics := set.IsICS
	if ics == nil {
		t.Fatal("ICS endpoints not matched")
	}
	cases := map[string]struct {
		client, server string
		want           bool
	}{
		"client in ics zone":     {"10.10.3.4", "192.0.2.1", true},
		"server in ics zone":     {"192.0.2.1", "10.10.3.4", true},
		"ipv6 asset":             {"fd00:1::9", "2001:db8::1", true},
		"neither":                {"192.0.2.1", "198.51.100.1", false},
		"mapped client in zone":  {"::ffff:10.10.0.1", "192.0.2.1", true},
		"adjacent prefix misses": {"10.11.0.1", "192.0.2.1", false},
	}
	for name, tc := range cases {
		if got := ics(netip.MustParseAddr(tc.client), netip.MustParseAddr(tc.server)); got != tc.want {
			t.Errorf("%s: IsICS = %v, want %v", name, got, tc.want)
		}
	}
	if err := (&httpgate.Server{}).Update(set); err != nil {
		t.Fatalf("settings rejected: %v", err)
	}
}

func TestGateEventMapping(t *testing.T) {
	client := netip.MustParseAddrPort("10.0.0.5:40000")
	server := netip.MustParseAddrPort("192.0.2.80:80")
	original := netip.MustParseAddrPort("198.51.100.1:18000")
	at := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	infected := gateEvent(httpgate.Event{
		Time: at, ID: "tx-1", Direction: avscan.Download, Client: client, Server: server, ICS: true,
		Method: "GET", Host: "files.example", Target: "/a.bin", Status: 200, Size: 1234, SHA256: "abc",
		Verdict: avscan.Infected, Signature: "Eicar-Test-Signature", Backend: "clamav", Action: avscan.Block, Duration: 1500 * time.Millisecond,
	}, original)
	if infected.Kind != gateEventDetected || infected.Proto != "av" || infected.Transport != "tcp" {
		t.Fatalf("detection event %+v", infected)
	}
	if infected.SrcIP != "10.0.0.5" || infected.DstIP != "192.0.2.80" || infected.SrcPort != 40000 || infected.DstPort != 80 || infected.Hash != "abc" {
		t.Fatalf("endpoints %+v", infected)
	}
	want := map[string]any{
		"client": "10.0.0.5:40000", "server": "192.0.2.80:80", "original_destination": "198.51.100.1:18000",
		"transaction": "tx-1", "direction": "download", "verdict": "infected", "action": "block", "backend": "clamav",
		"size": int64(1234), "duration_ms": int64(1500), "signature": "Eicar-Test-Signature", "method": "GET",
		"host": "files.example", "target": "/a.bin", "status": 200, "ics": true,
	}
	for k, v := range want {
		if infected.Attributes[k] != v {
			t.Errorf("%s = %#v, want %#v", k, infected.Attributes[k], v)
		}
	}
	for _, k := range []string{"reason", "detail", "sha256_partial", "streamed", "error"} {
		if _, ok := infected.Attributes[k]; ok {
			t.Errorf("%s set on a detection without it", k)
		}
	}
	if !infected.Timestamp.Equal(at) {
		t.Fatalf("timestamp %s", infected.Timestamp)
	}

	unscanned := gateEvent(httpgate.Event{Client: client, Server: server, Verdict: avscan.Unscanned, Reason: avscan.ReasonNotReady, Backend: "clamav", Detail: "starting", Action: avscan.PassUnscanned, Streamed: 10, SHA256Partial: true}, netip.AddrPort{})
	if unscanned.Kind != gateEventScanned || unscanned.Attributes["reason"] != "not_ready" || unscanned.Attributes["streamed"] != int64(10) || unscanned.Attributes["sha256_partial"] != true {
		t.Fatalf("unscanned event %+v", unscanned)
	}
	if _, ok := unscanned.Attributes["original_destination"]; ok {
		t.Fatal("unknown original destination reported")
	}
	if unscanned.Timestamp.IsZero() {
		t.Fatal("zero time not filled")
	}

	conn := gateEvent(httpgate.Event{Client: client, Error: "upstream dial: refused"}, netip.AddrPort{})
	if conn.Kind != gateEventConnection || conn.Attributes["error"] != "upstream dial: refused" || conn.DstIP != "" {
		t.Fatalf("connection event %+v", conn)
	}
	if _, ok := conn.Attributes["verdict"]; ok {
		t.Fatal("connection event carries a verdict")
	}
}
