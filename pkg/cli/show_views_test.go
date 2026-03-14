// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/anomaly"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/inventory"
	"github.com/tonylturner/containd/pkg/dp/signatures"
	"github.com/tonylturner/containd/pkg/dp/stats"
)

func TestShowConfigAuthAuditAndProxyViews(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	client := &dispatchHTTPClient{
		t: t,
		handlers: map[string]func(*http.Request) (*http.Response, error){
			"GET /api/v1/config": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, config.Config{
					System: config.SystemConfig{Hostname: "containd-lab"},
					Zones:  []config.Zone{{Name: "lan"}},
				}, nil), nil
			},
			"GET /api/v1/auth/session": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, map[string]any{
					"authenticated": true,
					"expiresAt":     now,
					"user": map[string]any{
						"id":       "u1",
						"username": "student",
						"role":     "admin",
					},
				}, nil), nil
			},
			"GET /api/v1/audit": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, []audit.Record{
					{
						ID:        7,
						Timestamp: now,
						Actor:     "student",
						Source:    "ui",
						Action:    "config.commit",
						Target:    "running",
						Result:    "success",
						Detail:    "applied changes",
					},
				}, nil), nil
			},
			"GET /api/v1/dataplane": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, config.DataPlaneConfig{
					CaptureInterfaces: []string{"wan", "lan1"},
					Enforcement:       true,
					EnforceTable:      "containd",
					DPIMock:           false,
				}, nil), nil
			},
			"GET /api/v1/services/proxy/forward": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, config.ForwardProxyConfig{
					Enabled:        true,
					ListenPort:     3128,
					ListenZones:    []string{"wan"},
					AllowedClients: []string{"hmi"},
					AllowedDomains: []string{"example.com"},
					Upstream:       "http://proxy.local:8080",
					LogRequests:    true,
				}, nil), nil
			},
			"GET /api/v1/services/proxy/reverse": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, config.ReverseProxyConfig{
					Enabled: true,
					Sites: []config.ReverseProxySite{
						{
							Name:       "hist",
							ListenPort: 8443,
							Hostnames:  []string{"hist.local"},
							Backends:   []string{"10.0.0.5:443"},
							TLSEnabled: true,
						},
					},
				}, nil), nil
			},
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	ctx := context.Background()

	var cfg bytes.Buffer
	if err := showConfig(api)(ctx, &cfg, nil); err != nil {
		t.Fatalf("showConfig: %v", err)
	}
	if !strings.Contains(cfg.String(), `"hostname": "containd-lab"`) {
		t.Fatalf("unexpected config output: %q", cfg.String())
	}

	var auth bytes.Buffer
	if err := showAuth(api)(ctx, &auth, nil); err != nil {
		t.Fatalf("showAuth: %v", err)
	}
	if !strings.Contains(auth.String(), "student") || !strings.Contains(auth.String(), "user.role") {
		t.Fatalf("unexpected auth output: %q", auth.String())
	}

	var auditOut bytes.Buffer
	if err := showAudit(api)(ctx, &auditOut, nil); err != nil {
		t.Fatalf("showAudit: %v", err)
	}
	if !strings.Contains(auditOut.String(), "config.commit") || !strings.Contains(auditOut.String(), "student") {
		t.Fatalf("unexpected audit output: %q", auditOut.String())
	}

	var dp bytes.Buffer
	if err := showDataPlane(api)(ctx, &dp, nil); err != nil {
		t.Fatalf("showDataPlane: %v", err)
	}
	if !strings.Contains(dp.String(), "wan,lan1") || !strings.Contains(dp.String(), "yes") {
		t.Fatalf("unexpected dataplane output: %q", dp.String())
	}

	var fp bytes.Buffer
	if err := showForwardProxy(api)(ctx, &fp, nil); err != nil {
		t.Fatalf("showForwardProxy: %v", err)
	}
	if !strings.Contains(fp.String(), "example.com") || !strings.Contains(fp.String(), "proxy.local:8080") {
		t.Fatalf("unexpected forward proxy output: %q", fp.String())
	}

	var rp bytes.Buffer
	if err := showReverseProxy(api)(ctx, &rp, nil); err != nil {
		t.Fatalf("showReverseProxy: %v", err)
	}
	if !strings.Contains(rp.String(), "hist") || !strings.Contains(rp.String(), "8443") {
		t.Fatalf("unexpected reverse proxy output: %q", rp.String())
	}
}

func TestShowTelemetryViews(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 13, 13, 0, 0, 0, time.UTC)
	client := &dispatchHTTPClient{
		t: t,
		handlers: map[string]func(*http.Request) (*http.Response, error){
			"GET /api/v1/flows": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, []dpevents.FlowSummary{
					{
						FlowID:      "flow-1",
						FirstSeen:   now.Add(-time.Minute),
						LastSeen:    now,
						SrcIP:       "10.0.0.10",
						DstIP:       "10.0.0.20",
						SrcPort:     12345,
						DstPort:     502,
						Transport:   "tcp",
						Application: "modbus",
						EventCount:  5,
					},
				}, nil), nil
			},
			"GET /api/v1/events": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, []dpevents.Event{
					{
						ID:        1,
						FlowID:    "flow-1",
						Proto:     "modbus",
						Kind:      "modbus.read",
						Attributes: map[string]any{"unit_id": float64(1), "function_code": float64(3)},
						Timestamp: now,
						SrcIP:     "10.0.0.10",
						DstIP:     "10.0.0.20",
						SrcPort:   12345,
						DstPort:   502,
					},
				}, nil), nil
			},
			"GET /api/v1/stats/protocols": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, []stats.ProtoStats{
					{
						Protocol:    "modbus",
						PacketCount: 12,
						ByteCount:   640,
						EventCount:  5,
						ReadCount:   4,
						WriteCount:  1,
						AlertCount:  0,
						LastSeen:    now,
					},
				}, nil), nil
			},
			"GET /api/v1/stats/top-talkers": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, []stats.FlowStats{
					{
						SrcIP:    "10.0.0.10",
						DstIP:    "10.0.0.20",
						Protocol: "modbus",
						Packets:  12,
						Bytes:    640,
					},
				}, nil), nil
			},
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	ctx := context.Background()

	var flows bytes.Buffer
	if err := showFlows(api)(ctx, &flows, nil); err != nil {
		t.Fatalf("showFlows: %v", err)
	}
	if !strings.Contains(flows.String(), "flow-1") || !strings.Contains(flows.String(), "modbus") {
		t.Fatalf("unexpected flows output: %q", flows.String())
	}

	var events bytes.Buffer
	if err := showEvents(api)(ctx, &events, nil); err != nil {
		t.Fatalf("showEvents: %v", err)
	}
	if !strings.Contains(events.String(), "modbus.read") || !strings.Contains(events.String(), "function_code=3") {
		t.Fatalf("unexpected events output: %q", events.String())
	}

	var protocols bytes.Buffer
	if err := showStatsProtocols(api)(ctx, &protocols, nil); err != nil {
		t.Fatalf("showStatsProtocols: %v", err)
	}
	if !strings.Contains(protocols.String(), "modbus") || !strings.Contains(protocols.String(), "640") {
		t.Fatalf("unexpected protocol stats output: %q", protocols.String())
	}

	var talkers bytes.Buffer
	if err := showStatsTopTalkers(api)(ctx, &talkers, []string{"5"}); err != nil {
		t.Fatalf("showStatsTopTalkers: %v", err)
	}
	if !strings.Contains(talkers.String(), "10.0.0.10") || !strings.Contains(talkers.String(), "640") {
		t.Fatalf("unexpected top talkers output: %q", talkers.String())
	}
}

func TestShowSecurityAndInventoryViews(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 13, 14, 0, 0, 0, time.UTC)
	client := &dispatchHTTPClient{
		t: t,
		handlers: map[string]func(*http.Request) (*http.Response, error){
			"GET /api/v1/signatures": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, []signatures.Signature{
					{
						ID:         "sig-1",
						Name:       "Modbus write outside maintenance",
						Severity:   "high",
						Protocol:   "modbus",
						Conditions: []signatures.Condition{{Field: "is_write", Op: "equals", Value: true}},
						References: []string{"https://example.com/sig-1"},
					},
				}, nil), nil
			},
			"GET /api/v1/signatures/matches": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, []signatures.Match{
					{
						Timestamp: now,
						Signature: signatures.Signature{ID: "sig-1", Name: "Modbus write outside maintenance", Severity: "high"},
						Event:     dpi.Event{Proto: "modbus", Kind: "modbus.write"},
					},
				}, nil), nil
			},
			"GET /api/v1/anomalies": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, []anomaly.Anomaly{
					{
						Type:      "protocol_violation",
						Protocol:  "modbus",
						Severity:  "high",
						Message:   "unexpected write burst",
						SourceIP:  "10.0.0.10",
						DestIP:    "10.0.0.20",
						Timestamp: now,
					},
				}, nil), nil
			},
			"GET /api/v1/inventory": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, []inventory.DiscoveredAsset{
					{
						IP:            "10.0.0.20",
						Protocol:      "modbus",
						Role:          "slave",
						UnitIDs:       []uint8{1, 2},
						FunctionCodes: []uint8{3, 16},
						FirstSeen:     now.Add(-time.Hour),
						LastSeen:      now,
						PacketCount:   12,
						Peers:         []string{"10.0.0.10"},
					},
				}, nil), nil
			},
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}
	ctx := context.Background()

	var sigs bytes.Buffer
	if err := showSignaturesAPI(api)(ctx, &sigs, nil); err != nil {
		t.Fatalf("showSignaturesAPI: %v", err)
	}
	if !strings.Contains(sigs.String(), "sig-1") || !strings.Contains(sigs.String(), "high") {
		t.Fatalf("unexpected signatures output: %q", sigs.String())
	}

	var matches bytes.Buffer
	if err := showSignatureMatchesAPI(api)(ctx, &matches, nil); err != nil {
		t.Fatalf("showSignatureMatchesAPI: %v", err)
	}
	if !strings.Contains(matches.String(), "modbus.write") || !strings.Contains(matches.String(), "sig-1") {
		t.Fatalf("unexpected signature matches output: %q", matches.String())
	}

	var anomalies bytes.Buffer
	if err := showAnomalies(api)(ctx, &anomalies, nil); err != nil {
		t.Fatalf("showAnomalies: %v", err)
	}
	if !strings.Contains(anomalies.String(), "protocol_violation") || !strings.Contains(anomalies.String(), "unexpected write burst") {
		t.Fatalf("unexpected anomalies output: %q", anomalies.String())
	}

	var inv bytes.Buffer
	if err := showInventoryAPI(api)(ctx, &inv, nil); err != nil {
		t.Fatalf("showInventoryAPI: %v", err)
	}
	if !strings.Contains(inv.String(), "10.0.0.20") || !strings.Contains(inv.String(), "1,2") || !strings.Contains(inv.String(), "3,16") {
		t.Fatalf("unexpected inventory output: %q", inv.String())
	}
}

func TestNumericSliceFormattingHelpers(t *testing.T) {
	t.Parallel()

	if got := fmtUint8Slice(nil); got != "—" {
		t.Fatalf("expected empty uint8 slice marker, got %q", got)
	}
	if got := fmtUint16Slice(nil); got != "—" {
		t.Fatalf("expected empty uint16 slice marker, got %q", got)
	}
	if got := fmtUint8Slice([]uint8{1, 5, 7}); got != "1,5,7" {
		t.Fatalf("unexpected uint8 formatting: %q", got)
	}
	if got := fmtUint16Slice([]uint16{200, 201}); got != "200,201" {
		t.Fatalf("unexpected uint16 formatting: %q", got)
	}
}
