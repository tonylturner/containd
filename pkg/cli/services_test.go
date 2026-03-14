// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestShowServicesStatusUnavailable(t *testing.T) {
	t.Parallel()

	client := &mockHTTPClient{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"status":"unavailable"}`)),
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}

	var buf bytes.Buffer
	if err := showServicesStatus(api)(context.Background(), &buf, nil); err != nil {
		t.Fatalf("showServicesStatus: %v", err)
	}
	if !strings.Contains(buf.String(), "services status: unavailable") {
		t.Fatalf("unexpected services status output: %q", buf.String())
	}
}

func TestShowServicesStatusDetailedTable(t *testing.T) {
	t.Parallel()

	body := bytes.NewBufferString(`{
	  "syslog": {"configured_forwarders": 2, "format": "json", "protos": "tcp"},
	  "proxy": {
	    "forward_enabled": "true",
	    "reverse_enabled": true,
	    "envoy_running": true,
	    "nginx_running": false,
	    "envoy_path": "/usr/bin/envoy"
	  },
	  "dns": {"enabled": "yes", "configured_upstreams": 3, "listen_port": 53},
	  "ntp": {"enabled": true, "servers_count": 2},
	  "clamav": {"enabled": true}
	}`)
	client := &mockHTTPClient{
		resp: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(body),
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}

	var buf bytes.Buffer
	if err := showServicesStatus(api)(context.Background(), &buf, nil); err != nil {
		t.Fatalf("showServicesStatus: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"SERVICE",
		"syslog",
		"forwarders=2 format=json proto=tcp",
		"envoy-forward",
		"path=/usr/bin/envoy",
		"nginx-reverse",
		"dns",
		"port=53 upstreams=3",
		"ntp",
		"servers=2",
		"clamav",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in services output: %q", want, out)
		}
	}
}

func TestShowSyslogConfigEmptyForwardersAndDefaultProto(t *testing.T) {
	t.Parallel()

	client := &dispatchHTTPClient{
		t: t,
		handlers: map[string]func(*http.Request) (*http.Response, error){
			"GET /api/v1/services/syslog": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, map[string]any{
					"format":     "rfc5424",
					"forwarders": []map[string]any{},
				}, nil), nil
			},
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}

	var empty bytes.Buffer
	if err := showSyslogConfig(api)(context.Background(), &empty, nil); err != nil {
		t.Fatalf("showSyslogConfig(empty): %v", err)
	}
	if !strings.Contains(empty.String(), "forwarders: (none)") {
		t.Fatalf("unexpected empty syslog config output: %q", empty.String())
	}

	client.handlers["GET /api/v1/services/syslog"] = func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, map[string]any{
			"format": "json",
			"forwarders": []map[string]any{
				{"address": "192.0.2.9", "port": 514},
			},
		}, nil), nil
	}

	var withDefaultProto bytes.Buffer
	if err := showSyslogConfig(api)(context.Background(), &withDefaultProto, nil); err != nil {
		t.Fatalf("showSyslogConfig(default proto): %v", err)
	}
	if !strings.Contains(withDefaultProto.String(), "192.0.2.9:514 proto=udp") {
		t.Fatalf("unexpected syslog config output: %q", withDefaultProto.String())
	}
}

func TestShowDHCPConfigAndLeases(t *testing.T) {
	t.Parallel()

	client := &dispatchHTTPClient{
		t: t,
		handlers: map[string]func(*http.Request) (*http.Response, error){
			"GET /api/v1/services/dhcp": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, map[string]any{
					"enabled":      true,
					"listenIfaces": "lan1,lan2",
					"pools": []map[string]any{
						{"iface": "lan1", "start": "10.0.0.10", "end": "10.0.0.99"},
					},
					"reservations": []map[string]any{
						{"iface": "lan1", "mac": "AA:BB:CC:DD:EE:FF", "ip": "10.0.0.20"},
					},
				}, nil), nil
			},
			"GET /api/v1/dhcp/leases": func(req *http.Request) (*http.Response, error) {
				return jsonHTTPResponse(http.StatusOK, map[string]any{
					"leases": []map[string]any{
						{
							"iface":     "lan1",
							"mac":       "aa:bb:cc:dd:ee:ff",
							"ip":        "10.0.0.20",
							"expiresAt": "2026-03-13T18:00:00Z",
							"hostname":  "student-plc",
						},
					},
				}, nil), nil
			},
		},
	}
	api := &API{BaseURL: "http://localhost:8080", Client: client}

	var cfg bytes.Buffer
	if err := showDHCPConfig(api)(context.Background(), &cfg, nil); err != nil {
		t.Fatalf("showDHCPConfig: %v", err)
	}
	cfgOut := cfg.String()
	for _, want := range []string{
		"DHCP configuration",
		"enabled: true",
		"listenIfaces: lan1,lan2",
		"1) lan1 10.0.0.10-10.0.0.99",
		"1) lan1 aa:bb:cc:dd:ee:ff -> 10.0.0.20",
	} {
		if !strings.Contains(cfgOut, want) {
			t.Fatalf("missing %q in DHCP config output: %q", want, cfgOut)
		}
	}

	var leases bytes.Buffer
	if err := showDHCPLeases(api)(context.Background(), &leases, nil); err != nil {
		t.Fatalf("showDHCPLeases: %v", err)
	}
	if !strings.Contains(leases.String(), "student-plc") || !strings.Contains(leases.String(), "10.0.0.20") {
		t.Fatalf("unexpected DHCP leases output: %q", leases.String())
	}

	client.handlers["GET /api/v1/dhcp/leases"] = func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusOK, map[string]any{"leases": []map[string]any{}}, nil), nil
	}

	var empty bytes.Buffer
	if err := showDHCPLeases(api)(context.Background(), &empty, nil); err != nil {
		t.Fatalf("showDHCPLeases(empty): %v", err)
	}
	if !strings.Contains(empty.String(), "No leases.") {
		t.Fatalf("unexpected empty DHCP leases output: %q", empty.String())
	}
}

func TestServiceFormattingHelpers(t *testing.T) {
	t.Parallel()

	if !boolAny("1") || !boolAny("true") || !boolAny("yes") {
		t.Fatal("expected truthy string values to be accepted")
	}
	if boolAny("no") || boolAny(123) {
		t.Fatal("expected non-bool, non-truthy values to be false")
	}
	if got := pathDetail("/usr/bin/envoy"); got != "path=/usr/bin/envoy" {
		t.Fatalf("unexpected pathDetail: %q", got)
	}
	if got := pathDetail(nil); got != "" {
		t.Fatalf("expected empty path detail, got %q", got)
	}
}
