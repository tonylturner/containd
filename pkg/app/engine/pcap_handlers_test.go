// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/pcap"
)

func TestResolvePCAPConfig(t *testing.T) {
	var physical string
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list kernel interfaces: %v", err)
	}
	if len(ifaces) == 0 {
		t.Fatal("need a kernel interface for resolver test")
	}
	physical = ifaces[0].Name

	configured := []config.Interface{
		{Name: "wan", Device: "eth0", Zone: "outside"},
		{Name: "lan1", Device: "eth1", Zone: "inside"},
		{Name: "lan2", Device: "eth2", Zone: "inside"},
	}
	got, err := resolvePCAPConfig(config.PCAPConfig{
		Interfaces: []string{"wan", physical},
		Zones:      []string{"inside"},
	}, configured)
	if err != nil {
		t.Fatalf("resolve logical, kernel and zone selections: %v", err)
	}
	want := []string{"eth0", physical, "eth1", "eth2"}
	if !reflect.DeepEqual(got.Interfaces, want) {
		t.Fatalf("resolved interfaces = %#v, want %#v", got.Interfaces, want)
	}
	if got.Zones != nil {
		t.Fatalf("resolved config retained zone selectors: %#v", got.Zones)
	}
}

func TestResolvePCAPConfigRejectsUnknownSelection(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.PCAPConfig
		want string
	}{
		{
			name: "unknown interface",
			cfg:  config.PCAPConfig{Interfaces: []string{"missing-logical-or-device"}},
			want: `pcap interface "missing-logical-or-device"`,
		},
		{
			name: "zone without interfaces",
			cfg:  config.PCAPConfig{Zones: []string{"empty-zone"}},
			want: `pcap zone "empty-zone" has no configured interfaces`,
		},
		{
			name: "empty selection",
			cfg:  config.PCAPConfig{},
			want: "pcap requires at least one interface or zone",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := resolvePCAPConfig(test.cfg, nil)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("resolvePCAPConfig error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestPCAPStartHandlerReturnsNamedResolutionError(t *testing.T) {
	mgr := pcap.NewManager(t.TempDir())
	ownership := newOwnershipManager(zap.NewNop().Sugar())
	ownership.setInterfaces([]config.Interface{{Name: "wan", Device: "eth0", Zone: "outside"}})
	req := httptest.NewRequest(http.MethodPost, "/internal/pcap/start", bytes.NewBufferString(
		`{"enabled":true,"zones":["ghost"]}`,
	))
	rec := httptest.NewRecorder()

	pcapStartHandler(mgr, ownership).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("pcap start status = %d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ghost") {
		t.Fatalf("pcap start error did not name requested zone: %s", rec.Body.String())
	}
}
