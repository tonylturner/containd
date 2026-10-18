// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"bytes"
	"fmt"
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
	configured := []config.Interface{
		{Name: "wan", Device: "eth0", Zone: "outside"},
		{Name: "lan1", Device: "eth1", Zone: "inside"},
		{Name: "lan2", Device: "eth2", Zone: "inside"},
		{Name: "lan3", Zone: "inside"},
		{Name: "lan4", Device: "missing", Zone: "inside"},
		{Name: "eth3", Zone: "inside"},
		{Name: "lan5", Device: "eth1", Zone: "inside"},
	}
	got, err := resolvePCAPConfig(config.PCAPConfig{
		Interfaces: []string{"wan", "eth4", "lan1"},
		Zones:      []string{"inside", "inside"},
		Filter:     config.PCAPFilter{Port: "502"},
	}, configured, pcapTestInterfaceByName)
	if err != nil {
		t.Fatalf("resolve logical, kernel and zone selections: %v", err)
	}
	want := []string{"eth0", "eth4", "eth1", "eth2", "eth3"}
	if !reflect.DeepEqual(got.Interfaces, want) {
		t.Fatalf("resolved interfaces = %#v, want %#v", got.Interfaces, want)
	}
	if got.Zones != nil {
		t.Fatalf("resolved config retained zone selectors: %#v", got.Zones)
	}
	if got.Filter.Port != "502" {
		t.Fatalf("resolved config lost capture filter: %#v", got.Filter)
	}
}

func pcapTestInterfaceByName(name string) (*net.Interface, error) {
	switch name {
	case "eth0", "eth1", "eth2", "eth3", "eth4":
		return &net.Interface{Name: name}, nil
	default:
		return nil, fmt.Errorf("no such network interface %q", name)
	}
}

func TestResolvePCAPConfigRejectsUnknownSelection(t *testing.T) {
	configured := []config.Interface{
		{Name: "lan2", Zone: "lan"},
		{Name: "lan3", Device: "missing", Zone: "lan"},
		{Name: "eth0", Device: "missing", Zone: "outside"},
	}
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
			name: "zone without existing devices",
			cfg:  config.PCAPConfig{Interfaces: []string{"eth1"}, Zones: []string{"lan"}},
			want: `pcap zone "lan" has no kernel devices ("lan2", "lan3" unbound)`,
		},
		{
			name: "unbound logical interface",
			cfg:  config.PCAPConfig{Interfaces: []string{"lan2"}},
			want: `pcap interface "lan2" has no existing kernel device "lan2"`,
		},
		{
			name: "missing configured device",
			cfg:  config.PCAPConfig{Interfaces: []string{"lan3"}},
			want: `pcap interface "lan3" has no existing kernel device "missing"`,
		},
		{
			name: "device setting takes precedence over existing name",
			cfg:  config.PCAPConfig{Interfaces: []string{"eth0"}},
			want: `pcap interface "eth0" has no existing kernel device "missing"`,
		},
		{
			name: "empty selection",
			cfg:  config.PCAPConfig{},
			want: "pcap requires at least one interface or zone",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := resolvePCAPConfig(test.cfg, configured, pcapTestInterfaceByName)
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
