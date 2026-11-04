// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"unsafe"

	"github.com/tonylturner/containd/pkg/cp/config"
	"golang.org/x/sys/unix"
)

func TestRuleOwnershipIsProtocolNotPriority(t *testing.T) {
	for _, priority := range []uint32{1, 100, 10000, 15000, 19999, 40000, 65535} {
		for _, protocol := range []uint8{0, unix.RTPROT_STATIC, routeProtoContaind} {
			var data bytes.Buffer
			_ = binary.Write(&data, binary.NativeEndian, fibRuleHdr{Family: unix.AF_INET, Table: 201, Action: frActToTbl})
			p := make([]byte, 4)
			binary.NativeEndian.PutUint32(p, priority)
			addRtAttr(&data, fraPriority, p)
			addRtAttr(&data, fraProtocol, []byte{protocol})
			r, ok := decodeKernelRule(data.Bytes(), int(unsafe.Sizeof(fibRuleHdr{})))
			if !ok || (r.proto == routeProtoContaind) != (protocol == routeProtoContaind) {
				t.Fatalf("priority %d protocol %d ownership=%v", priority, protocol, ok)
			}
			if ok && (r.priority != priority || r.proto != protocol) {
				t.Fatalf("decoded %+v", r)
			}
		}
	}
}

func TestRouteIntentRetainsKernelResolvedInterface(t *testing.T) {
	want := kernelRoute{dst: net.ParseIP("198.18.2.0"), dstLen: 24, gateway: net.ParseIP("198.18.0.2"), table: 254, proto: routeProtoContaind}
	got := want
	got.ifIndex = 42
	if !routeMatchesIntent(got, want) {
		t.Fatal("gateway-only route must retain kernel-selected OIF")
	}
	want.ifIndex = 43
	if routeMatchesIntent(got, want) {
		t.Fatal("explicit interface change must not match")
	}
}

func TestResolveRouteDefersMissingInterfaceAndRejectsInvalidIntent(t *testing.T) {
	indexes := map[string]int{"attached0": 7}
	gateways := map[string]config.Gateway{
		"late-gw": {Name: "late-gw", Address: "198.18.0.1", Iface: "missing0"},
	}
	tests := []struct {
		name          string
		route         config.StaticRoute
		wantDeferred  string
		wantIndex     int
		wantErrorPart string
	}{
		{
			name:         "missing explicit interface",
			route:        config.StaticRoute{Dst: "198.19.1.0/24", Iface: "missing0"},
			wantDeferred: "missing0",
		},
		{
			name:      "attached explicit interface",
			route:     config.StaticRoute{Dst: "198.19.2.0/24", Iface: "attached0"},
			wantIndex: 7,
		},
		{
			name:         "missing named gateway interface",
			route:        config.StaticRoute{Dst: "198.19.3.0/24", Gateway: "late-gw"},
			wantDeferred: "missing0",
		},
		{
			name:  "gateway only",
			route: config.StaticRoute{Dst: "198.19.4.0/24", Gateway: "198.18.0.2"},
		},
		{
			name:          "invalid destination still errors",
			route:         config.StaticRoute{Dst: "not-a-network", Iface: "missing0"},
			wantErrorPart: "route dst invalid",
		},
		{
			name:          "invalid table still errors",
			route:         config.StaticRoute{Dst: "198.19.5.0/24", Iface: "missing0", Table: 253},
			wantErrorPart: "invalid route table or metric",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, deferred, err := resolveRoute(tc.route, gateways, indexes)
			if tc.wantErrorPart != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrorPart) {
					t.Fatalf("resolveRoute() error = %v, want containing %q", err, tc.wantErrorPart)
				}
				if deferred != "" {
					t.Fatalf("invalid route was deferred as %q", deferred)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if deferred != tc.wantDeferred || got.ifIndex != tc.wantIndex {
				t.Fatalf("resolveRoute() = route %+v, deferred %q; want index %d and deferred %q", got, deferred, tc.wantIndex, tc.wantDeferred)
			}
		})
	}
}
