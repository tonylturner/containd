// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/dp/enforce"
)

func TestListenAddr(t *testing.T) {
	for _, tc := range []struct {
		name     string
		combined bool
		env      string
		want     string
	}{
		{"combined default", true, "", "127.0.0.1:8081"},
		{"split has no default", false, "", ""},
		{"combined override", true, ":9091", ":9091"},
		{"split override", false, "127.0.0.1:9091", "127.0.0.1:9091"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CONTAIND_ENGINE_ADDR", tc.env)
			t.Setenv("NGFW_ENGINE_ADDR", "")
			if got := ListenAddr(tc.combined); got != tc.want {
				t.Fatalf("ListenAddr(%v) = %q, want %q", tc.combined, got, tc.want)
			}
		})
	}
}

func TestCombinedDefaultAcceptsReservation(t *testing.T) {
	t.Setenv("CONTAIND_ENGINE_ADDR", "")
	t.Setenv("NGFW_ENGINE_ADDR", "")
	r := &mgmtpath.Reservation{}
	if err := r.ValidateEngineBind(ListenAddr(true)); err != nil {
		t.Fatal(err)
	}
	if err := r.ValidateEngineBind(ListenAddr(false)); err == nil {
		t.Fatal("split wildcard bind accepted for reservation")
	}
}

func TestEngineAPIPath(t *testing.T) {
	nics := map[string][]netip.Addr{
		"lo":   {netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")},
		"eth0": {netip.MustParseAddr("192.0.2.2")},
		"eth1": {netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("2001:db8::2")},
		"dup0": {netip.MustParseAddr("203.0.113.2")},
		"dup1": {netip.MustParseAddr("203.0.113.2")},
	}
	for _, tc := range []struct {
		addr string
		want *enforce.EngineAPIPath
		err  bool
	}{
		{addr: "127.0.0.1:8081"},
		{addr: "[::1]:8081"},
		{addr: "localhost:8081"},
		{addr: ":8081"},
		{addr: "0.0.0.0:8081"},
		{addr: "[::]:8081"},
		{addr: "198.51.100.2:9091", want: &enforce.EngineAPIPath{Device: "eth1", Addr: netip.MustParseAddr("198.51.100.2"), Port: 9091}},
		{addr: "[2001:db8::2]:8081", want: &enforce.EngineAPIPath{Device: "eth1", Addr: netip.MustParseAddr("2001:db8::2"), Port: 8081}},
		{addr: "[::ffff:192.0.2.2]:8081", want: &enforce.EngineAPIPath{Device: "eth0", Addr: netip.MustParseAddr("192.0.2.2"), Port: 8081}},
		{addr: "192.0.2.9:8081", err: true},
		{addr: "203.0.113.2:8081", err: true},
		{addr: "engine.example:8081", err: true},
		{addr: "192.0.2.2:http", err: true},
		{addr: "192.0.2.2:0", err: true},
		{addr: "192.0.2.2", err: true},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			got, err := engineAPIPath(tc.addr, nics)
			if (err != nil) != tc.err {
				t.Fatalf("engineAPIPath(%q) error = %v, want error %v", tc.addr, err, tc.err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("engineAPIPath(%q) = %+v, want %+v", tc.addr, got, tc.want)
			}
		})
	}
}

func TestEngineListener(t *testing.T) {
	nics := map[string][]netip.Addr{
		"lo":   {netip.MustParseAddr("127.0.0.1")},
		"eth1": {netip.MustParseAddr("198.51.100.2")},
	}
	reserved := &mgmtpath.Reservation{Device: "eth9", Local: netip.MustParsePrefix("10.99.99.2/24"), Port: 8080}
	bound := &enforce.EngineAPIPath{Device: "eth1", Addr: netip.MustParseAddr("198.51.100.2"), Port: 8081}
	for _, tc := range []struct {
		name        string
		addr        string
		combined    bool
		reservation *mgmtpath.Reservation
		want        *enforce.EngineAPIPath
		err         string
	}{
		{name: "combined loopback", addr: "127.0.0.1:8081", combined: true},
		{name: "combined wildcard", addr: ":8081", combined: true},
		{name: "combined bound", addr: "198.51.100.2:8081", combined: true, want: bound},
		{name: "split bound", addr: "198.51.100.2:8081", want: bound},
		{name: "split unset", err: "set CONTAIND_ENGINE_ADDR"},
		{name: "split wildcard", addr: ":8081", err: "set CONTAIND_ENGINE_ADDR"},
		{name: "split ipv6 wildcard", addr: "[::]:8081", err: "set CONTAIND_ENGINE_ADDR"},
		{name: "split loopback", addr: "127.0.0.1:8081", err: "set CONTAIND_ENGINE_ADDR"},
		{name: "split localhost", addr: "localhost:8081", err: "set CONTAIND_ENGINE_ADDR"},
		{name: "split address not held", addr: "192.0.2.9:8081", err: "want one interface"},
		{name: "split reserved loopback", addr: "127.0.0.1:8081", reservation: reserved},
		{name: "split reserved bound", addr: "198.51.100.2:8081", reservation: reserved, err: "reserved management path"},
		{name: "combined reserved wildcard", addr: ":8081", combined: true, reservation: reserved, err: "reserved management path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engineListener(tc.addr, tc.combined, tc.reservation, nics)
			if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
				t.Fatalf("engineListener(%q) error = %v, want %q", tc.addr, err, tc.err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("engineListener(%q) = %+v, want %+v", tc.addr, got, tc.want)
			}
		})
	}
}
