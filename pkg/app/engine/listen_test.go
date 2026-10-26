// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"net/netip"
	"reflect"
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
		{"split default", false, "", ":8081"},
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
