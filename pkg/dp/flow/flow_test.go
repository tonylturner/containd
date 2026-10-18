// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package flow

import (
	"net"
	"testing"
	"time"
)

func TestKeyHashDeterministic(t *testing.T) {
	k1 := Key{
		SrcIP:   net.ParseIP("192.0.2.1"),
		DstIP:   net.ParseIP("198.51.100.2"),
		SrcPort: 1234,
		DstPort: 80,
		Proto:   6,
		Dir:     DirForward,
	}
	k2 := k1
	if k1.Hash() != k2.Hash() {
		t.Fatalf("expected same hash")
	}
}

func TestStateExpiration(t *testing.T) {
	now := time.Now()
	st := NewState(Key{}, now)
	st.IdleTimeout = time.Second
	st.Touch(100, now)
	if st.Expired(now) {
		t.Fatalf("should not be expired at creation")
	}
	if !st.Expired(now.Add(2 * time.Second)) {
		t.Fatalf("expected idle expiration")
	}
}

func TestKeyOrientation(t *testing.T) {
	client, server := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
	fwd := Key{SrcIP: client, DstIP: server, SrcPort: 40000, DstPort: 502, Proto: 6, Dir: DirForward}
	rev := fwd.Reversed()
	if !rev.SrcIP.Equal(server) || rev.SrcPort != 502 || !rev.DstIP.Equal(client) || rev.DstPort != 40000 || rev.Dir != DirReverse {
		t.Fatalf("Reversed() = %+v", rev)
	}
	if back := rev.Reversed(); back.Hash() != fwd.Hash() {
		t.Fatalf("double reversal = %+v, want %+v", back, fwd)
	}
	for _, k := range []Key{fwd, rev} {
		if ip := k.OpenerIP(); !ip.Equal(client) {
			t.Fatalf("%+v OpenerIP() = %s", k, ip)
		}
		if ip := k.ServerIP(); !ip.Equal(server) {
			t.Fatalf("%+v ServerIP() = %s", k, ip)
		}
	}
}
