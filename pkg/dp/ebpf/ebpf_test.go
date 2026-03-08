// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ebpf

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/enforce"
)

// TestUpdaterImplementsInterface verifies that Updater satisfies enforce.Updater.
func TestUpdaterImplementsInterface(t *testing.T) {
	var _ enforce.Updater = (*Updater)(nil)
}

// TestNewUpdaterNilProgram ensures fallback behaviour when no eBPF program
// is provided.
func TestNewUpdaterNilProgram(t *testing.T) {
	u := NewUpdater(nil, nil)
	if u.IsEnabled() {
		t.Fatal("expected eBPF to be disabled with nil program")
	}
}

// TestUpdaterFallbackBlockHost verifies that BlockHostTemp delegates to the
// fallback updater when eBPF is not enabled.
func TestUpdaterFallbackBlockHost(t *testing.T) {
	fb := &mockUpdater{}
	u := NewUpdater(nil, fb)

	ip := net.ParseIP("192.168.1.100")
	err := u.BlockHostTemp(context.Background(), ip, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fb.blockHostCalls != 1 {
		t.Fatalf("expected 1 fallback call, got %d", fb.blockHostCalls)
	}
	if !fb.lastIP.Equal(ip) {
		t.Fatalf("expected IP %s, got %s", ip, fb.lastIP)
	}
}

// TestUpdaterFallbackBlockFlow verifies that BlockFlowTemp delegates to the
// fallback updater when eBPF is not enabled.
func TestUpdaterFallbackBlockFlow(t *testing.T) {
	fb := &mockUpdater{}
	u := NewUpdater(nil, fb)

	srcIP := net.ParseIP("10.0.0.1")
	dstIP := net.ParseIP("10.0.0.2")
	err := u.BlockFlowTemp(context.Background(), srcIP, dstIP, "tcp", "443", 60*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fb.blockFlowCalls != 1 {
		t.Fatalf("expected 1 fallback call, got %d", fb.blockFlowCalls)
	}
}

// TestUpdaterNoFallbackReturnsError verifies that operations return an error
// when both eBPF and fallback are unavailable.
func TestUpdaterNoFallbackReturnsError(t *testing.T) {
	u := NewUpdater(nil, nil)

	ip := net.ParseIP("192.168.1.1")
	err := u.BlockHostTemp(context.Background(), ip, 10*time.Second)
	if err == nil {
		t.Fatal("expected error with no eBPF and no fallback")
	}

	err = u.BlockFlowTemp(context.Background(), ip, ip, "tcp", "80", 10*time.Second)
	if err == nil {
		t.Fatal("expected error with no eBPF and no fallback")
	}
}

// TestFlowKeyToBytes verifies binary serialization of FlowKey.
func TestFlowKeyToBytes(t *testing.T) {
	fk := FlowKey{
		SrcIP: net.ParseIP("10.0.0.1"),
		DstIP: net.ParseIP("10.0.0.2"),
		Proto: 6,
		DPort: 443,
	}

	bk, err := flowKeyToBytes(fk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bk.Proto != 6 {
		t.Fatalf("expected proto 6, got %d", bk.Proto)
	}
	// SrcAddr should be 10.0.0.1 in network byte order = 0x0a000001
	if bk.SrcAddr != 0x0a000001 {
		t.Fatalf("unexpected SrcAddr: 0x%08x", bk.SrcAddr)
	}
	if bk.DstAddr != 0x0a000002 {
		t.Fatalf("unexpected DstAddr: 0x%08x", bk.DstAddr)
	}
}

// TestFlowKeyToBytesInvalidIP verifies that invalid IPs are rejected.
func TestFlowKeyToBytesInvalidIP(t *testing.T) {
	fk := FlowKey{
		SrcIP: nil,
		DstIP: net.ParseIP("10.0.0.1"),
		Proto: 6,
		DPort: 80,
	}
	_, err := flowKeyToBytes(fk)
	if err == nil {
		t.Fatal("expected error for nil SrcIP")
	}
}

// TestProtoFromString verifies protocol string conversion.
func TestProtoFromString(t *testing.T) {
	tests := []struct {
		input string
		want  uint8
		err   bool
	}{
		{"tcp", 6, false},
		{"udp", 17, false},
		{"icmp", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		got, err := ProtoFromString(tt.input)
		if (err != nil) != tt.err {
			t.Errorf("ProtoFromString(%q) error = %v, wantErr %v", tt.input, err, tt.err)
			continue
		}
		if got != tt.want {
			t.Errorf("ProtoFromString(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

// TestProgramStubNonLinux verifies the stub Program behavior.
// On Linux this exercises the real Program (without kernel access),
// on other platforms it exercises the stub.
func TestProgramStubNonLinux(t *testing.T) {
	p := NewProgram()
	defer p.Close()

	// On non-Linux: Load should return errNotSupported.
	// On Linux without privileges: Load should return an ebpf error.
	// Both cases are acceptable — we just verify no panic.
	_ = p.Load()
}

// TestSwap16 verifies byte swap.
func TestSwap16(t *testing.T) {
	if swap16(0x0050) != 0x5000 {
		t.Fatalf("swap16(0x0050) = 0x%04x, want 0x5000", swap16(0x0050))
	}
	if swap16(0x01BB) != 0xBB01 {
		t.Fatalf("swap16(0x01BB) = 0x%04x, want 0xBB01", swap16(0x01BB))
	}
}

// mockUpdater records calls for testing fallback delegation.
type mockUpdater struct {
	blockHostCalls int
	blockFlowCalls int
	lastIP         net.IP
}

func (m *mockUpdater) BlockHostTemp(_ context.Context, ip net.IP, _ time.Duration) error {
	m.blockHostCalls++
	m.lastIP = ip
	return nil
}

func (m *mockUpdater) BlockFlowTemp(_ context.Context, _, _ net.IP, _, _ string, _ time.Duration) error {
	m.blockFlowCalls++
	return nil
}
