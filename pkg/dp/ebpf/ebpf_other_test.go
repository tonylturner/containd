// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package ebpf

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProgramStubMethodsNonLinux(t *testing.T) {
	p := NewProgram()

	if err := p.Attach("eth0"); err != errNotSupported {
		t.Fatalf("Attach() error = %v, want %v", err, errNotSupported)
	}
	if err := p.Detach(); err != errNotSupported {
		t.Fatalf("Detach() error = %v, want %v", err, errNotSupported)
	}
	if err := p.SyncBlockHosts([]net.IP{net.ParseIP("192.0.2.10")}); err != errNotSupported {
		t.Fatalf("SyncBlockHosts() error = %v, want %v", err, errNotSupported)
	}
	if err := p.SyncBlockFlows([]FlowKey{{SrcIP: net.ParseIP("192.0.2.10"), DstIP: net.ParseIP("192.0.2.20"), Proto: 6, DPort: 502}}); err != errNotSupported {
		t.Fatalf("SyncBlockFlows() error = %v, want %v", err, errNotSupported)
	}
	if packets, bytes, err := p.ReadStats(); err != errNotSupported || packets != 0 || bytes != 0 {
		t.Fatalf("ReadStats() = (%d, %d, %v), want (0, 0, %v)", packets, bytes, err, errNotSupported)
	}
}

func TestUpdaterStubHelpersNonLinux(t *testing.T) {
	u := &Updater{prog: NewProgram(), enabled: true}

	if isLoaded(u.prog) {
		t.Fatal("isLoaded(non-linux stub) should be false")
	}
	if err := u.putBlockHost(net.ParseIP("192.0.2.10")); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("putBlockHost() error = %v, want unsupported error", err)
	}
	if err := u.putBlockFlow(FlowKey{SrcIP: net.ParseIP("192.0.2.10"), DstIP: net.ParseIP("192.0.2.20"), Proto: 6, DPort: 443}); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("putBlockFlow() error = %v, want unsupported error", err)
	}
}

func TestUpdaterEnabledErrorPathsNonLinux(t *testing.T) {
	u := &Updater{prog: NewProgram(), enabled: true}

	if err := u.BlockHostTemp(context.Background(), net.IPv6loopback, time.Second); err == nil || !strings.Contains(err.Error(), "invalid IPv4") {
		t.Fatalf("BlockHostTemp(invalid IPv4) error = %v, want invalid IPv4", err)
	}

	if err := u.BlockFlowTemp(context.Background(), net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.20"), "icmp", "80", time.Second); err == nil || !strings.Contains(err.Error(), "unsupported protocol") {
		t.Fatalf("BlockFlowTemp(invalid proto) error = %v, want unsupported protocol", err)
	}

	if err := u.BlockFlowTemp(context.Background(), net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.20"), "tcp", "70000", time.Second); err == nil || !strings.Contains(err.Error(), "invalid dport") {
		t.Fatalf("BlockFlowTemp(invalid dport) error = %v, want invalid dport", err)
	}

	if err := u.BlockHostTemp(context.Background(), net.ParseIP("192.0.2.10"), time.Second); err == nil || !strings.Contains(err.Error(), "block host") {
		t.Fatalf("BlockHostTemp(stub failure) error = %v, want block host wrapper", err)
	}

	if err := u.BlockFlowTemp(context.Background(), net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.20"), "tcp", "443", time.Second); err == nil || !strings.Contains(err.Error(), "block flow") {
		t.Fatalf("BlockFlowTemp(stub failure) error = %v, want block flow wrapper", err)
	}
}

func TestNewUpdaterStubProgramDisabledNonLinux(t *testing.T) {
	u := NewUpdater(NewProgram(), nil)
	if u.IsEnabled() {
		t.Fatal("NewUpdater(stub program) should remain disabled on non-linux")
	}
}
