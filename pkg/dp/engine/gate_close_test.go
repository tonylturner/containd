// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/verdict"
)

// gateCloseUpdater is an updater and revoker whose outcome the test scripts.
type gateCloseUpdater struct {
	err     error
	revoked int
}

func (u *gateCloseUpdater) BlockHostTemp(context.Context, net.IP, time.Duration) error { return u.err }
func (u *gateCloseUpdater) BlockFlowTemp(context.Context, net.IP, net.IP, string, string, time.Duration) error {
	return u.err
}
func (u *gateCloseUpdater) RevokeConnections(context.Context, []conntrack.Entry, string, time.Duration) error {
	u.revoked++
	return u.err
}

// recordingGateCloser records every request it receives.
type recordingGateCloser struct {
	mu   sync.Mutex
	reqs []GateCloseRequest
}

func (c *recordingGateCloser) CloseMatching(req GateCloseRequest) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reqs = append(c.reqs, req)
	return 1
}

func (c *recordingGateCloser) requests() []GateCloseRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]GateCloseRequest(nil), c.reqs...)
}

// installGateCloser installs c for the test and restores the previous
// closer afterwards; the closer is process state.
func installGateCloser(t *testing.T, c GateCloser) {
	t.Helper()
	prev := gateCloser.Load()
	SetGateCloser(c)
	t.Cleanup(func() {
		if prev == nil {
			SetGateCloser(nil)
			return
		}
		gateCloser.Store(prev)
	})
}

func gateCloseEngine(t *testing.T, up *gateCloseUpdater) *Engine {
	t.Helper()
	e, err := New(Config{Enforce: EnforceConfig{Enabled: true, TableName: "containd", Updater: up}})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestRevokeConnectionsClosesGatedLegs(t *testing.T) {
	closer := &recordingGateCloser{}
	installGateCloser(t, closer)
	up := &gateCloseUpdater{}
	e := gateCloseEngine(t, up)
	entries := []conntrack.Entry{
		{Proto: "tcp", Src: "10.0.0.5", Dst: "192.0.2.80", Sport: "40000", Dport: "80"},
		{Proto: "udp", Src: "10.0.0.5", Dst: "192.0.2.53", Sport: "40001", Dport: "53"},
		{Proto: "tcp", Src: "bad", Dst: "192.0.2.80", Sport: "1", Dport: "80"},
	}
	if err := e.RevokeConnections(context.Background(), entries, "connection", time.Minute); err != nil {
		t.Fatal(err)
	}
	want := []GateCloseRequest{{Src: netip.MustParseAddr("10.0.0.5"), Dst: netip.MustParseAddr("192.0.2.80"), SrcPort: 40000, DstPort: 80}}
	if got := closer.requests(); len(got) != 1 || got[0] != want[0] {
		t.Fatalf("connection scope requests %+v, want %+v", got, want)
	}
	if err := e.RevokeConnections(context.Background(), entries[:1], "client-service", time.Minute); err != nil {
		t.Fatal(err)
	}
	want = append(want, GateCloseRequest{Src: want[0].Src, Dst: want[0].Dst, DstPort: 80})
	if got := closer.requests(); len(got) != 2 || got[1] != want[1] {
		t.Fatalf("client-service scope requests %+v, want %+v", got, want)
	}
	// A failed revocation leaves the connections alone: the kernel still
	// carries them, so resetting them would be a block the rules do not hold.
	up.err = errors.New("nft failed")
	if err := e.RevokeConnections(context.Background(), entries[:1], "connection", time.Minute); err == nil {
		t.Fatal("revocation error was hidden")
	}
	if got := closer.requests(); len(got) != 2 {
		t.Fatalf("failed revocation closed connections: %+v", got)
	}
}

func TestRevokeConnectionsWithoutEnforcementNeedsNoCloser(t *testing.T) {
	installGateCloser(t, nil)
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.RevokeConnections(context.Background(), []conntrack.Entry{{Proto: "tcp", Src: "10.0.0.5", Dst: "192.0.2.80", Sport: "1", Dport: "80"}}, "connection", time.Minute); err == nil {
		t.Fatal("revocation without enforcement succeeded")
	}
}

func TestApplyVerdictClosesGatedConnections(t *testing.T) {
	closer := &recordingGateCloser{}
	installGateCloser(t, closer)
	up := &gateCloseUpdater{}
	e := gateCloseEngine(t, up)
	src, dst := net.ParseIP("10.0.0.5"), net.ParseIP("192.0.2.80")
	ctx := context.Background()
	cases := []struct {
		name string
		v    verdict.Verdict
		flow rules.EvalContext
		want *GateCloseRequest
	}{
		{"host block", verdict.Verdict{Action: verdict.BlockHostTemp}, rules.EvalContext{SrcIP: src, DstIP: dst}, &GateCloseRequest{Host: netip.MustParseAddr("10.0.0.5")}},
		{"host block by destination", verdict.Verdict{Action: verdict.BlockHostTemp}, rules.EvalContext{DstIP: dst}, &GateCloseRequest{Host: netip.MustParseAddr("192.0.2.80")}},
		{"tcp flow block", verdict.Verdict{Action: verdict.BlockFlowTemp}, rules.EvalContext{SrcIP: src, DstIP: dst, Proto: "tcp", Port: "80"}, &GateCloseRequest{Src: netip.MustParseAddr("10.0.0.5"), Dst: netip.MustParseAddr("192.0.2.80"), DstPort: 80}},
		{"udp flow block", verdict.Verdict{Action: verdict.BlockFlowTemp}, rules.EvalContext{SrcIP: src, DstIP: dst, Proto: "udp", Port: "53"}, nil},
		{"drop", verdict.Verdict{Action: verdict.DenyDrop}, rules.EvalContext{SrcIP: src, DstIP: dst}, nil},
	}
	for _, tc := range cases {
		before := len(closer.requests())
		if err := e.ApplyVerdict(ctx, tc.v, tc.flow); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got := closer.requests()[before:]
		switch {
		case tc.want == nil && len(got) != 0:
			t.Fatalf("%s: closed %+v, want nothing", tc.name, got)
		case tc.want != nil && (len(got) != 1 || got[0] != *tc.want):
			t.Fatalf("%s: closed %+v, want %+v", tc.name, got, *tc.want)
		}
	}
	up.err = errors.New("nft failed")
	before := len(closer.requests())
	if err := e.ApplyVerdict(ctx, verdict.Verdict{Action: verdict.BlockHostTemp}, rules.EvalContext{SrcIP: src}); err == nil {
		t.Fatal("block error was hidden")
	}
	if got := closer.requests()[before:]; len(got) != 0 {
		t.Fatalf("failed block closed connections: %+v", got)
	}
}

func TestApplyVerdictWithoutUpdaterClosesNothing(t *testing.T) {
	closer := &recordingGateCloser{}
	installGateCloser(t, closer)
	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyVerdict(context.Background(), verdict.Verdict{Action: verdict.BlockHostTemp}, rules.EvalContext{SrcIP: net.ParseIP("10.0.0.5")}); err != nil {
		t.Fatal(err)
	}
	if got := closer.requests(); len(got) != 0 {
		t.Fatalf("closed %+v without enforcement", got)
	}
}
